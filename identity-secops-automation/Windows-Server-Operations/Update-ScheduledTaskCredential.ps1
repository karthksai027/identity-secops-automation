<#
.SYNOPSIS
    Updates the run-as account of scheduled tasks after a service account password change, or moves them to a gMSA.

.DESCRIPTION
    Scheduled tasks that run as a named account store that account's password. When the
    password is rotated the task silently fails with "logon failure". This script:

      - Password mode : prompts for the credential securely (Get-Credential) and re-registers
                        it on every matching task. No password is ever written in the script.
      - gMSA mode     : switches the tasks to a group Managed Service Account, after which
                        Windows rotates the password automatically and no stored secret remains.

    Supports -WhatIf and -Confirm. Can target a remote server with -ComputerName.

.PARAMETER TaskName
    Name of the task(s) to update. Wildcards allowed.

.PARAMETER TaskPath
    Task folder. Default: '\' (root). Use '\MyFolder\' for sub-folders.

.PARAMETER Credential
    Credential for the run-as account (password mode). Prompted if not supplied.

.PARAMETER GmsaAccount
    gMSA in DOMAIN\name$ format (gMSA mode). The host must be allowed to retrieve the
    gMSA password (PrincipalsAllowedToRetrieveManagedPassword) and Install-ADServiceAccount
    should already have been run on it.

.PARAMETER ComputerName
    Optional remote computer. Default: local computer.

.EXAMPLE
    .\Update-ScheduledTaskCredential.ps1 -TaskName 'Daily S3 Upload'
    Prompts for the new password and updates the task.

.EXAMPLE
    .\Update-ScheduledTaskCredential.ps1 -TaskName 'Report*' -GmsaAccount 'CONTOSO\svc-reports$' -WhatIf

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Permissions : Local administrator on the target computer.
    Module      : ScheduledTasks (built in to Windows 8 / Server 2012 and later)

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules ScheduledTasks

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Password')]
param(
    [Parameter(Mandatory)]
    [string]$TaskName,

    [string]$TaskPath = '\',

    [Parameter(ParameterSetName = 'Password')]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(ParameterSetName = 'Gmsa', Mandatory)]
    [ValidatePattern('^[^\\]+\\[^\\]+\$$')]
    [string]$GmsaAccount,

    [string]$ComputerName
)

$ErrorActionPreference = 'Stop'

$cimParams = @{}
$session = $null
if ($ComputerName) {
    $session = New-CimSession -ComputerName $ComputerName
    $cimParams.CimSession = $session
}

try {
    $tasks = @(Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath @cimParams)
    if ($tasks.Count -eq 0) { throw "No scheduled task matched '$TaskName' in '$TaskPath'." }

    if ($PSCmdlet.ParameterSetName -eq 'Password' -and $Credential -eq [System.Management.Automation.PSCredential]::Empty) {
        $Credential = Get-Credential -Message "Run-as account for task(s) '$TaskName'"
    }

    foreach ($task in $tasks) {
        $target = "$($task.TaskPath)$($task.TaskName)"

        if ($PSCmdlet.ParameterSetName -eq 'Gmsa') {
            if ($PSCmdlet.ShouldProcess($target, "Set run-as account to gMSA $GmsaAccount")) {
                $principal = New-ScheduledTaskPrincipal -UserId $GmsaAccount -LogonType Password -RunLevel $task.Principal.RunLevel
                Set-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Principal $principal @cimParams | Out-Null
                [PSCustomObject]@{ Task = $target; RunAs = $GmsaAccount; Mode = 'gMSA'; Result = 'Updated' }
            }
        }
        else {
            if ($PSCmdlet.ShouldProcess($target, "Update stored password for $($Credential.UserName)")) {
                # Set-ScheduledTask only accepts a plain string; it stays in memory for this call only.
                Set-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath `
                    -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password @cimParams | Out-Null
                [PSCustomObject]@{ Task = $target; RunAs = $Credential.UserName; Mode = 'Password'; Result = 'Updated' }
            }
        }
    }
}
finally {
    if ($session) { Remove-CimSession -CimSession $session }
}
