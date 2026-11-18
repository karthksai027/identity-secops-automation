<#
.SYNOPSIS
    Finds inactive Entra ID members and guests using sign-in activity, including guests who never accepted their invitation.

.DESCRIPTION
    Supports the SC-300 identity governance objectives (access reviews, guest lifecycle).
    For each user the script takes the most recent of the interactive, non-interactive and
    last successful sign-in timestamps and flags:

      - Inactive          : no sign-in for -DaysInactive
      - Never signed in   : no sign-in recorded and created more than -DaysInactive ago
      - Pending invite    : guest whose invitation is still PendingAcceptance after -DaysInactive
      - Licensed          : inactive accounts that still consume licences (cost reclamation)

    Output feeds an access review, a guest clean-up, or a lifecycle workflow.
    Sign-in data in Entra ID is kept from April 2020 onwards; older activity shows as empty.

    Read-only.

.PARAMETER DaysInactive
    Inactivity threshold in days. Default: 90.

.PARAMETER UserType
    All (default), Member or Guest.

.PARAMETER IncludeDisabled
    Include accounts that are already disabled.

.PARAMETER OutputDirectory
    Folder for the CSV report. Default: .\Reports

.EXAMPLE
    .\Get-EntraStaleAccount.ps1 -UserType Guest -DaysInactive 60

.NOTES
    Module      : Microsoft.Graph.Authentication
    Scopes      : User.Read.All, AuditLog.Read.All
    Entra role  : Global Reader, Reports Reader or Security Reader
    Licence     : signInActivity requires Microsoft Entra ID P1 or P2.
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [ValidateSet('All', 'Member', 'Guest')]
    [string]$UserType = 'All',

    [switch]$IncludeDisabled,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-GraphIfNeeded {
    param([Parameter(Mandatory)][string[]]$Scopes)
    $ctx = Get-MgContext
    if (-not $ctx) {
        Connect-MgGraph -Scopes $Scopes -NoWelcome
        $ctx = Get-MgContext
    }
    if ($ctx.AuthType -eq 'Delegated') {
        $missing = $Scopes | Where-Object { $_ -notin $ctx.Scopes }
        if ($missing) { Write-Warning "Graph session is missing scopes: $($missing -join ', '). Reconnect with Connect-MgGraph -Scopes $($Scopes -join ',')" }
    }
    $ctx
}

function Invoke-GraphPaged {
    param([Parameter(Mandatory)][string]$Uri)
    $items = New-Object System.Collections.Generic.List[object]
    while ($Uri) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        if ($resp.PSObject.Properties.Name -contains 'value') { foreach ($v in $resp.value) { $items.Add($v) } }
        else { $items.Add($resp) }
        $Uri = $resp.'@odata.nextLink'
    }
    , $items
}
#endregion

Connect-GraphIfNeeded -Scopes 'User.Read.All', 'AuditLog.Read.All' | Out-Null

$select = 'id,displayName,userPrincipalName,mail,userType,accountEnabled,createdDateTime,externalUserState,' +
          'externalUserStateChangeDateTime,onPremisesSyncEnabled,assignedLicenses,signInActivity'
$uri = "https://graph.microsoft.com/v1.0/users?`$select=$select"
if ($UserType -ne 'All') { $uri += "&`$filter=userType eq '$UserType'" }

Write-Verbose 'Reading users with sign-in activity...'
$users = Invoke-GraphPaged -Uri $uri

$now    = Get-Date
$cutoff = $now.AddDays(-$DaysInactive)

$report = foreach ($u in $users) {
    if (-not $IncludeDisabled -and -not $u.accountEnabled) { continue }

    $last = $null
    if ($u.signInActivity) {
        $dates = @(
            $u.signInActivity.lastSignInDateTime
            $u.signInActivity.lastNonInteractiveSignInDateTime
            $u.signInActivity.lastSuccessfulSignInDateTime
        ) | Where-Object { $_ } | ForEach-Object { [datetime]$_ }
        if ($dates) { $last = ($dates | Measure-Object -Maximum).Maximum }
    }
    $created = if ($u.createdDateTime) { [datetime]$u.createdDateTime } else { $null }

    $findings = New-Object System.Collections.Generic.List[string]
    if ($u.userType -eq 'Guest' -and $u.externalUserState -eq 'PendingAcceptance' -and $created -and $created -lt $cutoff) {
        $findings.Add("Invitation pending for $DaysInactive+ days")
    }
    if ($last -and $last -lt $cutoff) { $findings.Add("No sign-in for $DaysInactive+ days") }
    elseif (-not $last -and $created -and $created -lt $cutoff) { $findings.Add('Never signed in') }

    if ($findings.Count -eq 0) { continue }

    $licensed = @($u.assignedLicenses).Count -gt 0
    if ($licensed) { $findings.Add('Still licensed') }

    [PSCustomObject]@{
        DisplayName        = $u.displayName
        UserPrincipalName  = $u.userPrincipalName
        Mail               = $u.mail
        UserType           = $u.userType
        AccountEnabled     = $u.accountEnabled
        OnPremisesSynced   = [bool]$u.onPremisesSyncEnabled
        CreatedDateTime    = $created
        LastSignIn         = $last
        DaysSinceSignIn    = if ($last) { [int]($now - $last).TotalDays } else { $null }
        GuestInviteState   = $u.externalUserState
        LicenseCount       = @($u.assignedLicenses).Count
        Findings           = $findings -join '; '
        Id                 = $u.id
    }
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("Entra_StaleAccounts_{0}_{1}d_{2:yyyyMMdd_HHmm}.csv" -f $UserType, $DaysInactive, $now)
@($report) | Sort-Object UserType, DaysSinceSignIn -Descending | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Users scanned: {0}. Stale: {1} (members {2}, guests {3}, licensed {4}). Report: {5}" -f $users.Count,
    @($report).Count, @($report | Where-Object UserType -eq 'Member').Count, @($report | Where-Object UserType -eq 'Guest').Count,
    @($report | Where-Object LicenseCount -gt 0).Count, $csvPath)
$report
