<#
.SYNOPSIS
    Intune device health in one report: non-compliant devices, devices that stopped checking in, unencrypted or jailbroken devices, and Autopilot devices that were never enrolled.

.DESCRIPTION
    Conditional Access that requires a compliant device is only as good as the compliance data
    behind it. This report reads every Intune managed device and flags:

      - Non-compliant, in grace period, or compliance unknown / error
      - No check-in for -StaleDays (lost, wiped, or user gave up on it)
      - Not encrypted (Windows and macOS)
      - Jailbroken or rooted
      - Personal device with corporate access

    With -IncludeAutopilot it also lists Windows Autopilot registered devices that have never
    enrolled into Intune (purchased and registered, but sitting in a cupboard or failing setup).

    Read-only.

.PARAMETER StaleDays
    Devices that haven't synced in this many days are flagged. Default: 30.

.PARAMETER IncludeAutopilot
    Also report Autopilot devices with no matching Intune enrolment.

.PARAMETER OutputDirectory
    Folder for the CSV reports. Default: .\Reports

.EXAMPLE
    .\Get-IntuneDeviceComplianceReport.ps1 -Verbose | Where-Object Findings | Format-Table DeviceName, User, OS, Compliance, LastSync, Findings

.EXAMPLE
    .\Get-IntuneDeviceComplianceReport.ps1 -IncludeAutopilot

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : Microsoft.Graph.Authentication
    Scopes      : DeviceManagementManagedDevices.Read.All (+ DeviceManagementServiceConfig.Read.All for -IncludeAutopilot)
    Role        : Intune Administrator (read), Global Reader, or an Intune RBAC read-only role
    Licence     : Microsoft Intune

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$StaleDays = 30,

    [switch]$IncludeAutopilot,

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
    , $items.ToArray()
}
#endregion

$scopes = @('DeviceManagementManagedDevices.Read.All')
if ($IncludeAutopilot) { $scopes += 'DeviceManagementServiceConfig.Read.All' }
Connect-GraphIfNeeded -Scopes $scopes | Out-Null

$base = 'https://graph.microsoft.com/v1.0/deviceManagement'
$now  = Get-Date

$select = 'id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,lastSyncDateTime,enrolledDateTime,' +
          'isEncrypted,jailBroken,managedDeviceOwnerType,model,manufacturer,serialNumber,azureADDeviceId,deviceEnrollmentType'

Write-Verbose 'Reading Intune managed devices...'
$devices = Invoke-GraphPaged -Uri "$base/managedDevices?`$select=$select"

$report = foreach ($d in $devices) {
    $lastSync = if ($d.lastSyncDateTime) { [datetime]$d.lastSyncDateTime } else { $null }
    $daysSinceSync = if ($lastSync) { [int]($now - $lastSync).TotalDays } else { $null }

    $findings = New-Object System.Collections.Generic.List[string]
    switch ($d.complianceState) {
        'noncompliant' { $findings.Add('Non-compliant') }
        'inGracePeriod' { $findings.Add('In grace period') }
        'error'        { $findings.Add('Compliance error') }
        'conflict'     { $findings.Add('Compliance policy conflict') }
        'unknown'      { $findings.Add('Compliance unknown') }
    }
    if ($null -ne $daysSinceSync -and $daysSinceSync -gt $StaleDays) { $findings.Add("No check-in for $StaleDays+ days") }
    if ($d.operatingSystem -in 'Windows', 'macOS' -and $d.isEncrypted -eq $false) { $findings.Add('Not encrypted') }
    if ($d.jailBroken -eq 'True') { $findings.Add('Jailbroken / rooted') }
    if ($d.managedDeviceOwnerType -eq 'personal') { $findings.Add('Personal device') }

    [PSCustomObject]@{
        DeviceName     = $d.deviceName
        User           = $d.userPrincipalName
        OS             = $d.operatingSystem
        OSVersion      = $d.osVersion
        Compliance     = $d.complianceState
        Ownership      = $d.managedDeviceOwnerType
        Encrypted      = $d.isEncrypted
        LastSync       = $lastSync
        DaysSinceSync  = $daysSinceSync
        Enrolled       = $d.enrolledDateTime
        EnrollmentType = $d.deviceEnrollmentType
        Model          = ("{0} {1}" -f $d.manufacturer, $d.model).Trim()
        SerialNumber   = $d.serialNumber
        Findings       = $findings -join '; '
        EntraDeviceId  = $d.azureADDeviceId
    }
}
$report = @($report | Sort-Object @{ e = { [bool]$_.Findings }; Descending = $true }, DeviceName)

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$stamp = '{0:yyyyMMdd_HHmm}' -f $now
$report | Export-Csv -Path (Join-Path $OutputDirectory "Intune_DeviceCompliance_$stamp.csv") -NoTypeInformation -Encoding UTF8

if ($IncludeAutopilot) {
    Write-Verbose 'Reading Windows Autopilot devices...'
    $enrolledSerials = @{}
    foreach ($d in $devices) { if ($d.serialNumber) { $enrolledSerials["$($d.serialNumber)".ToUpperInvariant()] = $true } }

    $autopilot = Invoke-GraphPaged -Uri "$base/windowsAutopilotDeviceIdentities"
    $notEnrolled = foreach ($ap in $autopilot) {
        $serial = "$($ap.serialNumber)".ToUpperInvariant()
        $hasDevice = ($ap.managedDeviceId -and $ap.managedDeviceId -ne '00000000-0000-0000-0000-000000000000') -or $enrolledSerials.ContainsKey($serial)
        if (-not $hasDevice) {
            [PSCustomObject]@{
                SerialNumber    = $ap.serialNumber
                Model           = ("{0} {1}" -f $ap.manufacturer, $ap.model).Trim()
                GroupTag        = $ap.groupTag
                EnrollmentState = $ap.enrollmentState
                LastContacted   = $ap.lastContactedDateTime
                AssignedUser    = $ap.userPrincipalName
            }
        }
    }
    $notEnrolled = @($notEnrolled)
    $notEnrolled | Export-Csv -Path (Join-Path $OutputDirectory "Intune_AutopilotNotEnrolled_$stamp.csv") -NoTypeInformation -Encoding UTF8
    $autopilotCount = @($autopilot).Count
    $notEnrolledCount = $notEnrolled.Count
    Write-Verbose "Autopilot devices: $autopilotCount. Never enrolled: $notEnrolledCount."
}

Write-Verbose ("Devices: {0}. Non-compliant: {1}. Stale ({2}+ days): {3}. Not encrypted: {4}." -f $report.Count,
    @($report | Where-Object Compliance -eq 'noncompliant').Count, $StaleDays,
    @($report | Where-Object { $_.Findings -match 'No check-in' }).Count,
    @($report | Where-Object { $_.Findings -match 'Not encrypted' }).Count)

$report
