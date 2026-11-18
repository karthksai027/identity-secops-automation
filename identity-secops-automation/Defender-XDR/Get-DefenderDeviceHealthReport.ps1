<#
.SYNOPSIS
    Finds devices that Defender for Endpoint can't properly protect: sensors that stopped reporting, machines discovered but never onboarded, and high-exposure devices.

.DESCRIPTION
    An alert can only fire on a device whose sensor is healthy. This report uses advanced hunting
    (the DeviceInfo table) to take the latest record for every device seen in the last -Days and
    flags:

      - Not onboarded      : found by device discovery but not running Defender for Endpoint
      - Sensor unhealthy   : SensorHealthState is anything other than Active
      - Not seen recently  : no report for -InactiveDays (switched off, broken, or tampered with)
      - High exposure      : Defender Vulnerability Management rates the device High exposure
      - Internet facing    : device is reachable from the internet

    Read-only.

.PARAMETER Days
    How far back to look for devices (maximum 30, the advanced hunting retention). Default: 30.

.PARAMETER InactiveDays
    Devices with no report for this many days are flagged. Default: 7.

.PARAMETER OutputDirectory
    Folder for the CSV report. Default: .\Reports

.EXAMPLE
    .\Get-DefenderDeviceHealthReport.ps1 | Where-Object Findings | Format-Table DeviceName, OSPlatform, SensorHealthState, LastSeen, Findings

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : Microsoft.Graph.Authentication
    Scopes      : ThreatHunting.Read.All
    Role        : Security Reader
    Licence     : Microsoft Defender for Endpoint P2 / Defender for Business (exposure data needs Defender Vulnerability Management)

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [ValidateRange(1, 30)]
    [int]$Days = 30,

    [ValidateRange(1, 30)]
    [int]$InactiveDays = 7,

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

Connect-GraphIfNeeded -Scopes 'ThreatHunting.Read.All' | Out-Null

$kql = @"
DeviceInfo
| where Timestamp > ago($($Days)d)
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceId, DeviceName, LastSeen = Timestamp, OSPlatform, OSVersion, DeviceType, OnboardingStatus,
          SensorHealthState, ExposureLevel, IsInternetFacing, MachineGroup, PublicIP, JoinType
"@

Write-Verbose 'Running DeviceInfo hunting query...'
$resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
    -Body (@{ Query = $kql } | ConvertTo-Json) -ContentType 'application/json' -OutputType PSObject

$now = (Get-Date).ToUniversalTime()

$report = foreach ($d in @($resp.results)) {
    $lastSeen = if ($d.LastSeen) { ([datetime]$d.LastSeen).ToUniversalTime() } else { $null }
    $findings = New-Object System.Collections.Generic.List[string]

    if ($d.OnboardingStatus -and $d.OnboardingStatus -ne 'Onboarded') { $findings.Add("Not onboarded ($($d.OnboardingStatus))") }
    elseif ($d.SensorHealthState -and $d.SensorHealthState -ne 'Active') { $findings.Add("Sensor $($d.SensorHealthState)") }
    if ($lastSeen -and ($now - $lastSeen).TotalDays -gt $InactiveDays) { $findings.Add("Not seen for $InactiveDays+ days") }
    if ($d.ExposureLevel -eq 'High') { $findings.Add('High exposure') }
    if ("$($d.IsInternetFacing)" -eq 'True') { $findings.Add('Internet facing') }

    [PSCustomObject]@{
        DeviceName        = $d.DeviceName
        OSPlatform        = $d.OSPlatform
        OSVersion         = $d.OSVersion
        DeviceType        = $d.DeviceType
        OnboardingStatus  = $d.OnboardingStatus
        SensorHealthState = $d.SensorHealthState
        ExposureLevel     = $d.ExposureLevel
        InternetFacing    = $d.IsInternetFacing
        DeviceGroup       = $d.MachineGroup
        JoinType          = $d.JoinType
        LastSeen          = $lastSeen
        DaysSinceSeen     = if ($lastSeen) { [int]($now - $lastSeen).TotalDays } else { $null }
        Findings          = $findings -join '; '
        DeviceId          = $d.DeviceId
    }
}
$report = @($report | Sort-Object @{ e = { [bool]$_.Findings }; Descending = $true }, DeviceName)

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("Defender_DeviceHealth_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date))
$report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Devices: {0}. Not onboarded: {1}. Unhealthy sensor: {2}. Not seen {3}+ days: {4}. High exposure: {5}. Report: {6}" -f
    $report.Count,
    @($report | Where-Object { $_.Findings -match 'Not onboarded' }).Count,
    @($report | Where-Object { $_.Findings -match '^Sensor|; Sensor' }).Count,
    $InactiveDays,
    @($report | Where-Object { $_.Findings -match 'Not seen' }).Count,
    @($report | Where-Object { $_.Findings -match 'High exposure' }).Count,
    $csvPath)

$report
