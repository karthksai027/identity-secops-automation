<#
.SYNOPSIS
    Exports all Active Directory computer objects with OS, activity and lifecycle flags.

.DESCRIPTION
    Builds a computer inventory straight from AD (no network connection to endpoints needed)
    and flags:

      - Stale    : enabled but no logon in -StaleDays (orphaned machine credentials)
      - Legacy OS: Windows 7/8/8.1, Windows Server 2003-2012 R2 (out of support, no patches)
      - Role     : Domain Controller, Server or Workstation

    Combines and replaces the earlier single-purpose computer export scripts.

    Read-only.

.PARAMETER StaleDays
    Days without logon before an enabled computer is flagged as stale. Default: 60.

.PARAMETER SearchBase
    Optional distinguished name of an OU to limit the search.

.PARAMETER Server
    Optional domain controller or domain to query.

.PARAMETER OutputDirectory
    Folder for the CSV report. Default: .\Reports

.EXAMPLE
    .\Get-ADComputerInventory.ps1 | Where-Object { $_.IsStale -or $_.IsLegacyOS }

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Permissions : Read access to computer objects.
    Module      : ActiveDirectory (RSAT)

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 60,

    [string]$SearchBase,

    [string]$Server,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

$cutoff = (Get-Date).AddDays(-$StaleDays)
$legacyPattern = 'Windows (XP|Vista|7|8)\b|Windows 8\.1|Server 2003|Server 2008|Server 2012'

$adParams = @{
    Filter     = '*'
    Properties = 'DNSHostName', 'OperatingSystem', 'OperatingSystemVersion', 'LastLogonDate',
                 'whenCreated', 'PrimaryGroupID', 'Description', 'IPv4Address'
}
if ($SearchBase) { $adParams.SearchBase = $SearchBase }
if ($Server)     { $adParams.Server     = $Server }

$report = Get-ADComputer @adParams | ForEach-Object {
    $os = "$($_.OperatingSystem)"
    $role = switch ($_.PrimaryGroupID) {
        516     { 'Domain Controller' }
        521     { 'Domain Controller (RODC)' }
        default { if ($os -match 'Server') { 'Server' } else { 'Workstation' } }
    }
    $domainPart = if ($_.DNSHostName -and $_.DNSHostName.Contains('.')) {
        $_.DNSHostName.Substring($_.DNSHostName.IndexOf('.') + 1)
    } else { $null }

    [PSCustomObject]@{
        Name                   = $_.Name
        DNSHostName            = $_.DNSHostName
        Domain                 = $domainPart
        Role                   = $role
        OperatingSystem        = $_.OperatingSystem
        OperatingSystemVersion = $_.OperatingSystemVersion
        IPv4Address            = $_.IPv4Address
        Enabled                = $_.Enabled
        LastLogonDate          = $_.LastLogonDate
        WhenCreated            = $_.whenCreated
        IsStale                = [bool]($_.Enabled -and (-not $_.LastLogonDate -or $_.LastLogonDate -lt $cutoff))
        IsLegacyOS             = [bool]($_.OperatingSystem -match $legacyPattern)
        Description            = $_.Description
        DistinguishedName      = $_.DistinguishedName
    }
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("AD_ComputerInventory_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date))
@($report) | Sort-Object Role, Name | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Computers: {0}. Stale: {1}. Legacy OS: {2}. Report: {3}" -f @($report).Count,
    @($report | Where-Object IsStale).Count, @($report | Where-Object IsLegacyOS).Count, $csvPath)
$report
