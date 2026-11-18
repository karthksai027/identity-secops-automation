<#
.SYNOPSIS
    Reports enabled Active Directory users who have not signed in for a given number of days.

.DESCRIPTION
    Dormant but enabled accounts are a common foothold for password spraying, credential
    stuffing and insider misuse. This script finds enabled users whose replicated
    lastLogonTimestamp is older than the threshold, plus enabled users who have never
    signed in and were created before the threshold.

    lastLogonTimestamp replicates between domain controllers but can lag by up to 14 days
    (ms-DS-Logon-Time-Sync-Interval). Treat results as candidates for review, not as an
    automatic disable list.

    Read-only. The script does not modify any account.

.PARAMETER DaysInactive
    Inactivity threshold in days. Default: 90.

.PARAMETER SearchBase
    Optional distinguished name of an OU to limit the search. Default: whole domain.

.PARAMETER Server
    Optional domain controller or domain to query.

.PARAMETER OutputDirectory
    Folder for the CSV report. Created if it does not exist. Default: .\Reports

.EXAMPLE
    .\Get-ADInactiveUser.ps1

.EXAMPLE
    .\Get-ADInactiveUser.ps1 -DaysInactive 60 -SearchBase "OU=Staff,DC=contoso,DC=com" -Verbose

.OUTPUTS
    PSCustomObject per inactive user, and a timestamped CSV in OutputDirectory.

.NOTES
    Permissions : Read access to user objects (Domain Users is sufficient).
    Module      : ActiveDirectory (RSAT)
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [string]$SearchBase,

    [string]$Server,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

$cutoff = (Get-Date).AddDays(-$DaysInactive)

$adParams = @{
    Filter     = 'Enabled -eq $true'
    Properties = 'LastLogonDate', 'whenCreated', 'Mail', 'Department', 'Title', 'PasswordLastSet', 'Description'
}
if ($SearchBase) { $adParams.SearchBase = $SearchBase }
if ($Server)     { $adParams.Server     = $Server }

Write-Verbose "Querying enabled users (cutoff: $($cutoff.ToString('yyyy-MM-dd')))"
$users = Get-ADUser @adParams

$report = foreach ($u in $users) {
    $neverLoggedOn = -not $u.LastLogonDate
    $isInactive = ($u.LastLogonDate -and $u.LastLogonDate -lt $cutoff) -or
                  ($neverLoggedOn -and $u.whenCreated -lt $cutoff)

    if ($isInactive) {
        [PSCustomObject]@{
            Name              = $u.Name
            SamAccountName    = $u.SamAccountName
            UserPrincipalName = $u.UserPrincipalName
            Mail              = $u.Mail
            Department        = $u.Department
            Title             = $u.Title
            LastLogonDate     = $u.LastLogonDate
            DaysSinceLogon    = if ($u.LastLogonDate) { [int]((Get-Date) - $u.LastLogonDate).TotalDays } else { $null }
            NeverLoggedOn     = $neverLoggedOn
            PasswordLastSet   = $u.PasswordLastSet
            WhenCreated       = $u.whenCreated
            Description       = $u.Description
            DistinguishedName = $u.DistinguishedName
        }
    }
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("AD_InactiveUsers_{0}d_{1:yyyyMMdd_HHmm}.csv" -f $DaysInactive, (Get-Date))
@($report) | Sort-Object DaysSinceLogon -Descending | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Enabled users scanned: {0}. Inactive: {1}. Report: {2}" -f @($users).Count, @($report).Count, $csvPath)
$report
