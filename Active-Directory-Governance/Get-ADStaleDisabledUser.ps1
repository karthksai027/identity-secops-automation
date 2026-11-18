<#
.SYNOPSIS
    Reports disabled Active Directory users that have not been modified for a given number of days.

.DESCRIPTION
    Accounts that are disabled but never deprovisioned keep their group memberships,
    licences and mailbox links. They can be re-enabled by mistake or by an attacker with
    delegated rights. This script lists disabled users whose whenChanged attribute is older
    than the threshold, together with their group membership count, to support leaver-process
    clean-up.

    whenChanged is not replicated and updates on any attribute change, so it is a proxy for
    "disabled since". Review before deleting.

    Read-only. The script does not modify any account.

.PARAMETER DaysDisabled
    Minimum days since the account was last changed. Default: 180.

.PARAMETER SearchBase
    Optional distinguished name of an OU to limit the search.

.PARAMETER Server
    Optional domain controller or domain to query.

.PARAMETER OutputDirectory
    Folder for the CSV report. Default: .\Reports

.EXAMPLE
    .\Get-ADStaleDisabledUser.ps1 -DaysDisabled 365

.NOTES
    Permissions : Read access to user objects.
    Module      : ActiveDirectory (RSAT)
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$DaysDisabled = 180,

    [string]$SearchBase,

    [string]$Server,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

$cutoff = (Get-Date).AddDays(-$DaysDisabled)

$adParams = @{
    Filter     = 'Enabled -eq $false'
    Properties = 'whenChanged', 'LastLogonDate', 'Mail', 'Department', 'Title', 'MemberOf', 'Description'
}
if ($SearchBase) { $adParams.SearchBase = $SearchBase }
if ($Server)     { $adParams.Server     = $Server }

# Skip built-in accounts that are disabled by design: Guest (-501), krbtgt (-502), DefaultAccount (-503)
$users = Get-ADUser @adParams | Where-Object {
    $_.whenChanged -lt $cutoff -and "$($_.SID.Value)" -notmatch '-50[123]$'
}

$report = foreach ($u in $users) {
    [PSCustomObject]@{
        Name              = $u.Name
        SamAccountName    = $u.SamAccountName
        UserPrincipalName = $u.UserPrincipalName
        Mail              = $u.Mail
        Department        = $u.Department
        Title             = $u.Title
        LastChanged       = $u.whenChanged
        DaysSinceChange   = [int]((Get-Date) - $u.whenChanged).TotalDays
        LastLogonDate     = $u.LastLogonDate
        GroupCount        = @($u.MemberOf | Where-Object { $_ }).Count
        Description       = $u.Description
        DistinguishedName = $u.DistinguishedName
    }
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("AD_StaleDisabledUsers_{0}d_{1:yyyyMMdd_HHmm}.csv" -f $DaysDisabled, (Get-Date))
@($report) | Sort-Object DaysSinceChange -Descending | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Stale disabled users: {0}. Report: {1}" -f @($report).Count, $csvPath)
$report
