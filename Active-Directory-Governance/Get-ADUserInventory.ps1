<#
.SYNOPSIS
    Exports an inventory of Active Directory user accounts for access reviews.

.DESCRIPTION
    Produces a baseline of user accounts with identity, organisational and security-relevant
    attributes (password age, password-never-expires, last logon). Use it as the source list
    for quarterly access reviews or to reconcile AD against HR records.

    By default only enabled users are included. Use -IncludeDisabled for all users.

    Read-only.

.PARAMETER IncludeDisabled
    Include disabled accounts.

.PARAMETER SearchBase
    Optional distinguished name of an OU to limit the search.

.PARAMETER Server
    Optional domain controller or domain to query.

.PARAMETER OutputDirectory
    Folder for the CSV report. Default: .\Reports

.EXAMPLE
    .\Get-ADUserInventory.ps1 -IncludeDisabled

.NOTES
    Permissions : Read access to user objects.
    Module      : ActiveDirectory (RSAT)
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [switch]$IncludeDisabled,

    [string]$SearchBase,

    [string]$Server,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

$domainParams = @{}
if ($Server) { $domainParams.Server = $Server }
$domainName = (Get-ADDomain @domainParams).DNSRoot

$adParams = @{
    Filter     = if ($IncludeDisabled) { '*' } else { 'Enabled -eq $true' }
    Properties = 'DisplayName', 'Mail', 'Department', 'Title', 'Manager', 'LastLogonDate',
                 'whenCreated', 'PasswordLastSet', 'PasswordNeverExpires', 'Description'
}
if ($SearchBase) { $adParams.SearchBase = $SearchBase }
if ($Server)     { $adParams.Server     = $Server }

$report = Get-ADUser @adParams | ForEach-Object {
    [PSCustomObject]@{
        Domain               = $domainName
        DisplayName          = $_.DisplayName
        SamAccountName       = $_.SamAccountName
        UserPrincipalName    = $_.UserPrincipalName
        Mail                 = $_.Mail
        Department           = $_.Department
        Title                = $_.Title
        Manager              = if ($_.Manager) { ($_.Manager -split ',')[0] -replace '^CN=' } else { $null }
        Enabled              = $_.Enabled
        LastLogonDate        = $_.LastLogonDate
        PasswordLastSet      = $_.PasswordLastSet
        PasswordNeverExpires = $_.PasswordNeverExpires
        WhenCreated          = $_.whenCreated
        Description          = $_.Description
        DistinguishedName    = $_.DistinguishedName
    }
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("AD_UserInventory_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date))
@($report) | Sort-Object DisplayName | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Users exported: {0}. Report: {1}" -f @($report).Count, $csvPath)
$report
