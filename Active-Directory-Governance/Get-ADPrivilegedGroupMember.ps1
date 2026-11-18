<#
.SYNOPSIS
    Lists every effective member of the privileged (Tier 0) Active Directory groups.

.DESCRIPTION
    Privileged group sprawl is one of the most common findings in AD security assessments.
    This script resolves recursive (nested) membership of the built-in privileged groups,
    looked up by well-known SID so it works in any language, and flags risky conditions on
    each member account:

      - Disabled or inactive (no logon in -InactiveDays) but still privileged
      - Password older than -PasswordAgeDays
      - Password never expires
      - Has a Service Principal Name (Kerberoastable privileged account)
      - Not marked "Account is sensitive and cannot be delegated"

    Groups checked: Domain Admins, Enterprise Admins, Schema Admins, Administrators,
    Account Operators, Server Operators, Print Operators, Backup Operators,
    Group Policy Creator Owners, Key Admins, Enterprise Key Admins, DnsAdmins.

    Read-only.

.PARAMETER InactiveDays
    Days without logon before a privileged member is flagged as inactive. Default: 90.

.PARAMETER PasswordAgeDays
    Password age in days before a privileged member is flagged. Default: 365.

.PARAMETER Server
    Optional domain controller or domain to query.

.PARAMETER OutputDirectory
    Folder for the CSV report. Default: .\Reports

.EXAMPLE
    .\Get-ADPrivilegedGroupMember.ps1 | Where-Object Findings | Format-Table Group, SamAccountName, Findings

.NOTES
    Permissions : Read access to groups and users. Enterprise/Schema Admins are read from the
                  forest root domain, so the account needs read access there too.
    Module      : ActiveDirectory (RSAT)
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 90,

    [ValidateRange(1, 3650)]
    [int]$PasswordAgeDays = 365,

    [string]$Server,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

$srv = @{}
if ($Server) { $srv.Server = $Server }

$domain     = Get-ADDomain @srv
$forest     = Get-ADForest @srv
$rootDomain = Get-ADDomain -Identity $forest.RootDomain -Server $forest.RootDomain
$domainSid  = $domain.DomainSID.Value
$rootSid    = $rootDomain.DomainSID.Value

# Group identity (SID or name) and the server to resolve it against
$groupTargets = @(
    @{ Id = "$domainSid-512"; Server = $domain.DNSRoot }      # Domain Admins
    @{ Id = "$rootSid-519";   Server = $rootDomain.DNSRoot }  # Enterprise Admins
    @{ Id = "$rootSid-518";   Server = $rootDomain.DNSRoot }  # Schema Admins
    @{ Id = 'S-1-5-32-544';   Server = $domain.DNSRoot }      # Administrators
    @{ Id = 'S-1-5-32-548';   Server = $domain.DNSRoot }      # Account Operators
    @{ Id = 'S-1-5-32-549';   Server = $domain.DNSRoot }      # Server Operators
    @{ Id = 'S-1-5-32-550';   Server = $domain.DNSRoot }      # Print Operators
    @{ Id = 'S-1-5-32-551';   Server = $domain.DNSRoot }      # Backup Operators
    @{ Id = "$domainSid-520"; Server = $domain.DNSRoot }      # Group Policy Creator Owners
    @{ Id = "$domainSid-526"; Server = $domain.DNSRoot }      # Key Admins
    @{ Id = "$rootSid-527";   Server = $rootDomain.DNSRoot }  # Enterprise Key Admins
    @{ Id = 'DnsAdmins';      Server = $domain.DNSRoot }      # No well-known RID
)

$now           = Get-Date
$inactiveDate  = $now.AddDays(-$InactiveDays)
$pwdAgeDate    = $now.AddDays(-$PasswordAgeDays)
$userProps     = 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires',
                 'ServicePrincipalName', 'AccountNotDelegated', 'UserPrincipalName', 'Description'

$report = foreach ($target in $groupTargets) {
    try {
        $group = Get-ADGroup -Identity $target.Id -Server $target.Server
    }
    catch {
        Write-Verbose "Group $($target.Id) not found on $($target.Server). Skipping."
        continue
    }

    try {
        $members = Get-ADGroupMember -Identity $group -Server $target.Server -Recursive
    }
    catch {
        Write-Warning "Could not expand $($group.Name): $($_.Exception.Message)"
        continue
    }

    foreach ($m in $members) {
        $findings = New-Object System.Collections.Generic.List[string]
        $detail   = $null

        if ($m.objectClass -eq 'user') {
            # Resolve against the member's own domain (members can come from child domains)
            $memberDomain = ($m.distinguishedName -split ',' | Where-Object { $_ -like 'DC=*' }) -replace '^DC=' -join '.'
            try {
                $detail = Get-ADUser -Identity $m.SID -Server $memberDomain -Properties $userProps
            }
            catch {
                Write-Verbose "Could not read user $($m.SamAccountName): $($_.Exception.Message)"
            }

            if ($detail) {
                if (-not $detail.Enabled) { $findings.Add('Disabled but still privileged') }
                if ($detail.Enabled -and (-not $detail.LastLogonDate -or $detail.LastLogonDate -lt $inactiveDate)) {
                    $findings.Add("No logon in $InactiveDays days")
                }
                if ($detail.PasswordLastSet -and $detail.PasswordLastSet -lt $pwdAgeDate) {
                    $findings.Add("Password older than $PasswordAgeDays days")
                }
                if ($detail.PasswordNeverExpires) { $findings.Add('Password never expires') }
                if (@($detail.ServicePrincipalName | Where-Object { $_ }).Count -gt 0) { $findings.Add('Has SPN (Kerberoastable)') }
                if (-not $detail.AccountNotDelegated) { $findings.Add('Not marked sensitive (delegable)') }
            }
        }
        elseif ($m.objectClass -eq 'computer') {
            $findings.Add('Computer account in privileged group')
        }

        [PSCustomObject]@{
            Group                = $group.Name
            MemberName           = $m.Name
            SamAccountName       = $m.SamAccountName
            ObjectClass          = $m.objectClass
            UserPrincipalName    = if ($detail) { $detail.UserPrincipalName } else { $null }
            Enabled              = if ($detail) { $detail.Enabled } else { $null }
            LastLogonDate        = if ($detail) { $detail.LastLogonDate } else { $null }
            PasswordLastSet      = if ($detail) { $detail.PasswordLastSet } else { $null }
            PasswordNeverExpires = if ($detail) { $detail.PasswordNeverExpires } else { $null }
            Findings             = $findings -join '; '
            DistinguishedName    = $m.distinguishedName
        }
    }
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("AD_PrivilegedGroupMembers_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date))
@($report) | Sort-Object Group, MemberName | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$unique = @($report | Where-Object ObjectClass -eq 'user' | Select-Object -ExpandProperty SamAccountName -Unique).Count
Write-Verbose ("Privileged memberships: {0}. Unique privileged users: {1}. Report: {2}" -f @($report).Count, $unique, $csvPath)
$report
