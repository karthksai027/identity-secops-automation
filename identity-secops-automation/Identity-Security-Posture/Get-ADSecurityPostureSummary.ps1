<#
.SYNOPSIS
    Produces an Active Directory security posture scorecard with a status and recommendation per check.

.DESCRIPTION
    Checks the AD attack-surface indicators that attackers and assessment tools (PingCastle,
    Purple Knight, Defender for Identity) look at first:

      Credential attacks   : Kerberoastable users, AS-REP roastable users, password-not-required,
                             reversible encryption, password-never-expires, old passwords
      Privilege            : Domain Admins size, adminCount=1 users, unconstrained delegation
      Hygiene              : inactive / locked / disabled users, stale computers,
                             krbtgt password age, Guest account, default password policy

    Each check returns Status = OK, Review or Risk with a short recommendation.
    Use -ExportDetails to also write a CSV of the affected accounts for each non-OK check.

    Read-only.

.PARAMETER PasswordAgeDays
    Password age threshold for enabled users. Default: 90.

.PARAMETER InactiveDays
    Inactivity threshold for users and computers. Default: 90.

.PARAMETER ExportDetails
    Write one CSV per finding listing the affected accounts.

.PARAMETER Server
    Optional domain controller or domain to query.

.PARAMETER OutputDirectory
    Folder for the reports. Default: .\Reports

.EXAMPLE
    .\Get-ADSecurityPostureSummary.ps1 | Format-Table -AutoSize

.EXAMPLE
    .\Get-ADSecurityPostureSummary.ps1 -ExportDetails -OutputDirectory D:\Audit

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Permissions : Read access to users, computers, groups and the domain object.
    Module      : ActiveDirectory (RSAT)

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'ExportDetails', Justification = 'Used inside Add-Check via script scope')]
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$PasswordAgeDays = 90,

    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 90,

    [switch]$ExportDetails,

    [string]$Server,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

$srv = @{}
if ($Server) { $srv.Server = $Server }

$now        = Get-Date
$stamp      = '{0:yyyyMMdd_HHmm}' -f $now
$domain     = Get-ADDomain @srv
$pwdPolicy  = Get-ADDefaultDomainPasswordPolicy @srv
$pwdCutoff  = $now.AddDays(-$PasswordAgeDays)
$idleCutoff = $now.AddDays(-$InactiveDays)

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

Write-Verbose 'Loading users and computers...'
$userProps = 'Enabled', 'PasswordNeverExpires', 'PasswordLastSet', 'PasswordNotRequired', 'LastLogonDate',
             'LockedOut', 'ServicePrincipalName', 'DoesNotRequirePreAuth', 'AllowReversiblePasswordEncryption',
             'TrustedForDelegation', 'adminCount', 'whenCreated'
$users     = @(Get-ADUser -Filter * -Properties $userProps @srv)
$enabled   = @($users | Where-Object Enabled)
$computers = @(Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, TrustedForDelegation, PrimaryGroupID, OperatingSystem @srv)

$results = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [string]$Category,
        [string]$Check,
        [object[]]$Items,
        [int]$ReviewAt,
        [int]$RiskAt,
        [string]$Recommendation,
        [object]$ValueOverride
    )
    $Items  = @($Items | Where-Object { $null -ne $_ })
    $count  = $Items.Count
    $value  = if ($null -ne $ValueOverride) { $ValueOverride } else { $count }
    $status = if ($count -ge $RiskAt) { 'Risk' } elseif ($count -ge $ReviewAt) { 'Review' } else { 'OK' }

    $results.Add([PSCustomObject]@{
        Category       = $Category
        Check          = $Check
        Value          = $value
        Status         = $status
        Recommendation = if ($status -eq 'OK') { '' } else { $Recommendation }
    })

    if ($ExportDetails -and $count -gt 0 -and $status -ne 'OK') {
        $safeName = ($Check -replace '[^A-Za-z0-9]+', '_').Trim('_')
        $Items | Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, DistinguishedName |
            Export-Csv -Path (Join-Path $OutputDirectory "AD_Posture_${safeName}_$stamp.csv") -NoTypeInformation -Encoding UTF8
    }
}

# ---------------- Credential attack surface ----------------
$kerberoastable = $enabled | Where-Object { @($_.ServicePrincipalName | Where-Object { $_ }).Count -gt 0 -and $_.SamAccountName -ne 'krbtgt' }
Add-Check 'Credential attacks' 'Kerberoastable user accounts (SPN set)' $kerberoastable 1 5 `
    'Move services to gMSA, or enforce 25+ character passwords and AES-only encryption on these accounts.'

$asrep = $enabled | Where-Object DoesNotRequirePreAuth
Add-Check 'Credential attacks' 'AS-REP roastable users (pre-auth disabled)' $asrep 1 1 `
    'Re-enable Kerberos pre-authentication unless a documented legacy dependency exists.'

$pwdNotRequired = $enabled | Where-Object PasswordNotRequired
Add-Check 'Credential attacks' 'Password not required (PASSWD_NOTREQD)' $pwdNotRequired 1 1 `
    'Clear the flag: Set-ADUser <user> -PasswordNotRequired $false, then set a strong password.'

$reversible = $enabled | Where-Object AllowReversiblePasswordEncryption
Add-Check 'Credential attacks' 'Reversible password encryption enabled' $reversible 1 1 `
    'Disable reversible encryption and reset the affected passwords.'

$neverExpires = $enabled | Where-Object PasswordNeverExpires
Add-Check 'Credential attacks' 'Password never expires (enabled users)' $neverExpires 1 10 `
    'Limit to documented service accounts; prefer gMSA. Human accounts should follow the password or passwordless policy.'

$oldPwd = $enabled | Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt $pwdCutoff }
Add-Check 'Credential attacks' "Password older than $PasswordAgeDays days" $oldPwd 1 25 `
    'Review against password policy; prioritise privileged and service accounts.'

# ---------------- Privilege ----------------
$daGroup   = Get-ADGroup -Identity "$($domain.DomainSID.Value)-512" @srv
$daMembers = @(Get-ADGroupMember -Identity $daGroup -Recursive @srv)
Add-Check 'Privilege' 'Domain Admins (effective members)' $daMembers 5 10 `
    'Keep Domain Admins minimal (break-glass plus named admin accounts). Use delegation and tiering for daily tasks.'

$adminCount = $users | Where-Object { $_.adminCount -eq 1 }
Add-Check 'Privilege' 'Users with adminCount=1 (current or former privileged)' $adminCount 10 25 `
    'Compare with Get-ADPrivilegedGroupMember.ps1. Clear adminCount and restore inheritance on accounts no longer privileged.'

$dcs = $computers | Where-Object { $_.PrimaryGroupID -in 516, 521 }
$unconstrainedComputers = $computers | Where-Object { $_.TrustedForDelegation -and $_.PrimaryGroupID -notin 516, 521 }
Add-Check 'Privilege' 'Non-DC computers with unconstrained delegation' $unconstrainedComputers 1 1 `
    'Replace with constrained or resource-based constrained delegation.'

$unconstrainedUsers = $enabled | Where-Object TrustedForDelegation
Add-Check 'Privilege' 'User accounts with unconstrained delegation' $unconstrainedUsers 1 1 `
    'Remove unconstrained delegation from user and service accounts.'

# ---------------- Hygiene ----------------
$inactive = $enabled | Where-Object {
    ($_.LastLogonDate -and $_.LastLogonDate -lt $idleCutoff) -or (-not $_.LastLogonDate -and $_.whenCreated -lt $idleCutoff)
}
Add-Check 'Hygiene' "Enabled users inactive $InactiveDays+ days" $inactive 1 25 `
    'Run Get-ADInactiveUser.ps1 and disable confirmed leavers.'

$locked = $users | Where-Object LockedOut
Add-Check 'Hygiene' 'Locked out accounts' $locked 5 20 `
    'A spike can indicate password spraying. Correlate with Event ID 4740 and 4625.'

$disabled = $users | Where-Object { -not $_.Enabled }
Add-Check 'Hygiene' 'Disabled user accounts' $disabled 100000 100000 '' -ValueOverride @($disabled).Count

$staleComputers = $computers | Where-Object { $_.Enabled -and $_.LastLogonDate -and $_.LastLogonDate -lt $idleCutoff }
Add-Check 'Hygiene' "Enabled computers inactive $InactiveDays+ days" $staleComputers 1 25 `
    'Disable and move stale computer objects; they keep valid machine credentials.'

$krbtgt = $users | Where-Object SamAccountName -eq 'krbtgt'
$krbAge = if ($krbtgt -and $krbtgt.PasswordLastSet) { [int]($now - $krbtgt.PasswordLastSet).TotalDays } else { -1 }
$krbItems = if ($krbAge -gt 180) { , $krbtgt } else { @() }
Add-Check 'Hygiene' 'krbtgt password age (days)' $krbItems 1 1 `
    'Rotate the krbtgt password twice (with replication in between) at least every 180 days.' -ValueOverride $krbAge

$guestSid = "$($domain.DomainSID.Value)-501"
$guest    = $users | Where-Object { $_.SID.Value -eq $guestSid -and $_.Enabled }
Add-Check 'Hygiene' 'Built-in Guest account enabled' $guest 1 1 'Disable the built-in Guest account.' `
    -ValueOverride ([bool]$guest)

# ---------------- Policy ----------------
$minLenItems = if ($pwdPolicy.MinPasswordLength -lt 14) { , $pwdPolicy } else { @() }
Add-Check 'Policy' 'Default policy minimum password length' $minLenItems 1 1 `
    'Set minimum length to 14+ (or use Fine-Grained Password Policies for privileged accounts).' `
    -ValueOverride $pwdPolicy.MinPasswordLength

$lockoutItems = if ($pwdPolicy.LockoutThreshold -eq 0) { , $pwdPolicy } else { @() }
Add-Check 'Policy' 'Account lockout threshold (0 = disabled)' $lockoutItems 1 1 `
    'Enable a lockout threshold (for example 10 attempts) to slow online password guessing.' `
    -ValueOverride $pwdPolicy.LockoutThreshold

# ---------------- Output ----------------
$summaryPath = Join-Path $OutputDirectory "AD_SecurityPosture_Summary_$stamp.csv"
$results | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Domain: {0}. Users: {1} (enabled {2}). Computers: {3}. DCs: {4}. Report: {5}" -f `
    $domain.DNSRoot, $users.Count, $enabled.Count, $computers.Count, @($dcs).Count, $summaryPath)

$results
