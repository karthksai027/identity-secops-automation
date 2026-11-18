<#
.SYNOPSIS
    Audits Entra ID tenant-wide identity security settings against Microsoft recommended practice and returns a pass/fail scorecard.

.DESCRIPTION
    A quick, repeatable tenant health check covering the settings an identity engineer is
    expected to know (SC-300 and Microsoft Secure Score identity controls):

      Access         : Security defaults vs Conditional Access, Global Administrator count
      Authentication : Weak methods (SMS / voice) enabled, FIDO2 / passkeys available,
                       Temporary Access Pass, authentication methods migration state,
                       MFA registration campaign
      Consent        : User consent to apps, admin consent workflow
      Collaboration  : Who can invite guests, guest directory access level, email-verified self sign-up
      Hardening      : Users can register apps, legacy MSOnline PowerShell blocked
      Hybrid         : Directory synchronisation status and last sync time

    Each check returns Status = Pass, Review or Fail with a recommendation.

    Read-only.

.PARAMETER OutputDirectory
    Folder for the CSV report. Default: .\Reports

.EXAMPLE
    .\Test-EntraTenantSecurityBaseline.ps1 | Format-Table Area, Check, Value, Status -AutoSize

.NOTES
    Module      : Microsoft.Graph.Authentication
    Scopes      : Policy.Read.All, RoleManagement.Read.Directory, Directory.Read.All
    Entra role  : Global Reader (least privilege, read-only)
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
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

function Invoke-GraphGet {
    param([Parameter(Mandatory)][string]$Uri)
    Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
}
#endregion

Connect-GraphIfNeeded -Scopes 'Policy.Read.All', 'RoleManagement.Read.Directory', 'Directory.Read.All' | Out-Null
$base = 'https://graph.microsoft.com/v1.0'

$results = New-Object System.Collections.Generic.List[object]
function Add-Result {
    param([string]$Area, [string]$Check, $Value, [ValidateSet('Pass', 'Review', 'Fail', 'Error')][string]$Status, [string]$Recommendation)
    $results.Add([PSCustomObject]@{
        Area           = $Area
        Check          = $Check
        Value          = "$Value"
        Status         = $Status
        Recommendation = if ($Status -eq 'Pass') { '' } else { $Recommendation }
    })
}

# Each section is isolated so one missing permission or licence does not stop the audit
# ---------------- Access ----------------
try {
    $sd = Invoke-GraphGet "$base/policies/identitySecurityDefaultsEnforcementPolicy"
    $ca = (Invoke-GraphGet "$base/identity/conditionalAccess/policies?`$select=id,state").value
    $caEnabled = @($ca | Where-Object state -eq 'enabled').Count
    if ($sd.isEnabled) {
        Add-Result 'Access' 'Security defaults' 'Enabled' 'Review' 'Fine for small tenants. With Entra ID P1, replace with Conditional Access for granular control.'
    }
    elseif ($caEnabled -gt 0) {
        Add-Result 'Access' 'Security defaults / Conditional Access' "Security defaults off, $caEnabled CA policies enabled" 'Pass' ''
    }
    else {
        Add-Result 'Access' 'Security defaults / Conditional Access' 'Security defaults off and no CA policy enabled' 'Fail' 'Enable security defaults or deploy baseline Conditional Access policies immediately.'
    }
}
catch { Add-Result 'Access' 'Security defaults / Conditional Access' $_.Exception.Message 'Error' 'Check Policy.Read.All consent.' }

try {
    $ga = (Invoke-GraphGet "$base/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'").value
    $gaCount = @($ga).Count
    $status = if ($gaCount -lt 2 -or $gaCount -gt 4) { 'Fail' } else { 'Pass' }
    Add-Result 'Access' 'Active Global Administrators' $gaCount $status 'Keep 2-4 Global Admins including 2 break-glass accounts; use PIM and least-privileged roles for everyone else.'
}
catch { Add-Result 'Access' 'Active Global Administrators' $_.Exception.Message 'Error' 'Check RoleManagement.Read.Directory consent.' }

# ---------------- Authentication ----------------
try {
    $amp = Invoke-GraphGet "$base/policies/authenticationMethodsPolicy"
    $cfg = @{}
    foreach ($m in $amp.authenticationMethodConfigurations) { $cfg[$m.id] = $m.state }

    $weak = @('Sms', 'Voice') | Where-Object { $cfg[$_] -eq 'enabled' }
    Add-Result 'Authentication' 'Weak methods enabled (SMS / Voice)' $(if ($weak) { $weak -join ', ' } else { 'None' }) $(if ($weak) { 'Review' } else { 'Pass' }) `
        'Move users to Microsoft Authenticator or passkeys, then scope SMS/Voice to a small exception group or disable.'

    Add-Result 'Authentication' 'FIDO2 security keys / passkeys' $cfg['Fido2'] $(if ($cfg['Fido2'] -eq 'enabled') { 'Pass' } else { 'Review' }) `
        'Enable FIDO2/passkeys at least for administrators to support phishing-resistant MFA.'

    Add-Result 'Authentication' 'Temporary Access Pass' $cfg['TemporaryAccessPass'] $(if ($cfg['TemporaryAccessPass'] -eq 'enabled') { 'Pass' } else { 'Review' }) `
        'Enable TAP for secure onboarding and passwordless bootstrap.'

    $migration = $amp.policyMigrationState
    Add-Result 'Authentication' 'Authentication methods migration state' $migration $(if ($migration -eq 'migrationComplete') { 'Pass' } else { 'Review' }) `
        'Complete migration from legacy MFA and SSPR policies to the unified Authentication methods policy.'

    $campaign = $amp.registrationEnforcement.authenticationMethodsRegistrationCampaign.state
    Add-Result 'Authentication' 'MFA registration campaign (nudge)' $campaign $(if ($campaign -in 'enabled', 'default') { 'Pass' } else { 'Review' }) `
        'Enable the registration campaign to nudge users to set up Microsoft Authenticator.'
}
catch { Add-Result 'Authentication' 'Authentication methods policy' $_.Exception.Message 'Error' 'Check Policy.Read.All consent.' }

# ---------------- Consent, collaboration, hardening ----------------
try {
    $auth  = Invoke-GraphGet "$base/policies/authorizationPolicy"
    $perms = $auth.defaultUserRolePermissions
    $grant = @($perms.permissionGrantPoliciesAssigned)

    $consentValue = if ($grant -match 'microsoft-user-default-legacy') { 'Users can consent to any app' }
                    elseif ($grant -match 'microsoft-user-default-low') { 'Verified publishers, low-risk permissions only' }
                    elseif ($grant.Count -eq 0) { 'User consent disabled' }
                    else { $grant -join ', ' }
    $consentStatus = if ($grant -match 'legacy') { 'Fail' } else { 'Pass' }
    Add-Result 'Consent' 'User consent to applications' $consentValue $consentStatus `
        'Allow user consent only for verified publishers and low-risk permissions, or disable it and use the admin consent workflow.'

    Add-Result 'Collaboration' 'Who can invite guests' $auth.allowInvitesFrom $(if ($auth.allowInvitesFrom -eq 'everyone') { 'Fail' } elseif ($auth.allowInvitesFrom -eq 'adminsGuestInvitersAndAllMembers') { 'Review' } else { 'Pass' }) `
        'Restrict invitations to admins and the Guest Inviter role (adminsAndGuestInviters).'

    $guestRole = switch ($auth.guestUserRoleId) {
        'a0b1b346-4d3e-4e8b-98f8-753987be4970' { 'Same access as members' }
        '10dae51f-b6af-4016-8d66-8c2a99b929b3' { 'Limited access (default)' }
        '2af84b1e-32c8-42b7-82bc-daa82404023b' { 'Restricted access' }
        default { $auth.guestUserRoleId }
    }
    Add-Result 'Collaboration' 'Guest directory access' $guestRole $(if ($guestRole -eq 'Same access as members') { 'Fail' } elseif ($guestRole -eq 'Restricted access') { 'Pass' } else { 'Review' }) `
        'Set guest access to "restricted" so guests cannot enumerate users and groups.'

    Add-Result 'Collaboration' 'Email-verified self-service sign-up' $auth.allowEmailVerifiedUsersToJoinOrganization $(if ($auth.allowEmailVerifiedUsersToJoinOrganization) { 'Fail' } else { 'Pass' }) `
        'Disable so unmanaged (viral) users cannot join the tenant.'

    Add-Result 'Hardening' 'Users can register applications' $perms.allowedToCreateApps $(if ($perms.allowedToCreateApps) { 'Fail' } else { 'Pass' }) `
        'Set to No; delegate app registration through the Application Developer role.'

    Add-Result 'Hardening' 'Users can create security groups' $perms.allowedToCreateSecurityGroups $(if ($perms.allowedToCreateSecurityGroups) { 'Review' } else { 'Pass' }) `
        'Restrict security group creation to admins or a delegated group.'

    Add-Result 'Hardening' 'Legacy MSOnline PowerShell blocked for non-admins' $auth.blockMsolPowerShell $(if ($auth.blockMsolPowerShell) { 'Pass' } else { 'Review' }) `
        'Block MSOnline PowerShell; it is retired and bypasses some modern controls.'
}
catch { Add-Result 'Consent' 'Authorization policy' $_.Exception.Message 'Error' 'Check Policy.Read.All consent.' }

try {
    $acr = Invoke-GraphGet "$base/policies/adminConsentRequestPolicy"
    Add-Result 'Consent' 'Admin consent request workflow' $acr.isEnabled $(if ($acr.isEnabled) { 'Pass' } else { 'Review' }) `
        'Enable the admin consent workflow so users can request apps instead of being blocked or consenting themselves.'
}
catch { Add-Result 'Consent' 'Admin consent request workflow' $_.Exception.Message 'Error' 'Check Policy.Read.All consent.' }

# ---------------- Hybrid ----------------
try {
    $org = (Invoke-GraphGet "$base/organization?`$select=displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime").value | Select-Object -First 1
    if ($org.onPremisesSyncEnabled) {
        $last = [datetime]$org.onPremisesLastSyncDateTime
        $hours = [int]((Get-Date).ToUniversalTime() - $last.ToUniversalTime()).TotalHours
        Add-Result 'Hybrid' 'Directory sync last run (hours ago)' $hours $(if ($hours -gt 3) { 'Fail' } else { 'Pass' }) `
            'Sync normally runs every 30 minutes. Check the Entra Connect / Cloud Sync server and Entra Connect Health.'
    }
    else {
        Add-Result 'Hybrid' 'Directory synchronisation' 'Cloud-only tenant' 'Pass' ''
    }
}
catch { Add-Result 'Hybrid' 'Directory synchronisation' $_.Exception.Message 'Error' 'Check Directory.Read.All consent.' }

# ---------------- Output ----------------
if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("Entra_TenantBaseline_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date))
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$score = [math]::Round((@($results | Where-Object Status -eq 'Pass').Count / [math]::Max(@($results | Where-Object Status -ne 'Error').Count, 1)) * 100)
Write-Verbose ("Baseline score: {0}% pass. Fail: {1}. Review: {2}. Report: {3}" -f $score,
    @($results | Where-Object Status -eq 'Fail').Count, @($results | Where-Object Status -eq 'Review').Count, $csvPath)

$results
