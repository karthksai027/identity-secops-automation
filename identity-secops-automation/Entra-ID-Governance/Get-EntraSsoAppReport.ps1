<#
.SYNOPSIS
    Reviews every single sign-on (SSO) enterprise app in Entra ID: SSO type, SAML certificate expiry, who can sign in, who owns it, and whether anyone still uses it.

.DESCRIPTION
    SSO apps fail in two ways: a SAML signing certificate expires and the app breaks for everyone,
    or an app is left open so that any user in the tenant can sign in to it. This report lists
    every enterprise app (the ones shown under Enterprise applications in the Entra admin centre)
    and flags:

      - SAML signing certificate expired or expiring within -DaysAhead
      - No notification email set for SAML certificate expiry
      - Password-based SSO (stored credentials) instead of SAML or OpenID Connect
      - "Assignment required" turned off, so every user can sign in
      - No owner
      - No sign-ins in -UnusedDays (candidate for removal), when sign-in data is available

    Microsoft first-party apps are skipped unless -IncludeMicrosoftApps is used.

    Read-only.

.PARAMETER DaysAhead
    Window for "certificate expiring soon". Default: 60.

.PARAMETER UnusedDays
    Apps with no sign-in in this many days are flagged. Default: 90.

.PARAMETER IncludeMicrosoftApps
    Include Microsoft first-party enterprise apps.

.PARAMETER OutputDirectory
    Folder for the CSV report. Default: .\Reports

.EXAMPLE
    .\Get-EntraSsoAppReport.ps1 | Where-Object Findings | Format-Table App, SsoType, CertExpires, AssignmentRequired, Findings

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : Microsoft.Graph.Authentication
    Scopes      : Application.Read.All, Directory.Read.All, AuditLog.Read.All (sign-in activity)
    Entra role  : Global Reader or Cloud Application Administrator (read)
    Licence     : App sign-in activity needs Entra ID P1. Everything else works on any licence.

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$DaysAhead = 60,

    [ValidateRange(1, 3650)]
    [int]$UnusedDays = 90,

    [switch]$IncludeMicrosoftApps,

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

Connect-GraphIfNeeded -Scopes 'Application.Read.All', 'Directory.Read.All', 'AuditLog.Read.All' | Out-Null

$base = 'https://graph.microsoft.com/v1.0'
$now  = Get-Date
$microsoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

$select = 'id,appId,displayName,accountEnabled,preferredSingleSignOnMode,appRoleAssignmentRequired,keyCredentials,' +
          'preferredTokenSigningKeyThumbprint,notificationEmailAddresses,appOwnerOrganizationId,loginUrl,homepage'
$uri = "$base/servicePrincipals?`$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')&`$select=$select"

Write-Verbose 'Reading enterprise apps...'
$apps = Invoke-GraphPaged -Uri $uri
if (-not $IncludeMicrosoftApps) { $apps = @($apps | Where-Object { $_.appOwnerOrganizationId -notin $microsoftTenantIds }) }

# Sign-in activity per app (beta report). Optional: skipped if not licensed or not consented.
$lastSignIn = @{}
$signInDataAvailable = $true
try {
    foreach ($s in (Invoke-GraphPaged -Uri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities')) {
        if ($s.lastSignInActivity -and $s.lastSignInActivity.lastSignInDateTime) {
            $lastSignIn[$s.appId] = [datetime]$s.lastSignInActivity.lastSignInDateTime
        }
    }
}
catch {
    $signInDataAvailable = $false
    Write-Warning 'App sign-in activity not available (needs Entra ID P1 and AuditLog.Read.All). Skipping the "unused" check.'
}

$i = 0
$report = foreach ($a in $apps) {
    $i++
    Write-Progress -Activity 'Reviewing SSO apps' -Status $a.displayName -PercentComplete (($i / [math]::Max(@($apps).Count, 1)) * 100)

    $mode = if ($a.preferredSingleSignOnMode) { $a.preferredSingleSignOnMode } else { 'none' }

    # Active SAML signing certificate
    $signCerts = @($a.keyCredentials | Where-Object { $_ -and $_.usage -eq 'Sign' })
    $activeCert = $null
    if ($signCerts.Count -gt 0) {
        # customKeyIdentifier holds the certificate thumbprint as base64; compare it to the hex thumbprint in use
        $activeCert = $signCerts | Where-Object {
            $kid = "$($_.customKeyIdentifier)"
            $hex = try { -join ([Convert]::FromBase64String($kid) | ForEach-Object { $_.ToString('X2') }) } catch { $kid }
            $a.preferredTokenSigningKeyThumbprint -and ($hex -eq "$($a.preferredTokenSigningKeyThumbprint)".ToUpperInvariant() -or $kid -eq $a.preferredTokenSigningKeyThumbprint)
        } | Select-Object -First 1
        if (-not $activeCert) { $activeCert = $signCerts | Sort-Object { [datetime]$_.endDateTime } -Descending | Select-Object -First 1 }
    }
    $certExpires = if ($activeCert) { [datetime]$activeCert.endDateTime } else { $null }
    $certDays    = if ($certExpires) { [int][math]::Floor(($certExpires - $now).TotalDays) } else { $null }

    # Assign first: Invoke-GraphPaged returns one list object, which @() would wrap instead of enumerate
    $ownerList  = Invoke-GraphPaged -Uri "$base/servicePrincipals/$($a.id)/owners?`$select=displayName,userPrincipalName"
    $assignList = Invoke-GraphPaged -Uri "$base/servicePrincipals/$($a.id)/appRoleAssignedTo?`$select=principalType"
    $owners      = @($ownerList)
    $assignments = @($assignList)
    $users  = @($assignments | Where-Object principalType -eq 'User').Count
    $groups = @($assignments | Where-Object principalType -eq 'Group').Count

    $last = if ($lastSignIn.ContainsKey($a.appId)) { $lastSignIn[$a.appId] } else { $null }

    $findings = New-Object System.Collections.Generic.List[string]
    if ($mode -eq 'saml') {
        if (-not $certExpires) { $findings.Add('SAML app with no signing certificate') }
        elseif ($certDays -lt 0) { $findings.Add('SAML certificate EXPIRED') }
        elseif ($certDays -le $DaysAhead) { $findings.Add("SAML certificate expires in $certDays days") }
        if (@($a.notificationEmailAddresses | Where-Object { $_ }).Count -eq 0) { $findings.Add('No certificate expiry notification email') }
    }
    if ($mode -eq 'password') { $findings.Add('Password-based SSO (prefer SAML/OIDC)') }
    if (-not $a.appRoleAssignmentRequired -and $mode -in 'saml', 'password', 'oidc') { $findings.Add('Assignment not required: every user can sign in') }
    if ($owners.Count -eq 0) { $findings.Add('No owner') }
    if ($signInDataAvailable -and $a.accountEnabled -and (-not $last -or $last -lt $now.AddDays(-$UnusedDays))) { $findings.Add("No sign-ins for $UnusedDays+ days") }
    if (-not $a.accountEnabled) { $findings.Add('Disabled') }

    [PSCustomObject]@{
        App                = $a.displayName
        SsoType            = $mode
        Enabled            = $a.accountEnabled
        AssignmentRequired = $a.appRoleAssignmentRequired
        AssignedUsers      = $users
        AssignedGroups     = $groups
        Owners             = (@($owners | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) -join '; ')
        CertExpires        = $certExpires
        CertDaysLeft       = $certDays
        NotificationEmails = (@($a.notificationEmailAddresses) -join '; ')
        LastSignIn         = $last
        Findings           = $findings -join '; '
        AppId              = $a.appId
    }
}
Write-Progress -Activity 'Reviewing SSO apps' -Completed

$report = @($report | Sort-Object @{ e = { if ($null -ne $_.CertDaysLeft) { $_.CertDaysLeft } else { 99999 } } }, App)

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("Entra_SsoApps_{0:yyyyMMdd_HHmm}.csv" -f $now)
$report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Apps: {0}. SAML: {1}. Cert expired/expiring: {2}. Open to all users: {3}. No owner: {4}. Report: {5}" -f $report.Count,
    @($report | Where-Object SsoType -eq 'saml').Count,
    @($report | Where-Object { $_.Findings -match 'SAML certificate' }).Count,
    @($report | Where-Object { $_.Findings -match 'Assignment not required' }).Count,
    @($report | Where-Object { $_.Findings -match 'No owner' }).Count, $csvPath)

$report
