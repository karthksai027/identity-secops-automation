<#
.SYNOPSIS
    Checks every Entra ID app registration for risky OAuth 2.0 and OpenID Connect settings: implicit flow, public client flows, unsafe redirect URIs, secrets instead of certificates, and more.

.DESCRIPTION
    How an app registration is configured decides which OAuth flows attackers can use against it.
    This report reviews each app registration and flags:

      Flows
        - Implicit grant issuing access tokens (tokens in the URL; use auth code + PKCE)
        - Implicit grant issuing ID tokens (only needed by old SPA libraries)
        - "Allow public client flows" on (enables ROPC and device code, which skip interactive
          sign-in and are a favourite of password spray and device code phishing)
      Redirect URIs
        - http:// on anything other than localhost (codes and tokens in clear text)
        - Wildcards (open redirect / token theft)
        - Hosts on shared cloud domains (azurewebsites.net, cloudapp.net, herokuapp.com,
          ngrok, ...) that can be taken over if the resource is deleted
        - localhost on a web (confidential) app
      Credentials
        - Client secrets in use (prefer certificates, managed identity or federated credentials)
      Exposure
        - Multi-tenant or personal-account sign-in audience
        - App instance property lock off on a multi-tenant app
        - No owner

    Read-only.

.PARAMETER OutputDirectory
    Folder for the CSV report. Default: .\Reports

.EXAMPLE
    .\Get-EntraAppRegistrationSecurityReport.ps1 | Where-Object Findings | Format-Table App, SignInAudience, Findings -Wrap

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : Microsoft.Graph.Authentication
    Scopes      : Application.Read.All
    Entra role  : Global Reader or Application Administrator (read)

.LINK
    https://github.com/karthksai027/identity-secops-automation
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

Connect-GraphIfNeeded -Scopes 'Application.Read.All' | Out-Null

$base = 'https://graph.microsoft.com/v1.0'
$select = 'id,appId,displayName,signInAudience,web,spa,publicClient,isFallbackPublicClient,api,' +
          'passwordCredentials,keyCredentials,servicePrincipalLockConfiguration,createdDateTime'

Write-Verbose 'Reading app registrations...'
$apps = Invoke-GraphPaged -Uri "$base/applications?`$select=$select"

$takeoverDomains = 'azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|' +
                   'azurestaticapps\.net|azureedge\.net|herokuapp\.com|ngrok\.io|ngrok-free\.app|github\.io|netlify\.app|vercel\.app'

$report = foreach ($a in $apps) {
    $findings = New-Object System.Collections.Generic.List[string]

    $webUris    = @($a.web.redirectUris | Where-Object { $_ })
    $spaUris    = @($a.spa.redirectUris | Where-Object { $_ })
    $publicUris = @($a.publicClient.redirectUris | Where-Object { $_ })
    $allUris    = @($webUris + $spaUris + $publicUris)

    # ---- Flows ----
    $implicit = $a.web.implicitGrantSettings
    if ($implicit -and $implicit.enableAccessTokenIssuance) { $findings.Add('Implicit flow issues access tokens') }
    if ($implicit -and $implicit.enableIdTokenIssuance) { $findings.Add('Implicit flow issues ID tokens') }
    if ($a.isFallbackPublicClient) { $findings.Add('Public client flows allowed (ROPC / device code)') }

    # ---- Redirect URIs ----
    foreach ($u in $allUris) {
        $isLocal = $u -match '^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(/|$)'
        if ($u -match '\*') { $findings.Add("Wildcard redirect URI: $u") }
        elseif ($u -match '^http://' -and -not $isLocal) { $findings.Add("Plain HTTP redirect URI: $u") }
        if ($u -match "^https?://[^/]*($takeoverDomains)(:\d+)?(/|$)") { $findings.Add("Redirect URI on a shared cloud domain (check it still exists): $u") }
    }
    if (@($webUris | Where-Object { $_ -match '^https?://(localhost|127\.0\.0\.1)' }).Count -gt 0) { $findings.Add('localhost redirect URI on a web app (remove in production)') }

    # ---- Credentials ----
    $secrets = @($a.passwordCredentials | Where-Object { $_ })
    $certs   = @($a.keyCredentials | Where-Object { $_ })
    if ($secrets.Count -gt 0) { $findings.Add("$($secrets.Count) client secret(s): prefer certificates or federated credentials") }

    # ---- Exposure ----
    if ($a.signInAudience -ne 'AzureADMyOrg') { $findings.Add("Sign-in audience $($a.signInAudience) (not single-tenant)") }
    if ($a.signInAudience -ne 'AzureADMyOrg' -and -not ($a.servicePrincipalLockConfiguration -and $a.servicePrincipalLockConfiguration.isEnabled)) {
        $findings.Add('App instance property lock off on a multi-tenant app')
    }

    $ownerList = Invoke-GraphPaged -Uri "$base/applications/$($a.id)/owners?`$select=userPrincipalName,displayName"
    $owners = @($ownerList)
    if ($owners.Count -eq 0) { $findings.Add('No owner') }

    $platforms = @()
    if ($webUris.Count -or ($implicit -and ($implicit.enableAccessTokenIssuance -or $implicit.enableIdTokenIssuance))) { $platforms += 'Web' }
    if ($spaUris.Count) { $platforms += 'SPA' }
    if ($publicUris.Count -or $a.isFallbackPublicClient) { $platforms += 'Public/mobile/desktop' }

    [PSCustomObject]@{
        App                 = $a.displayName
        AppId               = $a.appId
        SignInAudience      = $a.signInAudience
        Platforms           = $platforms -join ', '
        ImplicitAccessToken = [bool]($implicit -and $implicit.enableAccessTokenIssuance)
        ImplicitIdToken     = [bool]($implicit -and $implicit.enableIdTokenIssuance)
        PublicClientFlows   = [bool]$a.isFallbackPublicClient
        RedirectUris        = $allUris -join ' | '
        Secrets             = $secrets.Count
        Certificates        = $certs.Count
        AccessTokenVersion  = if ($a.api -and $a.api.requestedAccessTokenVersion) { "v$($a.api.requestedAccessTokenVersion)" } else { 'v1 (default)' }
        Owners              = (@($owners | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) -join '; ')
        Created             = $a.createdDateTime
        Findings            = $findings -join '; '
        RiskScore           = @($findings | Where-Object { $_ -match 'Implicit flow issues access|Public client|Wildcard|Plain HTTP|shared cloud domain' }).Count * 2 +
                              @($findings | Where-Object { $_ -notmatch 'Implicit flow issues access|Public client|Wildcard|Plain HTTP|shared cloud domain' }).Count
    }
}
$report = @($report | Sort-Object RiskScore -Descending)

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("Entra_AppRegistrationSecurity_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date))
$report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("App registrations: {0}. Implicit access tokens: {1}. Public client flows: {2}. Risky redirect URIs: {3}. Using secrets: {4}. Report: {5}" -f $report.Count,
    @($report | Where-Object ImplicitAccessToken).Count, @($report | Where-Object PublicClientFlows).Count,
    @($report | Where-Object { $_.Findings -match 'Wildcard|Plain HTTP|shared cloud domain' }).Count,
    @($report | Where-Object { $_.Secrets -gt 0 }).Count, $csvPath)

$report
