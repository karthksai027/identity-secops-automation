<#
.SYNOPSIS
    Backs up all Conditional Access policies and named locations to JSON and runs a coverage gap analysis.

.DESCRIPTION
    Conditional Access is the Zero Trust policy engine of Entra ID, and a single bad edit can
    lock out a tenant or silently remove MFA. This script:

      1. Exports every CA policy and named location as JSON (policy-as-code backup you can
         diff in Git or restore through Graph).
      2. Writes a readable summary CSV (state, users, apps, conditions, grant and session controls).
      3. Checks for the baseline policies Microsoft recommends and reports any that are missing:
           - Block legacy authentication
           - Require MFA for all users
           - Require MFA (or authentication strength) for admin roles
           - Sign-in risk or user risk based policy (Entra ID P2)
           - Policies left in report-only mode
           - Enabled policies with no excluded users (no break-glass exclusion)

    Read-only.

.PARAMETER OutputDirectory
    Parent folder; a dated sub-folder is created. Default: .\Reports

.EXAMPLE
    .\Export-EntraConditionalAccessPolicy.ps1 -Verbose

.NOTES
    Module      : Microsoft.Graph.Authentication
    Scopes      : Policy.Read.All
    Entra role  : Global Reader, Security Reader or Conditional Access Administrator
    Licence     : Conditional Access requires Microsoft Entra ID P1.
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
    , $items
}

function Join-List { param($Value) if ($null -eq $Value) { '' } else { (@($Value) | Where-Object { $_ }) -join ', ' } }
#endregion

Connect-GraphIfNeeded -Scopes 'Policy.Read.All' | Out-Null

$base     = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess'
$runDir   = Join-Path $OutputDirectory ("ConditionalAccess_{0:yyyyMMdd_HHmm}" -f (Get-Date))
$polDir   = Join-Path $runDir 'policies'
$locDir   = Join-Path $runDir 'namedLocations'
New-Item -Path $polDir, $locDir -ItemType Directory -Force | Out-Null

Write-Verbose 'Reading Conditional Access policies and named locations...'
$policies  = Invoke-GraphPaged -Uri "$base/policies"
$locations = Invoke-GraphPaged -Uri "$base/namedLocations"

# ---- 1. JSON backup ----
foreach ($p in $policies) {
    $file = ($p.displayName -replace '[\\/:*?"<>|]', '_') + "_$($p.id.Substring(0, 8)).json"
    $p | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $polDir $file) -Encoding UTF8
}
foreach ($l in $locations) {
    $file = ($l.displayName -replace '[\\/:*?"<>|]', '_') + "_$($l.id.Substring(0, 8)).json"
    $l | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $locDir $file) -Encoding UTF8
}

# ---- 2. Summary ----
$summary = foreach ($p in $policies) {
    $c = $p.conditions
    $g = $p.grantControls
    [PSCustomObject]@{
        DisplayName          = $p.displayName
        State                = $p.state
        IncludeUsers         = Join-List $c.users.includeUsers
        ExcludeUsers         = @($c.users.excludeUsers).Count
        IncludeGroups        = @($c.users.includeGroups).Count
        ExcludeGroups        = @($c.users.excludeGroups).Count
        IncludeRoles         = @($c.users.includeRoles).Count
        IncludeGuests        = [bool]$c.users.includeGuestsOrExternalUsers
        IncludeApplications  = Join-List $c.applications.includeApplications
        UserActions          = Join-List $c.applications.includeUserActions
        ClientAppTypes       = Join-List $c.clientAppTypes
        Platforms            = if ($c.platforms) { Join-List $c.platforms.includePlatforms } else { '' }
        Locations            = if ($c.locations) { Join-List $c.locations.includeLocations } else { '' }
        SignInRiskLevels     = Join-List $c.signInRiskLevels
        UserRiskLevels       = Join-List $c.userRiskLevels
        GrantControls        = if ($g) { Join-List $g.builtInControls } else { '' }
        GrantOperator        = if ($g) { $g.operator } else { '' }
        AuthenticationStrength = if ($g -and $g.authenticationStrength) { $g.authenticationStrength.displayName } else { '' }
        SessionControls      = if ($p.sessionControls) { Join-List ($p.sessionControls.PSObject.Properties | Where-Object { $_.Value } | ForEach-Object Name) } else { '' }
        Modified             = $p.modifiedDateTime
        Id                   = $p.id
    }
}
$summaryPath = Join-Path $runDir 'ConditionalAccess_Summary.csv'
$summary | Sort-Object State, DisplayName | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

# ---- 3. Gap analysis ----
$enabled = @($policies | Where-Object state -eq 'enabled')

function Test-RequiresMfa { param($Policy)
    $g = $Policy.grantControls
    $g -and ((@($g.builtInControls) -contains 'mfa') -or $g.authenticationStrength)
}

$legacyBlock = $enabled | Where-Object {
    $types = @($_.conditions.clientAppTypes)
    ($types -contains 'exchangeActiveSync' -or $types -contains 'other') -and
    (@($_.grantControls.builtInControls) -contains 'block')
}
$mfaAll = $enabled | Where-Object {
    (@($_.conditions.users.includeUsers) -contains 'All') -and
    (@($_.conditions.applications.includeApplications) -contains 'All') -and (Test-RequiresMfa $_)
}
$mfaAdmins = $enabled | Where-Object { @($_.conditions.users.includeRoles).Count -gt 0 -and (Test-RequiresMfa $_) }
$riskBased = $enabled | Where-Object { @($_.conditions.signInRiskLevels).Count -gt 0 -or @($_.conditions.userRiskLevels).Count -gt 0 }
$reportOnly = $policies | Where-Object state -eq 'enabledForReportingButNotEnforced'
$noExclusion = $enabled | Where-Object {
    @($_.conditions.users.excludeUsers).Count -eq 0 -and @($_.conditions.users.excludeGroups).Count -eq 0 -and
    (@($_.grantControls.builtInControls) -contains 'block' -or (@($_.conditions.users.includeUsers) -contains 'All'))
}

$gaps = @(
    [PSCustomObject]@{ Check = 'Block legacy authentication'; Status = if ($legacyBlock) { 'OK' } else { 'Missing' }; Policies = Join-List ($legacyBlock.displayName)
        Recommendation = 'Block client app types "Exchange ActiveSync" and "Other clients" for all users.' }
    [PSCustomObject]@{ Check = 'Require MFA for all users'; Status = if ($mfaAll) { 'OK' } else { 'Missing' }; Policies = Join-List ($mfaAll.displayName)
        Recommendation = 'All users, all cloud apps, grant: require MFA or an authentication strength. Exclude break-glass accounts.' }
    [PSCustomObject]@{ Check = 'Require MFA for admin roles'; Status = if ($mfaAdmins) { 'OK' } else { 'Missing' }; Policies = Join-List ($mfaAdmins.displayName)
        Recommendation = 'Target directory roles with the "Phishing-resistant MFA" authentication strength.' }
    [PSCustomObject]@{ Check = 'Risk-based policy (sign-in or user risk)'; Status = if ($riskBased) { 'OK' } else { 'Missing' }; Policies = Join-List ($riskBased.displayName)
        Recommendation = 'With Entra ID P2: require MFA for medium/high sign-in risk and secure password change for high user risk.' }
    [PSCustomObject]@{ Check = 'Policies in report-only mode'; Status = if ($reportOnly) { 'Review' } else { 'OK' }; Policies = Join-List ($reportOnly.displayName)
        Recommendation = 'Review sign-in impact in the CA insights workbook, then switch to On or delete.' }
    [PSCustomObject]@{ Check = 'Broad policies without any exclusion (break-glass)'; Status = if ($noExclusion) { 'Review' } else { 'OK' }; Policies = Join-List ($noExclusion.displayName)
        Recommendation = 'Exclude two monitored emergency access accounts from broad or blocking policies to avoid tenant lockout.' }
)
$gapPath = Join-Path $runDir 'ConditionalAccess_GapAnalysis.csv'
$gaps | Export-Csv -Path $gapPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Policies: {0} (enabled {1}, report-only {2}, disabled {3}). Named locations: {4}. Output: {5}" -f
    $policies.Count, $enabled.Count, @($reportOnly).Count, @($policies | Where-Object state -eq 'disabled').Count, $locations.Count, $runDir)

$gaps
