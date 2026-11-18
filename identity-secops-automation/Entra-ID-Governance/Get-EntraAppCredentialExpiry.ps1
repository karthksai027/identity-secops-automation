<#
.SYNOPSIS
    Reports client secrets and certificates on Entra ID app registrations and service principals that are expired, expiring, or too long-lived.

.DESCRIPTION
    Expired app credentials cause outages; long-lived client secrets are a favourite
    persistence mechanism after a tenant compromise (attackers add a secret to an existing
    app). This script inventories every credential and flags:

      - Expired
      - Expiring within -DaysAhead
      - Client secret valid for more than -MaxSecretLifetimeDays (Microsoft recommends short-lived
        secrets, or certificates / managed identities / federated credentials instead)
      - Credential created in the last -RecentDays (review for unexpected additions)
      - App with no owner (nobody responsible for rotation)

    Covers app registrations (secrets and certificates) and enterprise apps / service principals
    (for example SAML signing certificates).

    Read-only.

.PARAMETER DaysAhead
    Window for "expiring soon". Default: 30.

.PARAMETER MaxSecretLifetimeDays
    Secrets valid longer than this are flagged. Default: 365.

.PARAMETER RecentDays
    Credentials created within this many days are flagged for review. Default: 7.

.PARAMETER SkipOwners
    Skip owner lookups (faster on large tenants).

.PARAMETER OutputDirectory
    Folder for the CSV report. Default: .\Reports

.EXAMPLE
    .\Get-EntraAppCredentialExpiry.ps1 -DaysAhead 60 | Where-Object Status -ne 'Valid'

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
    [ValidateRange(1, 3650)][int]$DaysAhead = 30,
    [ValidateRange(1, 36500)][int]$MaxSecretLifetimeDays = 365,
    [ValidateRange(1, 365)][int]$RecentDays = 7,
    [switch]$SkipOwners,
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
$now  = Get-Date

Write-Verbose 'Reading app registrations...'
$apps = Invoke-GraphPaged -Uri "$base/applications?`$select=id,appId,displayName,passwordCredentials,keyCredentials"

Write-Verbose 'Reading service principals...'
$sps = Invoke-GraphPaged -Uri "$base/servicePrincipals?`$select=id,appId,displayName,appOwnerOrganizationId,passwordCredentials,keyCredentials,servicePrincipalType"
# Keep only service principals that hold their own credentials (for example SAML signing certificates)
$sps = $sps | Where-Object { @(@($_.keyCredentials) + @($_.passwordCredentials) | Where-Object { $_ }).Count -gt 0 }

$objects = @()
$objects += $apps | ForEach-Object { [PSCustomObject]@{ Obj = $_; Kind = 'AppRegistration'; OwnerUri = "$base/applications/$($_.id)/owners?`$select=displayName,userPrincipalName" } }
$objects += $sps  | ForEach-Object { [PSCustomObject]@{ Obj = $_; Kind = 'ServicePrincipal'; OwnerUri = "$base/servicePrincipals/$($_.id)/owners?`$select=displayName,userPrincipalName" } }

$report = foreach ($o in $objects) {
    $creds = @()
    $creds += @($o.Obj.passwordCredentials) | Where-Object { $_ } | ForEach-Object { [PSCustomObject]@{ C = $_; Type = 'Secret' } }
    $creds += @($o.Obj.keyCredentials)      | Where-Object { $_ } | ForEach-Object { [PSCustomObject]@{ C = $_; Type = "Certificate ($($_.usage))" } }
    if ($creds.Count -eq 0) { continue }

    $owners = $null
    if (-not $SkipOwners) {
        try {
            $ownerList = Invoke-GraphPaged -Uri $o.OwnerUri
            $owners = (@($ownerList) | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) -join '; '
        }
        catch { $owners = 'Unknown (lookup failed)' }
    }

    foreach ($cr in $creds) {
        $start = if ($cr.C.startDateTime) { [datetime]$cr.C.startDateTime } else { $null }
        $end   = [datetime]$cr.C.endDateTime
        $days  = [int][math]::Floor(($end - $now).TotalDays)
        $lifetime = if ($start) { [int]($end - $start).TotalDays } else { $null }

        $status = if ($end -lt $now) { 'Expired' } elseif ($days -le $DaysAhead) { 'Expiring soon' } else { 'Valid' }

        $findings = New-Object System.Collections.Generic.List[string]
        if ($status -ne 'Valid') { $findings.Add($status) }
        if ($cr.Type -eq 'Secret' -and $lifetime -gt $MaxSecretLifetimeDays -and $status -ne 'Expired') {
            $findings.Add("Secret lifetime $lifetime days (> $MaxSecretLifetimeDays)")
        }
        if ($start -and $start -gt $now.AddDays(-$RecentDays)) { $findings.Add("Created in last $RecentDays days - verify") }
        if (-not $SkipOwners -and -not $owners -and $o.Kind -eq 'AppRegistration') { $findings.Add('No owner') }

        [PSCustomObject]@{
            DisplayName    = $o.Obj.displayName
            AppId          = $o.Obj.appId
            ObjectType     = $o.Kind
            CredentialType = $cr.Type
            CredentialName = $cr.C.displayName
            KeyId          = $cr.C.keyId
            StartDate      = $start
            EndDate        = $end
            DaysRemaining  = $days
            LifetimeDays   = $lifetime
            Status         = $status
            Owners         = $owners
            Findings       = $findings -join '; '
        }
    }
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("Entra_AppCredentials_{0:yyyyMMdd_HHmm}.csv" -f $now)
$report | Sort-Object DaysRemaining | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Credentials: {0}. Expired: {1}. Expiring in {2} days: {3}. Report: {4}" -f @($report).Count,
    @($report | Where-Object Status -eq 'Expired').Count, $DaysAhead, @($report | Where-Object Status -eq 'Expiring soon').Count, $csvPath)
$report
