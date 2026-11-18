<#
.SYNOPSIS
    Finds OAuth apps holding high-risk Microsoft Graph or Exchange Online permissions, to detect illicit consent grants and over-privileged apps.

.DESCRIPTION
    Illicit consent grant attacks trick a user into consenting to a malicious app that can then
    read mail or files without a password or MFA. Over-privileged line-of-business apps create
    the same exposure. This script reviews both permission types:

      Delegated   : oauth2PermissionGrants (user or admin consent on behalf of users)
      Application : app role assignments to Microsoft Graph and Office 365 Exchange Online
                    (app-only access to every mailbox / file / directory object)

    Each grant is flagged when it includes a high-risk permission, was consented tenant-wide,
    belongs to a publisher that is not verified, or is a third-party (non-Microsoft, non-tenant) app.

    Investigation and remediation guidance: Microsoft "Detect and Remediate Illicit Consent Grants".

    Read-only.

.PARAMETER HighRiskOnly
    Return only grants containing at least one high-risk permission.

.PARAMETER OutputDirectory
    Folder for the CSV report. Default: .\Reports

.EXAMPLE
    .\Get-EntraRiskyAppPermission.ps1 -HighRiskOnly | Format-Table App, PermissionType, HighRiskPermissions, Findings

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : Microsoft.Graph.Authentication
    Scopes      : Application.Read.All, Directory.Read.All
    Entra role  : Global Reader, Security Reader or Cloud Application Administrator (read)

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [switch]$HighRiskOnly,
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

$ctx  = Connect-GraphIfNeeded -Scopes 'Application.Read.All', 'Directory.Read.All'
$base = 'https://graph.microsoft.com/v1.0'
# Microsoft first-party app owner tenants (Microsoft Services, Microsoft corporate)
$microsoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

# Permissions that allow mass data access, privilege escalation, or persistence
$highRisk = @(
    'Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'MailboxSettings.ReadWrite', 'Mail.ReadBasic.All',
    'Contacts.ReadWrite', 'Calendars.ReadWrite',
    'Files.Read.All', 'Files.ReadWrite.All', 'Sites.Read.All', 'Sites.ReadWrite.All', 'Sites.FullControl.All',
    'Notes.ReadWrite.All', 'Chat.Read.All', 'Chat.ReadWrite.All', 'ChannelMessage.Read.All',
    'Directory.ReadWrite.All', 'Directory.AccessAsUser.All', 'User.ReadWrite.All', 'Group.ReadWrite.All',
    'GroupMember.ReadWrite.All', 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All',
    'RoleManagement.ReadWrite.Directory', 'Policy.ReadWrite.ConditionalAccess',
    'UserAuthenticationMethod.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All',
    'full_access_as_app', 'full_access_as_user', 'EWS.AccessAsUser.All', 'Exchange.ManageAsApp'
)

Write-Verbose 'Reading service principals...'
$spById = @{}
foreach ($sp in (Invoke-GraphPaged -Uri "$base/servicePrincipals?`$select=id,appId,displayName,appOwnerOrganizationId,publisherName,verifiedPublisher,accountEnabled,appRoles")) {
    $spById[$sp.id] = $sp
}

function Get-AppContext {
    param($Sp)
    $owner = if ($Sp.appOwnerOrganizationId -in $microsoftTenantIds) { 'Microsoft' }
             elseif ($Sp.appOwnerOrganizationId -eq $ctx.TenantId) { 'This tenant' }
             else { 'Third party' }
    $verified = [bool]($Sp.verifiedPublisher -and $Sp.verifiedPublisher.displayName)
    [PSCustomObject]@{ Owner = $owner; Verified = $verified; Publisher = if ($verified) { $Sp.verifiedPublisher.displayName } else { $Sp.publisherName } }
}

$rows = New-Object System.Collections.Generic.List[object]

# ---- Delegated permissions ----
Write-Verbose 'Reading delegated permission grants...'
foreach ($g in (Invoke-GraphPaged -Uri "$base/oauth2PermissionGrants")) {
    $client   = $spById[$g.clientId]
    $resource = $spById[$g.resourceId]
    if (-not $client) { continue }
    $scopes = @($g.scope -split '\s+' | Where-Object { $_ })
    $info   = Get-AppContext $client

    $rows.Add([PSCustomObject]@{
        App            = $client.displayName
        AppId          = $client.appId
        PermissionType = 'Delegated'
        Resource       = if ($resource) { $resource.displayName } else { $g.resourceId }
        Permissions    = $scopes
        ConsentType    = if ($g.consentType -eq 'AllPrincipals') { 'Admin (all users)' } else { 'User' }
        PrincipalId    = $g.principalId
        Owner          = $info.Owner
        Publisher      = $info.Publisher
        Verified       = $info.Verified
        Enabled        = $client.accountEnabled
    })
}

# ---- Application permissions (Graph + Exchange Online) ----
$resourceAppIds = @{
    '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
    '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
}
foreach ($resAppId in $resourceAppIds.Keys) {
    $resSp = $spById.Values | Where-Object appId -eq $resAppId | Select-Object -First 1
    if (-not $resSp) { continue }
    $roleNames = @{}
    foreach ($r in @($resSp.appRoles)) { $roleNames[$r.id] = $r.value }

    Write-Verbose "Reading application permissions granted on $($resourceAppIds[$resAppId])..."
    $assignments = Invoke-GraphPaged -Uri "$base/servicePrincipals/$($resSp.id)/appRoleAssignedTo"

    foreach ($grp in ($assignments | Group-Object principalId)) {
        $client = $spById[$grp.Name]
        if (-not $client) { continue }
        $info = Get-AppContext $client
        $rows.Add([PSCustomObject]@{
            App            = $client.displayName
            AppId          = $client.appId
            PermissionType = 'Application'
            Resource       = $resourceAppIds[$resAppId]
            Permissions    = @($grp.Group | ForEach-Object { $roleNames[$_.appRoleId] } | Where-Object { $_ })
            ConsentType    = 'Admin (app-only)'
            PrincipalId    = $null
            Owner          = $info.Owner
            Publisher      = $info.Publisher
            Verified       = $info.Verified
            Enabled        = $client.accountEnabled
        })
    }
}

# ---- Evaluate ----
$report = foreach ($r in $rows) {
    $risky = @($r.Permissions | Where-Object { $_ -in $highRisk })
    if ($HighRiskOnly -and $risky.Count -eq 0) { continue }

    $findings = New-Object System.Collections.Generic.List[string]
    if ($risky.Count -gt 0) {
        $findings.Add('High-risk permission')
        if ($r.ConsentType -ne 'User') { $findings.Add('Tenant-wide') }
        if ($r.Owner -eq 'Third party') { $findings.Add('Third-party app') }
        if ($r.Owner -eq 'Third party' -and -not $r.Verified) { $findings.Add('Unverified publisher') }
    }

    [PSCustomObject]@{
        App                 = $r.App
        AppId               = $r.AppId
        PermissionType      = $r.PermissionType
        Resource            = $r.Resource
        ConsentType         = $r.ConsentType
        HighRiskPermissions = $risky -join ', '
        AllPermissions      = $r.Permissions -join ', '
        AppOwner            = $r.Owner
        Publisher           = $r.Publisher
        VerifiedPublisher   = $r.Verified
        Enabled             = $r.Enabled
        ConsentedByUserId   = $r.PrincipalId
        Findings            = $findings -join '; '
    }
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$csvPath = Join-Path $OutputDirectory ("Entra_AppPermissions_{0:yyyyMMdd_HHmm}.csv" -f (Get-Date))
$report | Sort-Object @{ e = { $_.HighRiskPermissions -ne '' }; Descending = $true }, AppOwner, App |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Grants reviewed: {0}. With high-risk permissions: {1}. Third-party high-risk: {2}. Report: {3}" -f
    $rows.Count, @($report | Where-Object HighRiskPermissions).Count,
    @($report | Where-Object { $_.HighRiskPermissions -and $_.AppOwner -eq 'Third party' }).Count, $csvPath)
$report
