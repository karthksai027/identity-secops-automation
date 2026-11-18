<#
.SYNOPSIS
    Reports every Entra ID directory role assignment (active and PIM-eligible) and flags privileged-access risks.

.DESCRIPTION
    Covers the SC-300 "plan and implement privileged access" objective. For every role
    assignment the script records the principal, the role, whether the role is highly
    privileged, and how it is held:

      Permanent      : standing active assignment
      PIM activated  : time-bound activation of an eligible assignment
      PIM eligible   : must be activated through Privileged Identity Management

    Findings raised:
      - Global Administrator count outside the recommended 2-4 range
      - Permanent (standing) assignments to highly privileged roles
      - Guest users holding a directory role
      - Hybrid (on-premises synced) accounts holding highly privileged roles
        (Microsoft recommends cloud-only admin accounts)
      - Disabled accounts or accounts with no sign-in for -InactiveDays still holding roles
      - Service principals holding highly privileged roles

    PIM data needs Microsoft Entra ID P2 (or Entra ID Governance). Without it, the script
    reports active assignments only and says so.

    Read-only.

.PARAMETER InactiveDays
    Days without sign-in before a role holder is flagged. Default: 45.

.PARAMETER OutputDirectory
    Folder for the CSV reports. Default: .\Reports

.EXAMPLE
    .\Get-EntraPrivilegedRoleReport.ps1 | Where-Object Findings | Format-Table Role, Principal, AssignmentType, Findings

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : Microsoft.Graph.Authentication
    Scopes      : RoleManagement.Read.Directory, Directory.Read.All, AuditLog.Read.All
    Entra role  : Global Reader or Privileged Role Administrator (read)
    Licence     : P1 for sign-in activity, P2 for PIM data.

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 45,

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

Connect-GraphIfNeeded -Scopes 'RoleManagement.Read.Directory', 'Directory.Read.All', 'AuditLog.Read.All' | Out-Null

$base = 'https://graph.microsoft.com/v1.0'
$globalAdminId = '62e90394-69f5-4237-9190-012177145e10'

# Built-in role template IDs considered Tier 0 / highly privileged
$highlyPrivileged = @(
    '62e90394-69f5-4237-9190-012177145e10'  # Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814'  # Privileged Role Administrator
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'  # Privileged Authentication Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d'  # Security Administrator
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'  # Conditional Access Administrator
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'  # Application Administrator
    '158c047a-c907-4556-b7ef-446551a6b5f7'  # Cloud Application Administrator
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'  # Hybrid Identity Administrator
    'fe930be7-5e62-47db-91af-98c3a49a38b1'  # User Administrator
    'c4e39bd9-1100-46d3-8c65-fb160da0071f'  # Authentication Administrator
    '29232cdf-9323-42fd-ade2-1d097af3e4de'  # Exchange Administrator
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'  # SharePoint Administrator
    '3a2c62db-5318-420d-8d74-23affee5d9d5'  # Intune Administrator
)

Write-Verbose 'Reading role definitions...'
$roleNames = @{}
foreach ($d in (Invoke-GraphPaged -Uri "$base/roleManagement/directory/roleDefinitions?`$select=id,displayName,templateId")) {
    $roleNames[$d.id] = $d.displayName
    if ($d.templateId) { $roleNames[$d.templateId] = $d.displayName }
}

Write-Verbose 'Reading active role assignments...'
$active = Invoke-GraphPaged -Uri "$base/roleManagement/directory/roleAssignments?`$expand=principal"

# Distinguish permanent vs PIM-activated, and read eligible assignments (P2)
$pimAvailable = $true
$activatedKeys = @{}
$eligible = @()
try {
    foreach ($inst in (Invoke-GraphPaged -Uri "$base/roleManagement/directory/roleAssignmentScheduleInstances")) {
        if ($inst.assignmentType -eq 'Activated') {
            $activatedKeys["$($inst.principalId)|$($inst.roleDefinitionId)"] = $inst.endDateTime
        }
    }
    $eligible = Invoke-GraphPaged -Uri "$base/roleManagement/directory/roleEligibilitySchedules?`$expand=principal"
}
catch {
    $pimAvailable = $false
    Write-Warning 'PIM data not available (requires Entra ID P2 / Governance and RoleManagement.Read.Directory). Reporting active assignments only.'
}

# User details (sync state, enabled, last sign-in) for every user principal
$userCache = @{}
function Get-UserDetail {
    param([string]$Id)
    if ($userCache.ContainsKey($Id)) { return $userCache[$Id] }
    $select = 'id,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,signInActivity'
    try {
        $u = Invoke-MgGraphRequest -Method GET -Uri "$base/users/$Id`?`$select=$select" -OutputType PSObject
    }
    catch {
        # signInActivity needs P1 + AuditLog.Read.All; retry without it
        $u = Invoke-MgGraphRequest -Method GET -Uri "$base/users/$Id`?`$select=$($select -replace ',signInActivity')" -OutputType PSObject
    }
    $userCache[$Id] = $u
    $u
}

$now = Get-Date
$inactiveCutoff = $now.AddDays(-$InactiveDays)

$entries = @()
$entries += $active   | ForEach-Object { [PSCustomObject]@{ Item = $_; Kind = 'Active' } }
$entries += $eligible | ForEach-Object { [PSCustomObject]@{ Item = $_; Kind = 'Eligible' } }

$report = foreach ($e in $entries) {
    $a = $e.Item
    $p = $a.principal
    $principalType = if ($p) { ($p.'@odata.type' -replace '^#microsoft\.graph\.', '') } else { 'unknown' }
    $isHigh = $a.roleDefinitionId -in $highlyPrivileged

    $assignmentType = if ($e.Kind -eq 'Eligible') { 'PIM eligible' }
                      elseif ($activatedKeys.ContainsKey("$($a.principalId)|$($a.roleDefinitionId)")) { 'PIM activated' }
                      else { 'Permanent' }

    $findings = New-Object System.Collections.Generic.List[string]
    $upn = $null; $enabled = $null; $synced = $null; $lastSignIn = $null; $userType = $null

    if ($principalType -eq 'user') {
        $u = Get-UserDetail -Id $a.principalId
        $upn = $u.userPrincipalName; $enabled = $u.accountEnabled; $synced = [bool]$u.onPremisesSyncEnabled; $userType = $u.userType
        if ($u.PSObject.Properties.Name -contains 'signInActivity' -and $u.signInActivity) {
            $dates = @($u.signInActivity.lastSignInDateTime, $u.signInActivity.lastNonInteractiveSignInDateTime) |
                     Where-Object { $_ } | ForEach-Object { [datetime]$_ }
            if ($dates) { $lastSignIn = ($dates | Measure-Object -Maximum).Maximum }
        }

        if ($userType -eq 'Guest') { $findings.Add('Guest holds a directory role') }
        if ($isHigh -and $synced) { $findings.Add('Synced on-prem account in privileged role (use cloud-only admin)') }
        if ($enabled -eq $false) { $findings.Add('Disabled account still assigned') }
        elseif ($e.Kind -eq 'Active' -and $lastSignIn -and $lastSignIn -lt $inactiveCutoff) { $findings.Add("No sign-in for $InactiveDays+ days") }
    }
    elseif ($principalType -eq 'servicePrincipal' -and $isHigh) {
        $findings.Add('Service principal holds highly privileged role')
    }
    elseif ($principalType -eq 'group') {
        $upn = $null
    }

    if ($isHigh -and $assignmentType -eq 'Permanent' -and $pimAvailable -and $principalType -ne 'servicePrincipal') {
        $findings.Add('Standing access to highly privileged role (convert to PIM eligible)')
    }

    [PSCustomObject]@{
        Role               = $roleNames[$a.roleDefinitionId]
        HighlyPrivileged   = $isHigh
        Principal          = if ($p) { $p.displayName } else { $a.principalId }
        UserPrincipalName  = $upn
        PrincipalType      = $principalType
        AssignmentType     = $assignmentType
        Scope              = $a.directoryScopeId
        AccountEnabled     = $enabled
        OnPremisesSynced   = $synced
        LastSignIn         = $lastSignIn
        Findings           = $findings -join '; '
        PrincipalId        = $a.principalId
        RoleDefinitionId   = $a.roleDefinitionId
    }
}

# Tenant-level finding: Global Administrator count (active + eligible, unique principals)
$gaCount = @($report | Where-Object { $_.RoleDefinitionId -eq $globalAdminId } | Select-Object -ExpandProperty PrincipalId -Unique).Count
$gaStatus = if ($gaCount -lt 2) { 'Risk: fewer than 2 (no redundancy / break-glass)' }
            elseif ($gaCount -gt 4) { 'Risk: more than 4 (excess standing privilege)' }
            else { 'OK' }

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$stamp   = '{0:yyyyMMdd_HHmm}' -f $now
$csvPath = Join-Path $OutputDirectory "Entra_PrivilegedRoles_$stamp.csv"
$report | Sort-Object @{ e = 'HighlyPrivileged'; Descending = $true }, Role, Principal |
    Select-Object -Property * -ExcludeProperty PrincipalId, RoleDefinitionId |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Assignments: {0} (PIM data: {1}). Global Admins: {2} -> {3}. With findings: {4}. Report: {5}" -f
    @($report).Count, $pimAvailable, $gaCount, $gaStatus, @($report | Where-Object Findings).Count, $csvPath)
if ($gaStatus -ne 'OK') { Write-Warning "Global Administrator count is $gaCount. $gaStatus" }

$report
