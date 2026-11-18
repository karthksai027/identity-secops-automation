<#
.SYNOPSIS
    Incident response playbook for a suspected compromised Entra ID account: collect evidence, then (optionally) contain.

.DESCRIPTION
    Implements the first hour of a Microsoft-aligned compromised-account response
    (SC-200: "respond to identity threats"). Safe by default: without switches it only
    collects evidence.

    Evidence (always, read-only) - saved as JSON in a case folder:
      - User profile, sync state, assigned roles
      - Sign-in logs for the last -LookbackDays (IP, location, app, client, result, risk)
      - Registered authentication methods (look for methods the user did not add)
      - Directory audit events initiated by the user (app consents, MFA changes, role changes)
      - Identity Protection risk state (Entra ID P2)
      - Optional: mailbox forwarding and inbox rules (-IncludeMailbox)

    Containment (only with -Contain, each step asks for confirmation unless -Confirm:$false):
      1. Block sign-in (accountEnabled = false). For synced accounts the on-premises AD account
         is disabled instead when -DisableOnPremises is used, because cloud changes are
         overwritten by sync.
      2. Revoke all refresh tokens and session cookies (revokeSignInSessions).
      3. Confirm the user as compromised in Identity Protection (-ConfirmCompromised, P2),
         which raises user risk to High and feeds risk-based Conditional Access.
      4. Disable forwarding inbox rules and remove mailbox forwarding (-RemediateMailbox).

    After the script: reset the password (twice for synced accounts), review and remove
    unknown MFA methods, review app consents from the audit evidence, and hunt for the
    attacker IPs across the tenant with the KQL in SC-200-Threat-Hunting.

.PARAMETER UserPrincipalName
    The suspected compromised account.

.PARAMETER LookbackDays
    Days of sign-in and audit history to collect. Default: 7 (max 30 for sign-in logs).

.PARAMETER Contain
    Perform containment steps 1 and 2.

.PARAMETER ConfirmCompromised
    Also mark the user as confirmed compromised in Identity Protection.

.PARAMETER DisableOnPremises
    For synced users, disable the on-premises AD account (requires the ActiveDirectory module).

.PARAMETER IncludeMailbox
    Collect mailbox forwarding and inbox rules (requires ExchangeOnlineManagement).

.PARAMETER RemediateMailbox
    Disable forwarding/redirect inbox rules and clear mailbox forwarding. Implies -IncludeMailbox.

.PARAMETER CaseRoot
    Parent folder for the evidence case folder. Default: .\IR-Cases

.EXAMPLE
    .\Invoke-CompromisedAccountResponse.ps1 -UserPrincipalName jdoe@contoso.com -IncludeMailbox
    Evidence collection only.

.EXAMPLE
    .\Invoke-CompromisedAccountResponse.ps1 -UserPrincipalName jdoe@contoso.com -Contain -ConfirmCompromised -RemediateMailbox -WhatIf
    Shows every containment action without making changes.

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : Microsoft.Graph.Authentication (+ ExchangeOnlineManagement, ActiveDirectory optional)
    Scopes      : User.ReadWrite.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All,
                  RoleManagement.Read.Directory, IdentityRiskyUser.ReadWrite.All
    Entra role  : Evidence - Security Reader / Global Reader.
                  Containment - User Administrator (Privileged Authentication Administrator if the
                  target holds an admin role) and Security Operator for Identity Protection.

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[^@\s]+@[^@\s]+$')]
    [string]$UserPrincipalName,

    [ValidateRange(1, 30)]
    [int]$LookbackDays = 7,

    [switch]$Contain,
    [switch]$ConfirmCompromised,
    [switch]$DisableOnPremises,
    [switch]$IncludeMailbox,
    [switch]$RemediateMailbox,

    [string]$CaseRoot = (Join-Path -Path (Get-Location) -ChildPath 'IR-Cases')
)

$ErrorActionPreference = 'Stop'
if ($RemediateMailbox) { $IncludeMailbox = $true }

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
    param([Parameter(Mandatory)][string]$Uri, [int]$MaxItems = 5000)
    $items = New-Object System.Collections.Generic.List[object]
    while ($Uri -and $items.Count -lt $MaxItems) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        if ($resp.PSObject.Properties.Name -contains 'value') { foreach ($v in $resp.value) { $items.Add($v) } }
        else { $items.Add($resp) }
        $Uri = $resp.'@odata.nextLink'
    }
    , $items
}

$actionLog = New-Object System.Collections.Generic.List[object]
function Write-Action {
    param([string]$Step, [string]$Result, [string]$Detail = '')
    $entry = [PSCustomObject]@{ Time = (Get-Date).ToString('s'); Step = $Step; Result = $Result; Detail = $Detail }
    $actionLog.Add($entry)
    Write-Verbose "$($entry.Time) [$Result] $Step $Detail"
}

function Save-Evidence {
    param([string]$Name, $Data)
    # Evidence is always written, even under -WhatIf
    $Data | ConvertTo-Json -Depth 15 | Set-Content -Path (Join-Path $caseDir "$Name.json") -Encoding UTF8 -WhatIf:$false
}
#endregion

$scopes = @('User.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory')
if ($Contain) { $scopes += 'User.ReadWrite.All' }
if ($ConfirmCompromised) { $scopes += 'IdentityRiskyUser.ReadWrite.All' } else { $scopes += 'IdentityRiskyUser.Read.All' }
Connect-GraphIfNeeded -Scopes $scopes | Out-Null

$base    = 'https://graph.microsoft.com/v1.0'
$since   = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
$caseDir = Join-Path $CaseRoot ("{0:yyyyMMdd_HHmm}_{1}" -f (Get-Date), ($UserPrincipalName -replace '[^A-Za-z0-9]', '_'))
New-Item -Path $caseDir -ItemType Directory -Force -WhatIf:$false | Out-Null

# ================= EVIDENCE =================
$user = Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri ("$base/users/$UserPrincipalName`?`$select=" +
    'id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesDomainName,createdDateTime,lastPasswordChangeDateTime,signInActivity')
Save-Evidence 'user' $user
Write-Action 'Collect user profile' 'OK' "Synced=$([bool]$user.onPremisesSyncEnabled) Enabled=$($user.accountEnabled)"

try {
    $roles = Invoke-GraphPaged -Uri "$base/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($user.id)'&`$expand=roleDefinition"
    Save-Evidence 'directoryRoles' $roles
    $roleNames = @($roles | ForEach-Object { $_.roleDefinition.displayName })
    Write-Action 'Collect directory roles' 'OK' $(if ($roleNames) { 'PRIVILEGED: ' + ($roleNames -join ', ') } else { 'None' })
}
catch { Write-Action 'Collect directory roles' 'Failed' $_.Exception.Message }

try {
    $signIns = Invoke-GraphPaged -Uri "$base/auditLogs/signIns?`$filter=userId eq '$($user.id)' and createdDateTime ge $since&`$top=500"
    Save-Evidence 'signIns' $signIns
    $summary = $signIns | ForEach-Object {
        [PSCustomObject]@{
            Time       = $_.createdDateTime
            IP         = $_.ipAddress
            Country    = $_.location.countryOrRegion
            City       = $_.location.city
            App        = $_.appDisplayName
            ClientApp  = $_.clientAppUsed
            Result     = if ($_.status.errorCode -eq 0) { 'Success' } else { "Failure $($_.status.errorCode)" }
            RiskLevel  = $_.riskLevelDuringSignIn
            MfaDetail  = $_.mfaDetail.authMethod
            Device     = $_.deviceDetail.displayName
            OS         = $_.deviceDetail.operatingSystem
        }
    }
    $summary | Export-Csv -Path (Join-Path $caseDir 'signIns_summary.csv') -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    $ips = @($summary | Where-Object Result -eq 'Success' | Group-Object IP, Country | Sort-Object Count -Descending |
             ForEach-Object { "$($_.Name) ($($_.Count))" })
    Write-Action 'Collect sign-in logs' 'OK' ("{0} sign-ins. Successful from: {1}" -f $signIns.Count, ($ips -join '; '))
}
catch { Write-Action 'Collect sign-in logs' 'Failed' $_.Exception.Message }

try {
    $methods = Invoke-GraphPaged -Uri "$base/users/$($user.id)/authentication/methods"
    Save-Evidence 'authenticationMethods' $methods
    Write-Action 'Collect authentication methods' 'OK' (($methods | ForEach-Object { $_.'@odata.type' -replace '^#microsoft\.graph\.' }) -join ', ')
}
catch { Write-Action 'Collect authentication methods' 'Failed' $_.Exception.Message }

try {
    $audits = Invoke-GraphPaged -Uri "$base/auditLogs/directoryAudits?`$filter=initiatedBy/user/id eq '$($user.id)' and activityDateTime ge $since"
    Save-Evidence 'directoryAudits' $audits
    $notable = @($audits | Where-Object { $_.activityDisplayName -match 'Consent|security info|authentication method|role|application|service principal|password' } |
                 ForEach-Object { "$($_.activityDateTime) $($_.activityDisplayName)" })
    Write-Action 'Collect directory audit events' 'OK' ("{0} events; notable: {1}" -f $audits.Count, ($notable -join ' | '))
}
catch { Write-Action 'Collect directory audit events' 'Failed' $_.Exception.Message }

try {
    $risk = Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri "$base/identityProtection/riskyUsers/$($user.id)"
    Save-Evidence 'riskState' $risk
    Write-Action 'Collect Identity Protection risk' 'OK' "riskLevel=$($risk.riskLevel) riskState=$($risk.riskState)"
}
catch { Write-Action 'Collect Identity Protection risk' 'Skipped' 'Not available (no risk record, or no Entra ID P2)' }

$forwardRules = @()
if ($IncludeMailbox) {
    try {
        if (-not (Get-Module -ListAvailable ExchangeOnlineManagement)) { throw 'ExchangeOnlineManagement module not installed.' }
        if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object State -eq 'Connected')) {
            Connect-ExchangeOnline -ShowBanner:$false
        }
        $mbx   = Get-EXOMailbox -Identity $UserPrincipalName -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
        $rules = @(Get-InboxRule -Mailbox $UserPrincipalName)
        Save-Evidence 'mailboxForwarding' ($mbx | Select-Object UserPrincipalName, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward)
        Save-Evidence 'inboxRules' ($rules | Select-Object Name, Enabled, Priority, Description, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, MoveToFolder, MarkAsRead, SubjectContainsWords, SubjectOrBodyContainsWords, Identity)
        $forwardRules = @($rules | Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo })
        Write-Action 'Collect mailbox forwarding and rules' 'OK' ("Mailbox forwarding: {0}. Rules: {1} (forward/redirect: {2})" -f
            $(if ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) { "$($mbx.ForwardingSmtpAddress)$($mbx.ForwardingAddress)" } else { 'none' }), $rules.Count, $forwardRules.Count)
    }
    catch { Write-Action 'Collect mailbox forwarding and rules' 'Failed' $_.Exception.Message }
}

# ================= CONTAINMENT =================
if ($Contain) {
    if ($user.onPremisesSyncEnabled) {
        if ($DisableOnPremises) {
            if ($PSCmdlet.ShouldProcess("$($user.onPremisesDomainName)\$($user.onPremisesSamAccountName)", 'Disable on-premises AD account')) {
                try {
                    Import-Module ActiveDirectory
                    Disable-ADAccount -Identity $user.onPremisesSamAccountName -Server $user.onPremisesDomainName -Confirm:$false
                    Write-Action 'Disable on-premises AD account' 'Done' 'Change reaches Entra ID at next sync cycle (Start-ADSyncSyncCycle -PolicyType Delta to speed up).'
                }
                catch { Write-Action 'Disable on-premises AD account' 'Failed' $_.Exception.Message }
            }
        }
        else {
            Write-Action 'Block sign-in' 'Skipped' 'Synced account: cloud change would be overwritten. Re-run with -DisableOnPremises or disable in AD.'
        }
    }
    elseif ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Block sign-in (accountEnabled = false)')) {
        try {
            Invoke-MgGraphRequest -Method PATCH -Uri "$base/users/$($user.id)" -Body (@{ accountEnabled = $false } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
            Write-Action 'Block sign-in' 'Done'
        }
        catch { Write-Action 'Block sign-in' 'Failed' $_.Exception.Message }
    }

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, 'Revoke all refresh tokens and sessions')) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri "$base/users/$($user.id)/revokeSignInSessions" | Out-Null
            Write-Action 'Revoke sessions' 'Done' 'Access tokens already issued stay valid until expiry (up to ~1 hour) unless CAE applies.'
        }
        catch { Write-Action 'Revoke sessions' 'Failed' $_.Exception.Message }
    }
}

if ($ConfirmCompromised -and $PSCmdlet.ShouldProcess($UserPrincipalName, 'Confirm user compromised in Identity Protection')) {
    try {
        Invoke-MgGraphRequest -Method POST -Uri "$base/identityProtection/riskyUsers/confirmCompromised" `
            -Body (@{ userIds = @($user.id) } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
        Write-Action 'Confirm compromised (Identity Protection)' 'Done' 'User risk set to High.'
    }
    catch { Write-Action 'Confirm compromised (Identity Protection)' 'Failed' $_.Exception.Message }
}

if ($RemediateMailbox) {
    foreach ($r in $forwardRules) {
        if ($PSCmdlet.ShouldProcess("$UserPrincipalName rule '$($r.Name)'", 'Disable inbox rule')) {
            try { Disable-InboxRule -Identity $r.Identity -Confirm:$false | Out-Null; Write-Action "Disable inbox rule '$($r.Name)'" 'Done' }
            catch { Write-Action "Disable inbox rule '$($r.Name)'" 'Failed' $_.Exception.Message }
        }
    }
    if ($mbx -and ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) -and
        $PSCmdlet.ShouldProcess($UserPrincipalName, 'Remove mailbox forwarding')) {
        try {
            Set-Mailbox -Identity $UserPrincipalName -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false -Confirm:$false | Out-Null
            Write-Action 'Remove mailbox forwarding' 'Done'
        }
        catch { Write-Action 'Remove mailbox forwarding' 'Failed' $_.Exception.Message }
    }
}

# ================= NEXT STEPS =================
$next = @"
Case: $UserPrincipalName   Folder: $caseDir

Next steps (manual):
 1. Reset the password (for synced users reset in AD; consider resetting twice).
 2. Review authenticationMethods.json - delete any MFA method the user did not register.
 3. Review directoryAudits.json for app consents, new MFA methods, role or policy changes made by the account.
 4. Review signIns_summary.csv - block attacker IPs with a Named Location + Conditional Access, then hunt for
    the same IPs across all users (SC-200-Threat-Hunting\Identity\*.kql).
 5. Check the user's devices in Defender for Endpoint / Intune for token theft or malware.
 6. Re-enable the account only after the user re-registers MFA (issue a Temporary Access Pass).
 7. Document timeline and root cause; feed IOCs to Sentinel threat intelligence.
"@
Set-Content -Path (Join-Path $caseDir 'NEXT_STEPS.txt') -Value $next -Encoding UTF8 -WhatIf:$false
$actionLog | Export-Csv -Path (Join-Path $caseDir 'action_log.csv') -NoTypeInformation -Encoding UTF8 -WhatIf:$false

Write-Verbose $next
$actionLog
