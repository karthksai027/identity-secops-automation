<#
.SYNOPSIS
    Detects external mail forwarding and suspicious inbox rules in Exchange Online - the most common business email compromise (BEC) persistence technique.

.DESCRIPTION
    After an account takeover, attackers typically create an inbox rule that forwards,
    redirects or hides mail (for example invoices or replies from the finance team) so they
    can continue a fraud after the password is reset. This script checks:

      Mailbox level : ForwardingSmtpAddress / ForwardingAddress pointing outside the
                      organisation's accepted domains
      Inbox rules   : ForwardTo, ForwardAsAttachmentTo, RedirectTo with external recipients
                      Rules that delete mail or move it to rarely viewed folders
                      (RSS Feeds, RSS Subscriptions, Conversation History, Archive, Junk)
                      Rules with very short or symbol-only names (".", "..", "a")
      Tenant level  : Outbound anti-spam auto-forwarding mode, remote domain auto-forward

    Read-only. Remediation (Disable-InboxRule, Set-Mailbox -ForwardingSmtpAddress $null)
    should follow your incident response process.

.PARAMETER Identity
    Optional list of mailboxes to check. Default: all user and shared mailboxes.

.PARAMETER SkipInboxRules
    Check mailbox-level forwarding only (much faster on large tenants).

.PARAMETER OutputDirectory
    Folder for the CSV reports. Default: .\Reports

.EXAMPLE
    .\Get-MailboxForwardingAudit.ps1 -Verbose

.EXAMPLE
    .\Get-MailboxForwardingAudit.ps1 -Identity user1@contoso.com, user2@contoso.com

.NOTES
    Module      : ExchangeOnlineManagement (v3)
    Role        : Global Reader, Security Reader or Exchange View-Only Organization Management
#>

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [string[]]$Identity,
    [switch]$SkipInboxRules,
    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object State -eq 'Connected')) {
    Connect-ExchangeOnline -ShowBanner:$false
}

$acceptedDomains = @(Get-AcceptedDomain | Select-Object -ExpandProperty DomainName)
Write-Verbose "Accepted domains: $($acceptedDomains -join ', ')"

function Test-External {
    param([string]$Address)
    if (-not $Address) { return $false }
    $domain = ($Address -replace '^smtp:', '').Split('@')[-1].Trim().TrimEnd(']', '>').ToLowerInvariant()
    -not ($acceptedDomains | Where-Object { $domain -eq $_.ToLowerInvariant() -or $domain.EndsWith('.' + $_.ToLowerInvariant()) })
}

function Get-SmtpFromRuleRecipient {
    param([string]$Value)
    # Rule recipients look like: "Name" [SMTP:user@domain.com]  or  [EX:/o=ExchangeLabs/...]
    if ($Value -match 'SMTP:([^\]\s]+)') { return $Matches[1] }
    if ($Value -match '^[^@\s]+@[^@\s]+$') { return $Value }
    $null
}

$hiddenFolders = 'RSS Feeds|RSS Subscriptions|Conversation History|Archive|Junk Email|Deleted Items|Notes'

# ---- Mailboxes ----
$mbxParams = @{ Properties = 'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward' }
if ($Identity) {
    $mailboxes = foreach ($id in $Identity) { Get-EXOMailbox -Identity $id @mbxParams }
}
else {
    $mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox @mbxParams
}
$mailboxes = @($mailboxes)
Write-Verbose "Mailboxes: $($mailboxes.Count)"

$findings = New-Object System.Collections.Generic.List[object]
$i = 0

foreach ($mbx in $mailboxes) {
    $i++
    Write-Progress -Activity 'Mailbox forwarding audit' -Status $mbx.UserPrincipalName -PercentComplete (($i / [math]::Max($mailboxes.Count, 1)) * 100)

    # Mailbox-level forwarding
    if ($mbx.ForwardingSmtpAddress) {
        $addr = "$($mbx.ForwardingSmtpAddress)" -replace '^smtp:', ''
        $findings.Add([PSCustomObject]@{
            Mailbox = $mbx.UserPrincipalName; Source = 'Mailbox forwarding (SMTP)'; RuleName = ''; Enabled = $true
            Target = $addr; External = Test-External $addr; Action = if ($mbx.DeliverToMailboxAndForward) { 'Forward and keep copy' } else { 'Forward only (no copy kept)' }
            Severity = if (Test-External $addr) { 'High' } else { 'Low' }
        })
    }
    if ($mbx.ForwardingAddress) {
        $recipient = Get-EXORecipient -Identity "$($mbx.ForwardingAddress)" -ErrorAction SilentlyContinue
        $addr = if ($recipient) { "$($recipient.PrimarySmtpAddress)" } else { "$($mbx.ForwardingAddress)" }
        $ext = Test-External $addr
        $findings.Add([PSCustomObject]@{
            Mailbox = $mbx.UserPrincipalName; Source = 'Mailbox forwarding (recipient object)'; RuleName = ''; Enabled = $true
            Target = $addr; External = $ext; Action = if ($mbx.DeliverToMailboxAndForward) { 'Forward and keep copy' } else { 'Forward only (no copy kept)' }
            Severity = if ($ext) { 'High' } else { 'Low' }
        })
    }

    if ($SkipInboxRules) { continue }

    # Inbox rules
    try {
        $rules = @(Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction Stop)
    }
    catch {
        Write-Warning "Could not read inbox rules for $($mbx.UserPrincipalName): $($_.Exception.Message)"
        continue
    }

    foreach ($rule in $rules) {
        $targets = @($rule.ForwardTo) + @($rule.ForwardAsAttachmentTo) + @($rule.RedirectTo) | Where-Object { $_ }
        foreach ($t in $targets) {
            $addr = Get-SmtpFromRuleRecipient "$t"
            $ext  = if ($addr) { Test-External $addr } else { $false }
            $findings.Add([PSCustomObject]@{
                Mailbox = $mbx.UserPrincipalName; Source = 'Inbox rule'; RuleName = $rule.Name; Enabled = $rule.Enabled
                Target = if ($addr) { $addr } else { "$t" }; External = $ext; Action = 'Forward / redirect'
                Severity = if ($ext) { 'High' } else { 'Low' }
            })
        }

        $suspicious = New-Object System.Collections.Generic.List[string]
        if ($rule.DeleteMessage -or $rule.SoftDeleteMessage) { $suspicious.Add('Deletes messages') }
        if ($rule.MoveToFolder -and "$($rule.MoveToFolder)" -match $hiddenFolders) { $suspicious.Add("Moves to '$($rule.MoveToFolder)'") }
        if ($rule.MarkAsRead -and ($rule.DeleteMessage -or $rule.MoveToFolder)) { $suspicious.Add('Marks as read') }
        if ($rule.Name -match '^[\W_]{1,3}$|^.{1,2}$') { $suspicious.Add('Obscure rule name') }

        if ($suspicious.Count -gt 0) {
            $keywords = @($rule.SubjectContainsWords) + @($rule.SubjectOrBodyContainsWords) + @($rule.BodyContainsWords) | Where-Object { $_ }
            $findings.Add([PSCustomObject]@{
                Mailbox = $mbx.UserPrincipalName; Source = 'Inbox rule (hiding)'; RuleName = $rule.Name; Enabled = $rule.Enabled
                Target = if ($keywords) { 'Keywords: ' + ($keywords -join ', ') } else { 'All matching mail' }
                External = $false; Action = $suspicious -join '; '
                Severity = if ($keywords -match 'invoice|payment|bank|wire|transfer|password|security|phish|hack') { 'High' } else { 'Medium' }
            })
        }
    }
}
Write-Progress -Activity 'Mailbox forwarding audit' -Completed

# ---- Tenant settings ----
$tenant = New-Object System.Collections.Generic.List[object]
foreach ($p in (Get-HostedOutboundSpamFilterPolicy)) {
    $tenant.Add([PSCustomObject]@{
        Setting = "Outbound spam policy '$($p.Name)' AutoForwardingMode"; Value = $p.AutoForwardingMode
        Status  = if ($p.AutoForwardingMode -eq 'On') { 'Risk: external auto-forwarding allowed' } else { 'OK' }
    })
}
foreach ($rd in (Get-RemoteDomain)) {
    $tenant.Add([PSCustomObject]@{
        Setting = "Remote domain '$($rd.DomainName)' AutoForwardEnabled"; Value = $rd.AutoForwardEnabled
        Status  = if ($rd.AutoForwardEnabled -and $rd.DomainName -eq '*') { 'Review: auto-forward allowed to all domains' } else { 'OK' }
    })
}

# ---- Output ----
if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$stamp = '{0:yyyyMMdd_HHmm}' -f (Get-Date)
$findings | Sort-Object @{ e = { switch ($_.Severity) { 'High' { 0 } 'Medium' { 1 } default { 2 } } } }, Mailbox |
    Export-Csv -Path (Join-Path $OutputDirectory "EXO_ForwardingAudit_$stamp.csv") -NoTypeInformation -Encoding UTF8
$tenant | Export-Csv -Path (Join-Path $OutputDirectory "EXO_ForwardingTenantSettings_$stamp.csv") -NoTypeInformation -Encoding UTF8

Write-Verbose ("Mailboxes: {0}. Findings: {1} (High {2}). Reports in {3}" -f $mailboxes.Count, $findings.Count,
    @($findings | Where-Object Severity -eq 'High').Count, $OutputDirectory)
$findings
