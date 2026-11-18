# Threat hunting queries (KQL)

These are the Microsoft Sentinel and Defender XDR queries I wrote while studying for SC-200. Each one goes after an attack I'd actually expect to see against a hybrid Active Directory and Entra ID environment: someone spraying passwords, spamming MFA prompts, sneaking an app consent through, or hiding mail with an inbox rule.

Every file starts with a short header: what it looks for, the MITRE ATT&CK technique, which table it needs, how to tune it, and what to do if it fires. I checked each query with the Kusto parser against the columns of the tables it uses.

## The queries

| Query | MITRE ATT&CK | Table(s) | What it catches |
|---|---|---|---|
| [`Identity/password_spray_detection.kql`](Identity/password_spray_detection.kql) | T1110.003 | SigninLogs | One IP failing against lots of accounts, and whether any of those accounts then got in from the same IP |
| [`Identity/mfa_fatigue_detection.kql`](Identity/mfa_fatigue_detection.kql) | T1621 | SigninLogs | A pile of denied or ignored MFA prompts, and whether the user finally tapped "Approve" |
| [`Identity/device_code_and_ropc_signins.kql`](Identity/device_code_and_ropc_signins.kql) | T1528, T1110 | SigninLogs | Sign-ins using the device code flow (used in device code phishing) or ROPC password grant, with first-time users highlighted |
| [`Identity/legacy_authentication_signins.kql`](Identity/legacy_authentication_signins.kql) | T1078.004 | SigninLogs | Sign-ins over old protocols that can't do MFA (IMAP, POP, SMTP AUTH, ActiveSync basic) |
| [`Identity/sign_in_from_new_country.kql`](Identity/sign_in_from_new_country.kql) | T1078.004 | SigninLogs | A successful sign-in from a country that user hasn't signed in from in the last 30 days |
| [`Identity/privileged_role_assignment.kql`](Identity/privileged_role_assignment.kql) | T1098.003 | AuditLogs | Someone being given an Entra ID admin role, especially Global Admin or a change made outside PIM |
| [`Identity/oauth_consent_grant.kql`](Identity/oauth_consent_grant.kql) | T1528 | AuditLogs | A user or admin granting an app permission to read mail, files or the directory |
| [`Identity/mfa_method_registered_from_new_ip.kql`](Identity/mfa_method_registered_from_new_ip.kql) | T1098.005 | AuditLogs, SigninLogs | A new MFA method registered from an IP that user has never signed in from |
| [`Endpoint/kerberoasting_rc4_service_tickets.kql`](Endpoint/kerberoasting_rc4_service_tickets.kql) | T1558.003 | SecurityEvent (4769) | One account asking for a burst of RC4 service tickets, the usual Kerberoasting pattern |
| [`Endpoint/ad_brute_force_and_lockouts.kql`](Endpoint/ad_brute_force_and_lockouts.kql) | T1110 | SecurityEvent (4625, 4740) | On-prem brute force or spraying, and the lockouts it caused |
| [`Endpoint/ad_privileged_group_change.kql`](Endpoint/ad_privileged_group_change.kql) | T1098 | SecurityEvent (4728, 4732, 4756) | Someone being added to Domain Admins or another high-privilege group |
| [`Email-and-Collaboration/inbox_rule_forwarding_or_hiding.kql`](Email-and-Collaboration/inbox_rule_forwarding_or_hiding.kql) | T1114.003, T1564.008 | OfficeActivity | New inbox rules or mailbox settings that forward, redirect or hide mail |
| [`Email-and-Collaboration/mass_file_download.kql`](Email-and-Collaboration/mass_file_download.kql) | T1530, T1567 | OfficeActivity | Someone downloading far more from SharePoint or OneDrive than they normally do |

### Defender XDR advanced hunting

These three run in the Defender portal (Hunting > Advanced hunting) rather than Sentinel, or from PowerShell with `Defender-XDR\Invoke-DefenderAdvancedHunting.ps1`.

| Query | MITRE ATT&CK | Table(s) | What it catches |
|---|---|---|---|
| [`Defender-XDR/suspicious_powershell_download.kql`](Defender-XDR/suspicious_powershell_download.kql) | T1059.001, T1105 | DeviceProcessEvents | PowerShell pulling code from the internet or running an encoded command, especially when Word, Outlook or a browser started it |
| [`Defender-XDR/user_clicked_malicious_url.kql`](Defender-XDR/user_clicked_malicious_url.kql) | T1566.002, T1204.001 | EmailEvents, UrlClickEvents | Who actually clicked a link in an email flagged as phishing or malware |
| [`Defender-XDR/dlp_alerts_by_user.kql`](Defender-XDR/dlp_alerts_by_user.kql) | T1567, T1048 | AlertInfo, AlertEvidence | People who keep tripping Purview DLP across email, SharePoint and endpoint |

## What you need connected

| Table | How it gets into Sentinel |
|---|---|
| `SigninLogs`, `AuditLogs` | The Microsoft Entra ID data connector (needs Entra ID P1 or P2) |
| `SecurityEvent` | Windows Security Events via the Azure Monitor Agent, with a data collection rule on your domain controllers |
| `OfficeActivity` | The Microsoft 365 connector, with Exchange and SharePoint turned on |
| Defender XDR tables (`Device*`, `Email*`, `UrlClickEvents`, `Alert*`) | Available in Defender advanced hunting with the matching Defender licence; can also be streamed to Sentinel with the Microsoft Defender XDR connector |

## How I use them

A good query is a quiet one. Tune until it only speaks up when it matters.

1. **Hunt.** Paste a query into Sentinel > Logs, change the `let` values at the top to suit your environment, and run it.
2. **Alert.** Once a query is quiet enough, turn it into a scheduled analytics rule and map the account and IP so incidents link up.
3. **Respond.** Each header points to the matching script in this repo, for example `Invoke-CompromisedAccountResponse.ps1` for a suspected account takeover.

## How the queries pair with the scripts

The PowerShell scripts show where the weak spots are today. The queries watch for someone trying to use them.

| The script finds... | ...and the query watches for |
|---|---|
| Kerberoastable accounts (`Get-ADSecurityPostureSummary.ps1`) | Someone Kerberoasting them (`kerberoasting_rc4_service_tickets.kql`) |
| Who's in Domain Admins (`Get-ADPrivilegedGroupMember.ps1`) | Someone new being added (`ad_privileged_group_change.kql`) |
| Who holds Entra ID admin roles (`Get-EntraPrivilegedRoleReport.ps1`) | New role assignments (`privileged_role_assignment.kql`) |
| Apps with risky permissions (`Get-EntraRiskyAppPermission.ps1`) | New risky consents (`oauth_consent_grant.kql`) |
| Existing mail forwarding (`Get-MailboxForwardingAudit.ps1`) | New forwarding or hiding rules (`inbox_rule_forwarding_or_hiding.kql`) |
| Users with weak MFA (`Get-EntraMfaStrengthReport.ps1`) | MFA push bombing (`mfa_fatigue_detection.kql`) |
