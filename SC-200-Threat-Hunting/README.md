# SC-200 Threat Hunting Library (KQL)

Hunting queries for **Microsoft Sentinel** (Log Analytics) covering the identity, endpoint and collaboration attacks that SC-200 focuses on. Each query has a header with the MITRE ATT&CK technique, the data source, tuning notes and the response action. Every query was checked with the Kusto language parser against the table schemas it uses.

## Queries

| Query | MITRE ATT&CK | Table(s) | What it finds |
|---|---|---|---|
| [`Identity/password_spray_detection.kql`](Identity/password_spray_detection.kql) | T1110.003 | SigninLogs | One IP failing against many accounts, plus any account that then signed in successfully from it |
| [`Identity/mfa_fatigue_detection.kql`](Identity/mfa_fatigue_detection.kql) | T1621 | SigninLogs | Bursts of denied or unanswered MFA prompts, and whether the user approved one afterwards |
| [`Identity/legacy_authentication_signins.kql`](Identity/legacy_authentication_signins.kql) | T1078.004 | SigninLogs | Sign-ins over protocols that cannot do MFA (IMAP, POP, SMTP AUTH, ActiveSync basic) |
| [`Identity/sign_in_from_new_country.kql`](Identity/sign_in_from_new_country.kql) | T1078.004 | SigninLogs | Successful sign-ins from a country not seen for that user in 30 days |
| [`Identity/privileged_role_assignment.kql`](Identity/privileged_role_assignment.kql) | T1098.003 | AuditLogs | Entra ID role assignments, highlighting Tier 0 roles and changes made outside PIM |
| [`Identity/oauth_consent_grant.kql`](Identity/oauth_consent_grant.kql) | T1528 | AuditLogs | App consents with high-risk permissions (illicit consent grant) |
| [`Identity/mfa_method_registered_from_new_ip.kql`](Identity/mfa_method_registered_from_new_ip.kql) | T1098.005 | AuditLogs, SigninLogs | Security info registered from an IP the user has never signed in from |
| [`Endpoint/kerberoasting_rc4_service_tickets.kql`](Endpoint/kerberoasting_rc4_service_tickets.kql) | T1558.003 | SecurityEvent (4769) | Bursts of RC4 service ticket requests from one account |
| [`Endpoint/ad_brute_force_and_lockouts.kql`](Endpoint/ad_brute_force_and_lockouts.kql) | T1110 | SecurityEvent (4625, 4740) | On-premises brute force vs spray, with resulting lockouts |
| [`Endpoint/ad_privileged_group_change.kql`](Endpoint/ad_privileged_group_change.kql) | T1098 | SecurityEvent (4728, 4732, 4756) | Members added to Domain Admins and other Tier 0 groups |
| [`Email-and-Collaboration/inbox_rule_forwarding_or_hiding.kql`](Email-and-Collaboration/inbox_rule_forwarding_or_hiding.kql) | T1114.003, T1564.008 | OfficeActivity | Inbox rules or mailbox settings that forward, redirect or hide mail (BEC) |
| [`Email-and-Collaboration/mass_file_download.kql`](Email-and-Collaboration/mass_file_download.kql) | T1530, T1567 | OfficeActivity | SharePoint / OneDrive download spikes compared with the user's own baseline |

## Data connectors required

| Table | How to get it into the workspace |
|---|---|
| `SigninLogs`, `AuditLogs` | Microsoft Entra ID data connector (Entra ID diagnostic settings). Needs Entra ID P1/P2. |
| `SecurityEvent` | Windows Security Events via AMA connector with a data collection rule on domain controllers ("Common" or "All Events"). |
| `OfficeActivity` | Microsoft 365 (formerly Office 365) connector with Exchange and SharePoint enabled. |

## How to use

1. **Hunt:** paste a query into Sentinel > Logs (or Hunting > New query) and adjust the `let` variables at the top.
2. **Detect:** promote stable queries to a Scheduled analytics rule. Map entities (Account = `UserPrincipalName`, IP = `IPAddress`) so incidents correlate.
3. **Respond:** each header names the matching response script in this repository, for example `M365-Security-Operations/Invoke-CompromisedAccountResponse.ps1`.

## How the scripts and queries work together

| Posture (point-in-time, PowerShell) | Detection (continuous, KQL) |
|---|---|
| `Get-ADSecurityPostureSummary.ps1` lists Kerberoastable accounts | `kerberoasting_rc4_service_tickets.kql` catches the attack against them |
| `Get-ADPrivilegedGroupMember.ps1` shows who is in Domain Admins | `ad_privileged_group_change.kql` alerts when that changes |
| `Get-EntraPrivilegedRoleReport.ps1` inventories role holders | `privileged_role_assignment.kql` alerts on new assignments |
| `Get-EntraRiskyAppPermission.ps1` inventories app permissions | `oauth_consent_grant.kql` alerts on new risky consents |
| `Get-MailboxForwardingAudit.ps1` finds existing forwarding | `inbox_rule_forwarding_or_hiding.kql` catches new rules as they are created |
| `Get-EntraMfaStrengthReport.ps1` finds weak MFA | `mfa_fatigue_detection.kql` catches push bombing |
