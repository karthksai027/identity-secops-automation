# Identity & Security Operations Automation

PowerShell and KQL for Active Directory and Microsoft Entra ID governance, identity security, and Microsoft 365 threat detection and response. Built from hands-on Windows Server 2022 and Entra ID Global Administrator work, and aligned to **SC-300 (Identity and Access Administrator)** and **SC-200 (Security Operations Analyst)**.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-5391FE?logo=powershell&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-REST-0078D4?logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Microsoft%20Sentinel-0078D4)
![Focus](https://img.shields.io/badge/Focus-SC--300%20%7C%20SC--200-2E7D32)
![Quality](https://github.com/karthksai027/identity-secops-automation/actions/workflows/quality.yml/badge.svg)

---

## Why this repository exists

Most identity incidents I have dealt with did not start with a sophisticated exploit. They started with an account nobody disabled, a password that never expired, a service account with an SPN, an app that got consent to read mail, or a user who only had SMS for MFA.

This toolkit finds those gaps **on a schedule instead of during an incident**, then detects and responds when someone tries to use them:

| Stage | What is covered | Folder |
|---|---|---|
| **Govern** | Account lifecycle, access reviews, privileged access, guest lifecycle | `Active-Directory-Governance`, `Entra-ID-Governance` |
| **Harden** | AD attack surface, tenant settings, Conditional Access coverage, MFA strength, app permissions | `Identity-Security-Posture`, `Entra-ID-Governance` |
| **Detect** | 12 KQL hunting queries mapped to MITRE ATT&CK | `SC-200-Threat-Hunting` |
| **Respond** | Compromised-account playbook, BEC mailbox forwarding audit | `M365-Security-Operations` |
| **Operate** | Endpoint asset inventory, service account credential rotation, offsite backup | `Endpoint-Asset-Inventory`, `Windows-Server-Operations`, `Cloud-Backup-Automation` |

---

## Repository structure

```text
.
├── Active-Directory-Governance/
│   ├── Get-ADInactiveUser.ps1
│   ├── Get-ADStaleDisabledUser.ps1
│   ├── Get-ADUserInventory.ps1
│   ├── Get-ADPrivilegedGroupMember.ps1
│   └── Invoke-ADGovernanceReport.ps1        # runs the AD reports + HTML summary
├── Identity-Security-Posture/
│   └── Get-ADSecurityPostureSummary.ps1
├── Entra-ID-Governance/
│   ├── Get-EntraMfaStrengthReport.ps1
│   ├── Get-EntraPrivilegedRoleReport.ps1
│   ├── Get-EntraStaleAccount.ps1
│   ├── Export-EntraConditionalAccessPolicy.ps1
│   ├── Get-EntraAppCredentialExpiry.ps1
│   ├── Get-EntraRiskyAppPermission.ps1
│   └── Test-EntraTenantSecurityBaseline.ps1
├── M365-Security-Operations/
│   ├── Get-MailboxForwardingAudit.ps1
│   └── Invoke-CompromisedAccountResponse.ps1
├── SC-200-Threat-Hunting/                   # KQL - see its own README
│   ├── Identity/                (7 queries)
│   ├── Endpoint/                (3 queries)
│   └── Email-and-Collaboration/ (2 queries)
├── Endpoint-Asset-Inventory/
│   ├── Get-ADComputerInventory.ps1
│   └── Get-ADHardwareInventory.ps1
├── Windows-Server-Operations/
│   └── Update-ScheduledTaskCredential.ps1
├── Cloud-Backup-Automation/
│   └── Sync-FolderToS3.ps1
├── docs/Unattended-Authentication.md
├── tests/Repository.Tests.ps1               # Pester quality gates
├── .github/workflows/quality.yml            # PSScriptAnalyzer + Pester on every push
├── PSScriptAnalyzerSettings.psd1
├── SECURITY.md
└── LICENSE
```

---

## Script index

### Active Directory governance and posture

| Script | Problem it solves | Requirements |
|---|---|---|
| `Get-ADInactiveUser.ps1` | Enabled accounts with no logon in N days (default 90), including accounts that never signed in. Dormant accounts are a common password-spray foothold. | `ActiveDirectory` module. Domain Users read access. |
| `Get-ADStaleDisabledUser.ps1` | Accounts disabled for 180+ days but never deprovisioned; shows how many groups they still belong to. | `ActiveDirectory` module. Read access. |
| `Get-ADUserInventory.ps1` | Baseline user export for access reviews and HR reconciliation (password age, never-expires, manager). | `ActiveDirectory` module. Read access. |
| `Get-ADPrivilegedGroupMember.ps1` | Recursive members of all Tier 0 groups (looked up by well-known SID), flagged for inactivity, old passwords, SPNs, and missing "sensitive and cannot be delegated". | `ActiveDirectory` module. Read access including the forest root domain. |
| `Get-ADSecurityPostureSummary.ps1` | 18-check AD risk scorecard: Kerberoastable and AS-REP roastable users, PASSWD_NOTREQD, unconstrained delegation, krbtgt password age, lockout policy and more. `-ExportDetails` lists the affected accounts. | `ActiveDirectory` module. Read access. |
| `Invoke-ADGovernanceReport.ps1` | Runs the five AD reports above plus computer inventory into one dated folder with an HTML summary for managers and auditors. | As above. |

### Microsoft Entra ID governance (SC-300)

| Script | Problem it solves | Graph scopes / role |
|---|---|---|
| `Get-EntraMfaStrengthReport.ps1` | Grades each user's MFA as Phishing-resistant / Strong / Weak / None and flags admins without phishing-resistant MFA. Uses the registration details report (P1/P2) or per-user methods (any licence). | `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`. Global Reader. |
| `Get-EntraPrivilegedRoleReport.ps1` | All active and PIM-eligible role assignments. Flags standing Tier 0 access, synced admin accounts, guests and service principals in roles, inactive admins, Global Admin count. | `RoleManagement.Read.Directory`, `Directory.Read.All`, `AuditLog.Read.All`. Global Reader. P2 for PIM data. |
| `Get-EntraStaleAccount.ps1` | Inactive members and guests from `signInActivity`, guests whose invitation is still pending, and stale accounts that still hold licences. | `User.Read.All`, `AuditLog.Read.All`. Global Reader. P1. |
| `Export-EntraConditionalAccessPolicy.ps1` | JSON backup of every CA policy and named location (policy as code), summary CSV, and a gap analysis against Microsoft's baseline policies. | `Policy.Read.All`. Global Reader / Security Reader. |
| `Get-EntraAppCredentialExpiry.ps1` | Expired, expiring and over-long client secrets and certificates on app registrations and enterprise apps, plus newly added credentials and ownerless apps. | `Application.Read.All`. Global Reader. |
| `Get-EntraRiskyAppPermission.ps1` | Delegated and application permissions to Microsoft Graph and Exchange Online; flags high-risk scopes, tenant-wide consent, third-party and unverified publishers (illicit consent grant review). | `Application.Read.All`, `Directory.Read.All`. Global Reader. |
| `Test-EntraTenantSecurityBaseline.ps1` | Tenant scorecard: security defaults vs CA, Global Admin count, SMS/voice enabled, FIDO2, TAP, methods migration, user consent, guest invitation and access settings, app registration, MSOnline block, sync health. | `Policy.Read.All`, `RoleManagement.Read.Directory`, `Directory.Read.All`. Global Reader. |

### Microsoft 365 security operations (SC-200)

| Script | Problem it solves | Requirements |
|---|---|---|
| `Get-MailboxForwardingAudit.ps1` | Business email compromise persistence: external mailbox forwarding, inbox rules that forward/redirect externally, and rules that hide mail (delete, move to RSS/Archive, obscure names, finance keywords). Also checks tenant auto-forwarding settings. | `ExchangeOnlineManagement` v3. Global Reader or View-Only Organization Management. |
| `Invoke-CompromisedAccountResponse.ps1` | First-hour playbook. Always collects evidence (sign-ins, MFA methods, audit events, roles, risk state, inbox rules) into a case folder. With `-Contain`: blocks sign-in (or disables the on-prem account for synced users), revokes sessions, confirms compromise in Identity Protection, removes malicious forwarding. Supports `-WhatIf`. | Graph: `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`, `User.ReadWrite.All` (containment), `IdentityRiskyUser.ReadWrite.All`. User Administrator / Security Operator. |

### Infrastructure operations

| Script | Problem it solves | Requirements |
|---|---|---|
| `Get-ADComputerInventory.ps1` | All computer objects with role (DC / server / workstation), stale flag and out-of-support OS flag. | `ActiveDirectory` module. Read access. |
| `Get-ADHardwareInventory.ps1` | Hardware asset register over WinRM/CIM for an OU or list: serial, model, CPU, RAM, disk, MACs, IP, current or last user. Unreachable machines are written to a separate CSV with the reason. | `ActiveDirectory` module. WinRM on targets. Local admin on targets. |
| `Update-ScheduledTaskCredential.ps1` | Re-registers the run-as password after a service account rotation (prompted securely), or moves the task to a gMSA so no password is stored at all. `-WhatIf` supported. | `ScheduledTasks` module. Local admin. |
| `Sync-FolderToS3.ps1` | Unattended, logged incremental backup to Amazon S3 with credential, bucket and source pre-checks, `-DryRun`, and an opt-in `-Mirror` (delete) mode that refuses to mirror an empty folder. | AWS CLI v2 with a named profile. `s3:ListBucket`, `s3:PutObject` (+ `s3:DeleteObject` for `-Mirror`). |

### KQL hunting queries

Twelve Microsoft Sentinel queries mapped to MITRE ATT&CK (password spray, MFA fatigue, legacy auth, new-country sign-in, privileged role changes, illicit consent, rogue MFA registration, Kerberoasting, AD brute force, Tier 0 group changes, BEC inbox rules, mass download). See **[SC-200-Threat-Hunting/README.md](SC-200-Threat-Hunting/README.md)**.

---

## Quick start

```powershell
git clone https://github.com/karthksai027/identity-secops-automation.git
cd identity-secops-automation

# Every script has full help
Get-Help .\Entra-ID-Governance\Get-EntraMfaStrengthReport.ps1 -Full
```

**Active Directory scripts** (domain-joined admin workstation or server):

```powershell
Install-WindowsFeature RSAT-AD-PowerShell                                                   # Windows Server
Get-WindowsCapability -Online -Name Rsat.ActiveDirectory* | Add-WindowsCapability -Online   # Windows 10/11

.\Active-Directory-Governance\Invoke-ADGovernanceReport.ps1 -Verbose
.\Identity-Security-Posture\Get-ADSecurityPostureSummary.ps1 -ExportDetails
```

**Entra ID scripts** only need the Graph authentication module. They call the Graph REST API directly, so there is no dependency on the large Graph SDK sub-modules:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

.\Entra-ID-Governance\Test-EntraTenantSecurityBaseline.ps1 | Format-Table Area, Check, Value, Status
.\Entra-ID-Governance\Get-EntraPrivilegedRoleReport.ps1 | Where-Object Findings
```

Each script signs you in with only the scopes it needs, or reuses your existing `Connect-MgGraph` session and warns if a scope is missing.

**Exchange Online scripts:**

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
.\M365-Security-Operations\Get-MailboxForwardingAudit.ps1
```

**Incident response (always rehearse with -WhatIf):**

```powershell
.\M365-Security-Operations\Invoke-CompromisedAccountResponse.ps1 -UserPrincipalName jdoe@contoso.com -IncludeMailbox
.\M365-Security-Operations\Invoke-CompromisedAccountResponse.ps1 -UserPrincipalName jdoe@contoso.com -Contain -ConfirmCompromised -RemediateMailbox -WhatIf
```

All reports are written to `.\Reports` (or `-OutputDirectory`) as timestamped CSV files and returned as objects, so you can pipe them into `Where-Object`, `Export-Excel` or Sentinel watchlists.

For scheduled runs, see **[docs/Unattended-Authentication.md](docs/Unattended-Authentication.md)** (certificate-based app auth, managed identity, gMSA).

---

## Engineering standards

- **Read-only by default.** Only three scripts can change anything. Each needs an explicit switch and supports `-WhatIf` (or `-DryRun` for the S3 sync).
- **Least privilege.** Every script documents the minimum Graph scopes and directory roles. None needs Global Administrator.
- **No secrets in code.** Credentials are prompted, come from a profile, certificate or managed identity, or are avoided entirely with gMSA.
- **Consistent interface.** `Verb-Noun` names with approved verbs, `[CmdletBinding()]`, full comment-based help, `-OutputDirectory`, objects on the pipeline.
- **Tested.** PSScriptAnalyzer (PowerShell 5.1 and 7 syntax compatibility) and Pester run on every push. All 19 scripts were also run end-to-end against simulated (mocked) AD, Graph, Exchange Online and AWS CLI data, not a live tenant, and every KQL query was validated with the Kusto parser against its table schema.

---

## Safety disclaimer

- **Test first** in a lab or non-production tenant before running in production.
- **Containment actions are disruptive.** `Invoke-CompromisedAccountResponse.ps1 -Contain` blocks a user and revokes their sessions. Follow your incident response process and change control.
- **`Sync-FolderToS3.ps1 -Mirror` deletes** objects in S3 that no longer exist locally. Run with `-DryRun` first and enable S3 Versioning on the bucket.
- **Protect the output.** Reports contain names, email addresses, hostnames, IP and MAC addresses. Store them on access-controlled shares and never commit them. `.gitignore` blocks CSV, HTML, log and case folders.
- **Heuristics need review.** Findings such as "inactive" or "high-risk permission" are prompts for a human decision, not automatic verdicts.
- **No warranty.** Provided as-is under the MIT License.

---

## Roadmap

- [ ] Entra ID access review automation (create and report on reviews through Graph)
- [ ] Lifecycle Workflows for joiner / mover / leaver
- [ ] Windows Server 2022 hardening checks (SMBv1, LLMNR, NTLM auditing, LAPS coverage, Credential Guard)
- [ ] Defender XDR advanced hunting versions of the KQL queries
- [ ] Sentinel analytics rules as ARM / Bicep templates

---

## Author

Windows Server 2022 Administrator and Microsoft Entra ID Global Administrator, moving into Cloud Identity and Security Operations. Completing **SC-300** and **SC-200**.


## License

[MIT](LICENSE)
