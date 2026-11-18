# Karthik's Identity & SecOps Toolkit

Many Microsoft 365 incidents start with one account that has more access than it needs. This is the PowerShell and KQL I built to find those accounts across hybrid Active Directory and Microsoft Entra ID, close the gaps, and respond when something looks wrong.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-5391FE?logo=powershell&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-REST-0078D4?logo=microsoft&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Microsoft%20Sentinel-0078D4)
![Studying](https://img.shields.io/badge/Studying-SC--300%20%7C%20SC--200-2E7D32)
![Quality](https://github.com/karthksai027/identity-secops-automation/actions/workflows/quality.yml/badge.svg)

---

## How this started

I look after identity, endpoint and email security as a Microsoft 365 & Security Engineer, in a hybrid setup where on-prem Active Directory syncs to Microsoft Entra ID. Over time I collected a folder of scripts on my desktop for the questions I kept coming back to:

- Which users haven't logged in for 90 days?
- Which disabled accounts are still sitting there six months later?
- Who still doesn't have MFA set up, or only has SMS?
- What hardware do we actually have, and who's using it?
- Is last night's backup in S3?

They worked, but they were rough. Hard-coded paths, duplicate copies, a password parameter sitting in a plain text file. When I started studying for **SC-300** (Identity and Access Administrator) and **SC-200** (Security Operations Analyst), I went back to that folder and rebuilt it properly. Then I kept adding the things the exams kept pointing at: privileged roles, Conditional Access, risky app consents, mailbox forwarding, and hunting queries for Sentinel.

This repo is the result. It's what I'd want to hand to the next admin who inherits a tenant.

---

## What it covers

| Area | What I wanted to answer | Folder |
|---|---|---|
| **Account hygiene** | Who's inactive, who's disabled but never cleaned up, who's in Domain Admins and shouldn't be | `Active-Directory-Governance` |
| **AD attack surface** | Kerberoastable accounts, accounts without pre-auth, old krbtgt password, weak password policy | `Identity-Security-Posture` |
| **Entra ID** | MFA strength, standing admin access, stale guests, Conditional Access gaps, expiring app secrets, risky app permissions, tenant settings | `Entra-ID-Governance` |
| **Hybrid identity** | Synced admin accounts that should be cloud-only, whether Entra Connect sync is healthy, and disabling the on-prem account during an incident so the next sync doesn't undo it | `Entra-ID-Governance`, `M365-Security-Operations` |
| **Incident response** | What to do in the first hour when an account looks compromised, and where attackers hide mail rules | `M365-Security-Operations` |
| **Detection** | 12 KQL queries for Microsoft Sentinel, each mapped to MITRE ATT&CK | `SC-200-Threat-Hunting` |
| **Day-to-day ops** | Hardware inventory, service account passwords on scheduled tasks, offsite backup | `Endpoint-Asset-Inventory`, `Windows-Server-Operations`, `Cloud-Backup-Automation` |

---

## Repository layout

```text
.
├── Active-Directory-Governance/
│   ├── Get-ADInactiveUser.ps1
│   ├── Get-ADStaleDisabledUser.ps1
│   ├── Get-ADUserInventory.ps1
│   ├── Get-ADPrivilegedGroupMember.ps1
│   └── Invoke-ADGovernanceReport.ps1        # runs the AD reports and builds an HTML summary
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
├── SC-200-Threat-Hunting/                   # KQL, with its own README
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
├── tests/Repository.Tests.ps1
├── .github/workflows/quality.yml
├── PSScriptAnalyzerSettings.psd1
├── SECURITY.md
└── LICENSE
```

---

## The scripts

### Active Directory

| Script | What it does | You'll need |
|---|---|---|
| `Get-ADInactiveUser.ps1` | Lists enabled accounts with no logon in 90 days (you can change the number), including ones that never logged in at all. These are the accounts password sprays love. | `ActiveDirectory` module, normal read access |
| `Get-ADStaleDisabledUser.ps1` | Finds accounts that were disabled months ago but never removed, and shows how many groups they still belong to. Skips built-ins like krbtgt and Guest. | `ActiveDirectory` module, read access |
| `Get-ADUserInventory.ps1` | A clean export of every user with department, manager, last logon and password age. Handy for access reviews or checking against HR's list. | `ActiveDirectory` module, read access |
| `Get-ADPrivilegedGroupMember.ps1` | Shows everyone in Domain Admins, Enterprise Admins and the other high-privilege groups, including people who get there through nested groups. Flags anyone inactive, with an old password, with an SPN, or not protected from delegation. | `ActiveDirectory` module, read access to the forest root |
| `Get-ADSecurityPostureSummary.ps1` | 18 quick checks that give each area an OK, Review or Risk rating with a short "here's what to do" note. Add `-ExportDetails` to get the actual account lists. | `ActiveDirectory` module, read access |
| `Invoke-ADGovernanceReport.ps1` | Runs the AD reports above in one go and drops them in a dated folder with an HTML summary I can send to a manager. | Same as above |

### Microsoft Entra ID

| Script | What it does | Graph permissions / role |
|---|---|---|
| `Get-EntraMfaStrengthReport.ps1` | Sorts every user into phishing-resistant, strong, weak (SMS or voice) or no MFA. Calls out admins who don't have phishing-resistant MFA yet. | `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`. Global Reader. |
| `Get-EntraPrivilegedRoleReport.ps1` | Lists every admin role assignment, active and PIM-eligible. Flags standing Global Admin access, synced on-prem accounts holding admin roles, guests or apps with roles, and admins who haven't signed in for a while. | `RoleManagement.Read.Directory`, `Directory.Read.All`, `AuditLog.Read.All`. Global Reader. P2 for PIM data. |
| `Get-EntraStaleAccount.ps1` | Finds members and guests who haven't signed in, guests who never accepted their invite, and inactive accounts still using a licence. | `User.Read.All`, `AuditLog.Read.All`. Global Reader. P1. |
| `Export-EntraConditionalAccessPolicy.ps1` | Backs up every Conditional Access policy to JSON so you can see what changed and roll back. Also checks for the policies I'd expect every tenant to have. | `Policy.Read.All`. Global Reader. |
| `Get-EntraAppCredentialExpiry.ps1` | Shows app secrets and certificates that have expired, are about to, or were set to last far too long. Also flags brand-new credentials and apps with no owner. | `Application.Read.All`. Global Reader. |
| `Get-EntraRiskyAppPermission.ps1` | Looks at what every app is allowed to do in Microsoft Graph and Exchange Online and highlights the dangerous ones, especially third-party apps from unverified publishers. | `Application.Read.All`, `Directory.Read.All`. Global Reader. |
| `Test-EntraTenantSecurityBaseline.ps1` | A pass/fail check of tenant settings: security defaults, Global Admin count, SMS and voice, FIDO2, guest invites, user consent, app registration, sync health and more. | `Policy.Read.All`, `RoleManagement.Read.Directory`, `Directory.Read.All`. Global Reader. |

### Microsoft 365 incident response

| Script | What it does | You'll need |
|---|---|---|
| `Get-MailboxForwardingAudit.ps1` | Looks for the classic email-compromise tricks: mailboxes forwarding outside the company, inbox rules that forward or redirect, and rules that quietly delete or hide mail about invoices and payments. | `ExchangeOnlineManagement` v3. Global Reader or View-Only Organization Management. |
| `Invoke-CompromisedAccountResponse.ps1` | My first-hour checklist as a script. By default it only gathers evidence (sign-ins, MFA methods, audit events, roles, risk level, inbox rules) into a case folder. With `-Contain` it blocks sign-in and kills sessions. Try it with `-WhatIf` first. | Graph read permissions, plus `User.ReadWrite.All` and `IdentityRiskyUser.ReadWrite.All` for containment. User Administrator / Security Operator. |

### Everyday infrastructure

| Script | What it does | You'll need |
|---|---|---|
| `Get-ADComputerInventory.ps1` | Every computer in AD, tagged as DC, server or workstation, with flags for stale machines and unsupported Windows versions. | `ActiveDirectory` module, read access |
| `Get-ADHardwareInventory.ps1` | Connects to each machine over WinRM and builds an asset register: serial, model, CPU, RAM, disk, MAC, IP and who's logged in. Anything unreachable goes in a separate list with the reason. | `ActiveDirectory` module, WinRM on the targets, local admin |
| `Update-ScheduledTaskCredential.ps1` | Fixes scheduled tasks after a service account password change, or better, moves them to a gMSA so there's no password to manage at all. | `ScheduledTasks` module, local admin |
| `Sync-FolderToS3.ps1` | A logged, unattended backup to Amazon S3 that checks credentials, the bucket and the source folder before it starts. Has `-DryRun`, and a `-Mirror` option that won't run against an empty folder. | AWS CLI v2 with a named profile |

### KQL hunting queries

Twelve queries for Microsoft Sentinel: password spray, MFA fatigue, legacy sign-ins, sign-ins from a new country, admin role changes, risky app consent, MFA registered from an unknown IP, Kerberoasting, AD brute force, Domain Admins changes, suspicious inbox rules and mass downloads. Details are in **[SC-200-Threat-Hunting/README.md](SC-200-Threat-Hunting/README.md)**.

---

## Getting started

```powershell
git clone https://github.com/karthksai027/identity-secops-automation.git
cd identity-secops-automation

# Every script has built-in help
Get-Help .\Entra-ID-Governance\Get-EntraMfaStrengthReport.ps1 -Full
```

**Active Directory** (run from a domain-joined admin machine):

```powershell
Install-WindowsFeature RSAT-AD-PowerShell                                                   # Windows Server
Get-WindowsCapability -Online -Name Rsat.ActiveDirectory* | Add-WindowsCapability -Online   # Windows 10/11

.\Active-Directory-Governance\Invoke-ADGovernanceReport.ps1 -Verbose
.\Identity-Security-Posture\Get-ADSecurityPostureSummary.ps1 -ExportDetails
```

**Entra ID.** These only need the Graph authentication module. They call the Graph API directly, so you don't have to install the whole SDK.

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

.\Entra-ID-Governance\Test-EntraTenantSecurityBaseline.ps1 | Format-Table Area, Check, Value, Status
.\Entra-ID-Governance\Get-EntraPrivilegedRoleReport.ps1 | Where-Object Findings
```

Each script asks only for the permissions it needs. If you're already connected, it reuses your session and tells you if something's missing.

**Exchange Online:**

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
.\M365-Security-Operations\Get-MailboxForwardingAudit.ps1
```

**Incident response.** Always do a dry run first.

```powershell
.\M365-Security-Operations\Invoke-CompromisedAccountResponse.ps1 -UserPrincipalName jdoe@contoso.com -IncludeMailbox
.\M365-Security-Operations\Invoke-CompromisedAccountResponse.ps1 -UserPrincipalName jdoe@contoso.com -Contain -ConfirmCompromised -RemediateMailbox -WhatIf
```

Reports land in `.\Reports` (or wherever you point `-OutputDirectory`) as dated CSV files. Each script also returns objects, so you can pipe the results straight into `Where-Object` or `Export-Excel`.

Want to run them on a schedule without storing passwords? See **[docs/Unattended-Authentication.md](docs/Unattended-Authentication.md)**.

---

## How I built it

- **Look, don't touch.** Almost everything here only reads. The three scripts that can change something need an explicit switch, and they support `-WhatIf` (or `-DryRun` for the S3 backup).
- **Least privilege.** Each script lists the smallest set of permissions it needs. None of them need Global Administrator.
- **No passwords in code.** That's where the original desktop scripts went wrong. Credentials are now prompted for, come from a certificate or managed identity, or disappear entirely with a gMSA.
- **Same shape everywhere.** Approved `Verb-Noun` names, full `Get-Help`, the same `-OutputDirectory` switch, and objects you can pipe.
- **Checked on every push.** GitHub Actions runs PSScriptAnalyzer and Pester whenever I push a change. Before publishing, I also ran all 19 scripts end to end against simulated AD, Graph, Exchange Online and AWS data (not a live tenant), and checked every KQL query against its table schema.

---

## Before you run anything

- **Try it in a lab first.** These are written to be safe, but your environment isn't mine.
- **Containment is disruptive.** `Invoke-CompromisedAccountResponse.ps1 -Contain` locks a person out. Follow your own incident process.
- **`Sync-FolderToS3.ps1 -Mirror` deletes** files in S3 that are gone locally. Run `-DryRun` first and turn on S3 versioning.
- **The reports are sensitive.** They hold names, emails, hostnames, IPs and MAC addresses. Keep them somewhere locked down. The `.gitignore` stops them being committed by accident.
- **A finding is a prompt, not a verdict.** "Inactive" or "high-risk" means "go and look", not "delete it".
- **No warranty.** MIT licensed, use at your own risk.

---

## What I'm working on next

- [ ] Automating Entra ID access reviews through Graph
- [ ] Joiner / mover / leaver with Lifecycle Workflows
- [ ] Windows Server 2022 hardening checks (SMBv1, LLMNR, NTLM, LAPS, Credential Guard)
- [ ] Defender XDR versions of the hunting queries
- [ ] Sentinel analytics rules as Bicep templates

---

## About me

I'm Karthik, a Microsoft 365 & Security Engineer. I look after identity, endpoint and email security: rolling out MFA and Conditional Access in Entra ID, keeping devices compliant in Intune with Autopilot, automating provisioning, licensing and reporting with PowerShell and Microsoft Graph, and working alerts across Defender for Endpoint, Identity and Office 365.

Before moving to the cloud I was a System Administrator running Active Directory, Group Policy, Windows Server, DNS/DHCP and SonicWall firewalls, so hybrid identity is where I started. I like building environments that are secure by default, so people can get on with their work without fighting the controls.

I'm currently studying for **SC-300** and **SC-200**.

If you spot a bug or have an idea, open an issue. I'd like to hear it.

## License

[MIT](LICENSE)
