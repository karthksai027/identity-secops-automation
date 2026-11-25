# identity-secops-automation

PowerShell (and some KQL) I use to keep an eye on Active Directory and Microsoft Entra ID.

I'm an IT Administrator at a ~200-person engineering consultancy. We run hybrid identity: on-prem AD synced to Entra ID with Entra Connect. Project consultants join and leave all the time, so most of my week is joiners and leavers, access reviews, and making sure nothing gets left behind. These scripts started as a messy folder on my desktop that I used for exactly that. This repo is the cleaned-up version.

I passed **SC-300** (Identity and Access Administrator) and I'm studying for **SC-200** now, so the repo has two parts:

1. **Scripts I use at work.** I run these against our real AD and Entra tenant.
2. **Lab / SC-200 study.** Things I wrote while studying. They've been run in a lab or a trial tenant, not in production. They're clearly marked below so nobody mistakes them for battle-tested tools.

---

## 1. Scripts I use at work

### Active Directory

| Script | What I use it for |
|---|---|
| `Active-Directory-Governance/Get-ADInactiveUser.ps1` | Enabled accounts with no logon in 90 days. Mostly consultants whose exit never reached IT. |
| `Active-Directory-Governance/Get-ADStaleDisabledUser.ps1` | Accounts disabled months ago but still sitting in groups. |
| `Active-Directory-Governance/Get-ADUserInventory.ps1` | Full user export I compare against the HR list (Keka) during access reviews. |
| `Active-Directory-Governance/Get-ADPrivilegedGroupMember.ps1` | Who's in Domain Admins and the other high-privilege groups, including through nested groups. |
| `Active-Directory-Governance/Invoke-ADGovernanceReport.ps1` | Runs the reports above and builds one HTML summary for the quarterly review. |
| `Identity-Security-Posture/Get-ADSecurityPostureSummary.ps1` | Quick OK / Review / Risk checks on the domain (password policy, krbtgt age, Kerberoastable accounts and so on). |
| `Endpoint-Asset-Inventory/Get-ADComputerInventory.ps1` | Computers in AD, with stale machines and old Windows versions flagged. |
| `Endpoint-Asset-Inventory/Get-ADHardwareInventory.ps1` | Serial, model, RAM, disk and logged-on user over WinRM. Feeds our IT asset register. |
| `Windows-Server-Operations/Update-ScheduledTaskCredential.ps1` | Fixes scheduled tasks after a service account password change, or moves them to a gMSA. |

### Entra ID

| Script | What I use it for |
|---|---|
| `Entra-ID-Governance/Get-EntraMfaStrengthReport.ps1` | Who has strong MFA, who's still on SMS, who has nothing. I used this while rolling MFA out to 100% of users. |
| `Entra-ID-Governance/Get-EntraPrivilegedRoleReport.ps1` | Admin role assignments, including PIM-eligible ones. Flags standing Global Admin access. |
| `Entra-ID-Governance/Get-EntraStaleAccount.ps1` | Members and guests who haven't signed in, and licences we're paying for on inactive accounts. |
| `Entra-ID-Governance/Export-EntraConditionalAccessPolicy.ps1` | Backs up our Conditional Access policies to JSON before I change anything. |
| `Entra-ID-Governance/Get-EntraSsoAppReport.ps1` | Checks our SSO apps (Zoho on SAML, Keka on OIDC): certificate expiry, owners, whether assignment is required. |

All of these are read-only except `Update-ScheduledTaskCredential.ps1`, which supports `-WhatIf`.

---

## 2. Lab / SC-200 study

Written while studying for SC-300 and SC-200. Most of it came out of a 30-day Microsoft 365 E5 trial and my own lab. **Not run in production. Test before you trust them.**

| Folder | What's in it |
|---|---|
| `SC-200-Threat-Hunting/` | 16 KQL hunting queries for Sentinel and Defender XDR (password spray, MFA fatigue, risky consent, Kerberoasting and more). See its own README. |
| `Defender-XDR/` | Incident triage, device health and a runner for advanced hunting queries. |
| `Intune-Endpoint-Management/` | Device compliance and Autopilot enrolment report. |
| `Purview-DLP/` | DLP policy coverage report. |
| `M365-Security-Operations/` | Mailbox forwarding audit and a first-hour compromised-account checklist script. |
| `Identity-Protocols/` | Offline decoders for JWTs and SAML responses, for SSO troubleshooting practice. |
| `Entra-ID-Governance/` (extras) | `Get-EntraAppCredentialExpiry`, `Get-EntraRiskyAppPermission`, `Get-EntraAppRegistrationSecurityReport`, `Test-EntraTenantSecurityBaseline`. |
| `Cloud-Backup-Automation/` | A logged folder-to-S3 sync with `-DryRun`. |

Notes I took on OAuth 2.0, OIDC and SAML are in `docs/OAuth-OIDC-SAML-Guide.md`.

---

## Running them

```powershell
git clone https://github.com/karthksai027/identity-secops-automation.git
cd identity-secops-automation

# every script has help
Get-Help .\Active-Directory-Governance\Get-ADInactiveUser.ps1 -Full
```

**AD scripts:** run from a domain-joined machine with RSAT (the ActiveDirectory module). Normal read access is enough.

```powershell
.\Active-Directory-Governance\Invoke-ADGovernanceReport.ps1 -Verbose
```

**Entra scripts:** only need `Microsoft.Graph.Authentication`. Each script asks for the Graph scopes it needs. Global Reader is enough for all of them.

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
.\Entra-ID-Governance\Get-EntraMfaStrengthReport.ps1
```

Reports go to `.\Reports` as dated CSVs. For scheduled runs without stored passwords (certificate or gMSA), see `docs/Unattended-Authentication.md`.

## A few things to know

- `lastLogonTimestamp` can lag by up to 14 days, so treat "inactive" as "go and check", not "delete".
- The reports contain names, emails and hostnames. Don't share them around. `.gitignore` keeps CSV and HTML output out of commits.
- PSScriptAnalyzer and Pester run on every push (`.github/workflows/quality.yml`).

## What I'm working on next

- Entra ID access reviews through Graph, to replace the spreadsheet part of our quarterly review
- Joiner / mover / leaver with Lifecycle Workflows, triggered from HR
- Moving more of the SC-200 queries from "lab" to "used at work" as I get them tuned

Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

MIT
