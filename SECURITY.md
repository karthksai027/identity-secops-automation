# Security

## Found a problem?

If you find a security issue in these scripts, such as a way they could leak credentials or change something they shouldn't, please don't open a public issue. Use GitHub's [private vulnerability reporting](../../security/advisories/new) on this repo and I'll look at it as soon as I can.

## How I've tried to keep this safe

- **Read-only unless you say otherwise.** Only three scripts can change anything: `Invoke-CompromisedAccountResponse.ps1`, `Update-ScheduledTaskCredential.ps1` and `Sync-FolderToS3.ps1`. Each one needs an explicit switch and supports `-WhatIf` or `-DryRun`.
- **No secrets in the code.** Credentials are prompted for, come from a named profile, or come from a certificate or managed identity. The automated tests fail if they spot a hard-coded password or key. (The desktop version once kept a password in a text file. Never again.)
- **Least privilege.** Every script says exactly which Graph permissions and admin roles it needs, and none of them need Global Administrator.
- **The output is sensitive.** Reports contain people's names, email addresses, IPs and MAC addresses. The `.gitignore` blocks CSV, HTML, log and case folders so they don't end up in a commit by mistake.
