# Security Policy

## Reporting a vulnerability

If you find a security issue in these scripts (for example a way they could leak credentials or
make an unintended change), please **do not open a public issue**. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository instead.

## Design principles

- **Read-only by default.** Only `Invoke-CompromisedAccountResponse.ps1`, `Update-ScheduledTaskCredential.ps1`
  and `Sync-FolderToS3.ps1` can change anything. All of them support `-WhatIf` and/or require an explicit switch.
- **No secrets in code.** Credentials are prompted (`Get-Credential`), taken from a named profile, or come
  from a managed identity / certificate. CI fails if a hard-coded secret pattern is detected.
- **Least privilege.** Each script documents the minimum Microsoft Graph scopes and Entra / AD roles it needs.
- **Output is sensitive.** Reports contain identities, IP and MAC addresses. `.gitignore` blocks CSV, HTML,
  log and case folders from being committed.
