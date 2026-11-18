# Running the scripts on a schedule

When I run these by hand, I sign in with my own admin account and `Connect-MgGraph -Scopes ...`. For anything that runs on a schedule, I don't want a password stored anywhere. Here's how to set that up.

## Microsoft Graph: an app registration with a certificate

1. Create an app registration, for example `IdentitySecOps-Reporting`.
2. Under **API permissions**, add only the **Application** permissions the scheduled scripts need, then grant admin consent. For the read-only reports that's:
   `User.Read.All`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`, `RoleManagement.Read.Directory`,
   `Directory.Read.All`, `Application.Read.All`, `Policy.Read.All`.
   For the Defender XDR and Intune reports add `SecurityIncident.Read.All`, `ThreatHunting.Read.All` and
   `DeviceManagementManagedDevices.Read.All` (+ `DeviceManagementServiceConfig.Read.All` for Autopilot).
3. Upload a certificate (public key only). Keep the private key in the local machine certificate store on the server that runs the task, marked as non-exportable.
4. Connect before running a script:

```powershell
Connect-MgGraph -ClientId '<app-id>' -TenantId '<tenant-id>' -CertificateThumbprint '<thumbprint>' -NoWelcome
.\Entra-ID-Governance\Get-EntraStaleAccount.ps1 -OutputDirectory 'D:\Reports'
```

The scripts notice you're already connected and skip their own sign-in.

If the job runs on an Azure VM or in Azure Automation, use a **managed identity** instead (`Connect-MgGraph -Identity`). Then there's no certificate to renew either.

## Exchange Online and Purview

```powershell
Connect-ExchangeOnline -AppId '<app-id>' -Organization 'contoso.onmicrosoft.com' -CertificateThumbprint '<thumbprint>' -ShowBanner:$false

# Purview DLP report (Security & Compliance PowerShell)
Connect-IPPSSession -AppId '<app-id>' -Organization 'contoso.onmicrosoft.com' -CertificateThumbprint '<thumbprint>'
```

The app needs the `Exchange.ManageAsApp` application permission and an Exchange role such as **View-Only Organization Management** (or Global Reader). For the DLP report, also assign it the **Compliance Administrator** role or Global Reader.

## Active Directory and Task Scheduler

Run the AD reports under a **group Managed Service Account (gMSA)**. Windows changes its password for you, so there's nothing to rotate or leak.

```powershell
# Once, on a domain controller
New-ADServiceAccount -Name svc-idreports -DNSHostName svc-idreports.contoso.com `
    -PrincipalsAllowedToRetrieveManagedPassword 'ReportServers'

# On the reporting server
Install-ADServiceAccount svc-idreports
.\Windows-Server-Operations\Update-ScheduledTaskCredential.ps1 -TaskName 'AD Governance Monthly' -GmsaAccount 'CONTOSO\svc-idreports$'
```

## AWS

Use an EC2 instance profile, an IAM Identity Center profile, or a named profile that can only touch the backup bucket. Never put access keys in the script or in the Task Scheduler arguments.
