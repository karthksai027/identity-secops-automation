# Running the scripts unattended

Interactive runs use delegated sign-in (`Connect-MgGraph -Scopes ...`) and your own admin account.
For scheduled runs, never store a user password. Use one of these options.

## Microsoft Graph: app registration with a certificate

1. Create an app registration, for example `IdentitySecOps-Reporting`.
2. Under **API permissions**, add only the **Application** permissions the scheduled scripts need,
   then grant admin consent. For the read-only reports:
   `User.Read.All`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`, `RoleManagement.Read.Directory`,
   `Directory.Read.All`, `Application.Read.All`, `Policy.Read.All`.
3. Upload a certificate (public key only). Keep the private key in the local machine certificate store
   of the server that runs the task, marked non-exportable.
4. Connect before running a script:

```powershell
Connect-MgGraph -ClientId '<app-id>' -TenantId '<tenant-id>' -CertificateThumbprint '<thumbprint>' -NoWelcome
.\Entra-ID-Governance\Get-EntraStaleAccount.ps1 -OutputDirectory 'D:\Reports'
```

The scripts detect the existing session and skip their own interactive sign-in.

On an Azure VM or in Azure Automation, use a **managed identity** instead (`Connect-MgGraph -Identity`),
so there is no certificate to rotate.

## Exchange Online

```powershell
Connect-ExchangeOnline -AppId '<app-id>' -Organization 'contoso.onmicrosoft.com' -CertificateThumbprint '<thumbprint>' -ShowBanner:$false
```

The app needs the `Exchange.ManageAsApp` application permission and an Exchange role such as
**View-Only Organization Management** (or Global Reader).

## Active Directory and Task Scheduler

Run AD reports under a **group Managed Service Account (gMSA)**. Windows rotates its password automatically.

```powershell
# Once, on a domain controller
New-ADServiceAccount -Name svc-idreports -DNSHostName svc-idreports.contoso.com `
    -PrincipalsAllowedToRetrieveManagedPassword 'ReportServers'

# On the reporting server
Install-ADServiceAccount svc-idreports
.\Windows-Server-Operations\Update-ScheduledTaskCredential.ps1 -TaskName 'AD Governance Monthly' -GmsaAccount 'CONTOSO\svc-idreports$'
```

## AWS

Use an EC2 instance profile or IAM Identity Center profile, or a named profile limited to the backup bucket.
Never put access keys in the script or in Task Scheduler arguments.
