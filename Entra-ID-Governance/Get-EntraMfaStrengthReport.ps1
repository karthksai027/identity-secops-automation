<#
.SYNOPSIS
    Classifies every Entra ID user's registered MFA methods by strength and flags at-risk users.

.DESCRIPTION
    Not all MFA is equal. SMS and voice are vulnerable to SIM swap and real-time phishing,
    and Authenticator push can be phished by adversary-in-the-middle kits. This script grades
    each user by the strongest method they have registered:

      Phishing-resistant : FIDO2 security key, passkey, Windows Hello for Business,
                           platform credential (macOS), certificate-based auth
      Strong             : Microsoft Authenticator, software/hardware OATH token
      Weak               : SMS, voice call, office phone
      None               : no MFA method registered

    Flags:
      - Users with no MFA or only weak MFA
      - Admins (any directory role) without a phishing-resistant method
      - Users not capable of MFA

    Two data sources:
      -Source Report  (default) : /reports/authenticationMethods/userRegistrationDetails.
                                  One call per page, fast, includes isAdmin. Needs Entra ID P1/P2.
      -Source PerUser           : /users/{id}/authentication/methods for each user. Works on any
                                  licence, but is slow on large tenants.

    Read-only.

.PARAMETER Source
    Report (default) or PerUser.

.PARAMETER IncludeGuests
    Include guest users. Guests usually satisfy MFA in their home tenant, so they are
    excluded by default.

.PARAMETER OutputDirectory
    Folder for the CSV reports. Default: .\Reports

.EXAMPLE
    .\Get-EntraMfaStrengthReport.ps1

.EXAMPLE
    .\Get-EntraMfaStrengthReport.ps1 -Source PerUser -Verbose

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : Microsoft.Graph.Authentication
    Scopes      : Report  -> AuditLog.Read.All, UserAuthenticationMethod.Read.All
                  PerUser -> User.Read.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory
    Entra role  : Global Reader, Security Reader or Reports Reader (least privilege, read-only)
    Licence     : Report source requires Microsoft Entra ID P1 or P2.

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [ValidateSet('Report', 'PerUser')]
    [string]$Source = 'Report',

    [switch]$IncludeGuests,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-GraphIfNeeded {
    param([Parameter(Mandatory)][string[]]$Scopes)
    $ctx = Get-MgContext
    if (-not $ctx) {
        Connect-MgGraph -Scopes $Scopes -NoWelcome
        $ctx = Get-MgContext
    }
    if ($ctx.AuthType -eq 'Delegated') {
        $missing = $Scopes | Where-Object { $_ -notin $ctx.Scopes }
        if ($missing) { Write-Warning "Graph session is missing scopes: $($missing -join ', '). Reconnect with Connect-MgGraph -Scopes $($Scopes -join ',')" }
    }
    $ctx
}

function Invoke-GraphPaged {
    param([Parameter(Mandatory)][string]$Uri)
    $items = New-Object System.Collections.Generic.List[object]
    while ($Uri) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        if ($resp.PSObject.Properties.Name -contains 'value') { foreach ($v in $resp.value) { $items.Add($v) } }
        else { $items.Add($resp) }
        $Uri = $resp.'@odata.nextLink'
    }
    , $items.ToArray()
}

function Get-MethodTier {
    param([string]$Method)
    switch -Regex ($Method) {
        'fido2|passKey|windowsHello|macOsSecureEnclave|platformCredential|x509'      { return 3 }  # Phishing-resistant
        'microsoftAuthenticator|softwareOneTimePasscode|hardwareOneTimePasscode|softwareOath|hardwareOath' { return 2 }  # Strong
        'phone|sms|voice'                                                            { return 1 }  # Weak
        default                                                                      { return 0 }  # Password, email, TAP, security questions
    }
}
#endregion

$tierName = @{ 3 = 'Phishing-resistant'; 2 = 'Strong'; 1 = 'Weak'; 0 = 'None' }

if ($Source -eq 'Report') {
    Connect-GraphIfNeeded -Scopes 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All' | Out-Null
    Write-Verbose 'Reading userRegistrationDetails report...'
    $raw = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails'

    $rows = foreach ($r in $raw) {
        [PSCustomObject]@{
            UserPrincipalName = $r.userPrincipalName
            DisplayName       = $r.userDisplayName
            UserType          = $r.userType
            IsAdmin           = [bool]$r.isAdmin
            Methods           = @($r.methodsRegistered)
            IsMfaCapable      = [bool]$r.isMfaCapable
            DefaultMethod     = $r.defaultMfaMethod
            Error             = $null
        }
    }
}
else {
    Connect-GraphIfNeeded -Scopes 'User.Read.All', 'UserAuthenticationMethod.Read.All', 'RoleManagement.Read.Directory' | Out-Null

    Write-Verbose 'Reading directory role assignments...'
    $adminIds = @{}
    foreach ($a in (Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=principalId')) {
        $adminIds[$a.principalId] = $true
    }

    Write-Verbose 'Reading users...'
    $users = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName,userType,accountEnabled&$filter=accountEnabled eq true'

    $i = 0
    $rows = foreach ($u in $users) {
        $i++
        Write-Progress -Activity 'Reading authentication methods' -Status $u.userPrincipalName -PercentComplete (($i / [math]::Max($users.Count, 1)) * 100)
        try {
            $methods = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/users/$($u.id)/authentication/methods"
            $names = @($methods | ForEach-Object { ($_.'@odata.type' -replace '^#microsoft\.graph\.', '') -replace 'AuthenticationMethod$', '' })
            $err = $null
        }
        catch {
            $names = @()
            $err = $_.Exception.Message
        }
        $mfaNames = $names | Where-Object { (Get-MethodTier $_) -gt 0 }
        [PSCustomObject]@{
            UserPrincipalName = $u.userPrincipalName
            DisplayName       = $u.displayName
            UserType          = $u.userType
            IsAdmin           = $adminIds.ContainsKey($u.id)
            Methods           = $names
            IsMfaCapable      = [bool]$mfaNames
            DefaultMethod     = $null
            Error             = $err
        }
    }
    Write-Progress -Activity 'Reading authentication methods' -Completed
}

if (-not $IncludeGuests) { $rows = $rows | Where-Object { $_.UserType -ne 'guest' } }

$report = foreach ($r in $rows) {
    $tier = 0
    foreach ($m in $r.Methods) { $t = Get-MethodTier $m; if ($t -gt $tier) { $tier = $t } }

    $findings = New-Object System.Collections.Generic.List[string]
    if ($r.Error) { $findings.Add("Could not read methods: $($r.Error)") }
    elseif ($tier -eq 0) { $findings.Add('No MFA method registered') }
    elseif ($tier -eq 1) { $findings.Add('Only weak MFA (SMS/voice)') }
    if ($r.IsAdmin -and $tier -lt 3) { $findings.Add('Admin without phishing-resistant MFA') }

    [PSCustomObject]@{
        UserPrincipalName = $r.UserPrincipalName
        DisplayName       = $r.DisplayName
        UserType          = $r.UserType
        IsAdmin           = $r.IsAdmin
        MfaStrength       = $tierName[$tier]
        MethodsRegistered = ($r.Methods -join ', ')
        DefaultMfaMethod  = $r.DefaultMethod
        IsMfaCapable      = $r.IsMfaCapable
        Findings          = $findings -join '; '
        AtRisk            = $findings.Count -gt 0
    }
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$stamp    = '{0:yyyyMMdd_HHmm}' -f (Get-Date)
$fullPath = Join-Path $OutputDirectory "Entra_MfaStrength_All_$stamp.csv"
$riskPath = Join-Path $OutputDirectory "Entra_MfaStrength_AtRisk_$stamp.csv"

$report | Sort-Object MfaStrength, UserPrincipalName | Export-Csv -Path $fullPath -NoTypeInformation -Encoding UTF8
$report | Where-Object AtRisk | Sort-Object IsAdmin -Descending | Export-Csv -Path $riskPath -NoTypeInformation -Encoding UTF8

$summary = $report | Group-Object MfaStrength | Select-Object @{ n = 'MfaStrength'; e = { $_.Name } }, Count
Write-Verbose ("Users: {0}. At risk: {1}. Admins at risk: {2}." -f @($report).Count,
    @($report | Where-Object AtRisk).Count, @($report | Where-Object { $_.AtRisk -and $_.IsAdmin }).Count)
Write-Verbose ($summary | Out-String)
Write-Verbose "Reports: $fullPath ; $riskPath"

$report
