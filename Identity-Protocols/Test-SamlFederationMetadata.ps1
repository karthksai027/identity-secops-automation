<#
.SYNOPSIS
    Reads SAML federation metadata (from a URL, a file, or an Entra ID app) and checks the entity ID, endpoints and signing certificates, including how long each certificate has left.

.DESCRIPTION
    Federation metadata is how two sides of a SAML trust tell each other "this is who I am,
    this is where to send users, and this is the certificate I sign with". When a certificate is
    rolled on one side and not the other, SSO breaks. This script reads metadata and reports:

      - Entity ID and whether it describes an identity provider (IdP) or service provider (SP)
      - Single sign-on, single logout and assertion consumer (reply) endpoints, with bindings
      - Supported NameID formats
      - Every signing certificate: thumbprint, subject, valid from/to, and days left

    It flags expired certificates, certificates expiring within -DaysAhead, plain-HTTP
    endpoints, and (with -ExpectedThumbprint) metadata that no longer contains the certificate
    the other side trusts.

    -TenantId with -AppId builds the Entra ID app-specific metadata URL for you, which is the
    URL you'd give a SaaS vendor during SAML setup.

.PARAMETER Url
    Metadata URL to download.

.PARAMETER Path
    Metadata XML file to read.

.PARAMETER TenantId
    Entra tenant ID or verified domain (used with -AppId).

.PARAMETER AppId
    Application (client) ID of the Entra enterprise app (used with -TenantId).

.PARAMETER DaysAhead
    Certificates expiring within this many days are flagged. Default: 60.

.PARAMETER ExpectedThumbprint
    Certificate thumbprint the relying party currently trusts. Flags it if the metadata no longer contains it.

.EXAMPLE
    .\Test-SamlFederationMetadata.ps1 -TenantId contoso.onmicrosoft.com -AppId 11111111-2222-3333-4444-555555555555

.EXAMPLE
    .\Test-SamlFederationMetadata.ps1 -Url https://vendor.example.com/saml/metadata

.EXAMPLE
    .\Test-SamlFederationMetadata.ps1 -Path .\metadata.xml -ExpectedThumbprint 'A1B2C3...'

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : none (Windows PowerShell 5.1 and PowerShell 7)
    Network     : HTTPS to the metadata URL (not needed with -Path)
    Permissions : none, metadata is public by design

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1

[CmdletBinding(DefaultParameterSetName = 'Url')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Url')]
    [ValidatePattern('^https?://')]
    [string]$Url,

    [Parameter(Mandatory, ParameterSetName = 'File')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$Path,

    [Parameter(Mandatory, ParameterSetName = 'Entra')]
    [string]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'Entra')]
    [guid]$AppId,

    [ValidateRange(1, 3650)]
    [int]$DaysAhead = 60,

    [string]$ExpectedThumbprint
)

$ErrorActionPreference = 'Stop'

switch ($PSCmdlet.ParameterSetName) {
    'Entra' { $Url = "https://login.microsoftonline.com/$TenantId/federationmetadata/2007-06/federationmetadata.xml?appid=$AppId" }
}

$xmlText = if ($PSCmdlet.ParameterSetName -eq 'File') {
    Get-Content -Path $Path -Raw
} else {
    Write-Verbose "Downloading $Url"
    (Invoke-WebRequest -Uri $Url -UseBasicParsing).Content
}

$doc = New-Object System.Xml.XmlDocument
$doc.XmlResolver = $null
$doc.LoadXml($xmlText)

$ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
$ns.AddNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata')
$ns.AddNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')

$entity = $doc.SelectSingleNode('//md:EntityDescriptor', $ns)
if (-not $entity) { throw 'No SAML 2.0 EntityDescriptor found in the metadata.' }

$idp = $entity.SelectSingleNode('md:IDPSSODescriptor', $ns)
$sp  = $entity.SelectSingleNode('md:SPSSODescriptor', $ns)
$role = if ($idp -and $sp) { 'IdP and SP' } elseif ($idp) { 'Identity provider (IdP)' } elseif ($sp) { 'Service provider (SP)' } else { 'Unknown (no SAML SSO descriptor)' }

$now = [DateTime]::UtcNow
$warnings = New-Object System.Collections.Generic.List[string]

$endpoints = foreach ($desc in @($idp, $sp) | Where-Object { $_ }) {
    foreach ($e in $desc.SelectNodes('md:SingleSignOnService | md:SingleLogoutService | md:AssertionConsumerService', $ns)) {
        $binding = ($e.GetAttribute('Binding') -split ':')[-1]
        if ($e.GetAttribute('Location') -match '^http://' ) { $warnings.Add("Plain HTTP endpoint: $($e.GetAttribute('Location'))") }
        "{0} [{1}] {2}" -f $e.LocalName, $binding, $e.GetAttribute('Location')
    }
}

$certs = foreach ($kd in $entity.SelectNodes('.//md:KeyDescriptor', $ns)) {
    $use = $kd.GetAttribute('use')
    if ($use -and $use -ne 'signing') { continue }
    $b64 = $kd.SelectSingleNode('ds:KeyInfo/ds:X509Data/ds:X509Certificate', $ns)
    if (-not $b64) { continue }
    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String(($b64.InnerText -replace '\s', '')))
    $days = [int][math]::Floor(($c.NotAfter.ToUniversalTime() - $now).TotalDays)
    [PSCustomObject]@{ Thumbprint = $c.Thumbprint; Subject = $c.Subject; NotBefore = $c.NotBefore; NotAfter = $c.NotAfter; DaysLeft = $days }
}
$certs = @($certs | Sort-Object Thumbprint -Unique)

if ($certs.Count -eq 0) { $warnings.Add('No signing certificate in the metadata') }
foreach ($c in $certs) {
    if ($c.DaysLeft -lt 0) { $warnings.Add("Certificate $($c.Thumbprint) EXPIRED $(-$c.DaysLeft) days ago") }
    elseif ($c.DaysLeft -le $DaysAhead) { $warnings.Add("Certificate $($c.Thumbprint) expires in $($c.DaysLeft) days") }
}
if ($certs.Count -gt 1) { $warnings.Add("$($certs.Count) signing certificates published (normal during a rollover; make sure the relying party trusts the new one)") }
if ($ExpectedThumbprint) {
    $want = ($ExpectedThumbprint -replace '[\s:]', '').ToUpperInvariant()
    if ($certs.Thumbprint -notcontains $want) { $warnings.Add("Expected certificate $want is no longer in the metadata: the trust needs updating") }
}

[PSCustomObject]@{
    Source         = if ($Url) { $Url } else { (Resolve-Path $Path).Path }
    EntityId       = $entity.GetAttribute('entityID')
    Role           = $role
    Endpoints      = ($endpoints -join "`n")
    NameIdFormats  = (@($entity.SelectNodes('.//md:NameIDFormat', $ns) | ForEach-Object { ($_.InnerText.Trim() -split ':')[-1] } | Sort-Object -Unique) -join ', ')
    SigningCerts   = $certs
    NearestExpiry  = ($certs | Sort-Object DaysLeft | Select-Object -First 1).NotAfter
    Warnings       = $warnings -join '; '
}
