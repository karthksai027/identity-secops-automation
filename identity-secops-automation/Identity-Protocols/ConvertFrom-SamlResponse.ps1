<#
.SYNOPSIS
    Decodes a SAML 2.0 response or request captured from the browser and explains why an SSO sign-in might be failing.

.DESCRIPTION
    Most SAML SSO tickets come down to a handful of mismatches: wrong audience (Identifier /
    Entity ID), wrong Reply URL (ACS), wrong NameID format or value, missing attributes, clock
    skew, or a certificate the app doesn't trust. This script decodes the base64 SAMLResponse
    you captured (browser dev tools > Network > the POST to the app, or a SAML tracer
    extension) and shows:

      Response  : status, destination, issuer, InResponseTo
      Assertion : issuer, NameID and format, audience, recipient, validity window,
                  authentication time and method (AuthnContextClassRef), session index
      Claims    : every attribute name and value
      Signature : whether the response and/or the assertion is signed, the algorithms,
                  and the signing certificate's thumbprint, subject and expiry

    With -VerifySignature it checks the XML signature against the certificate inside the
    message, and compares that certificate with -TrustedThumbprint if you give one (the
    thumbprint shown on the app's SAML signing certificate in Entra ID).

    It flags common problems: non-Success status, expired or not-yet-valid assertion,
    audience or recipient that don't match -ExpectedAudience / -ExpectedReplyUrl, SHA-1
    signatures, unsigned assertions, and encrypted assertions (which can only be read with the
    app's private key).

    Use -Deflated for a SAMLRequest taken from a redirect URL (HTTP-Redirect binding).

    SAML responses contain personal data and are valid sign-in tokens until they expire.
    Decode them locally and delete captures when you're done.

.PARAMETER SamlMessage
    The base64 SAMLResponse or SAMLRequest value (URL-encoded is fine). Accepts pipeline input.

.PARAMETER Path
    Read the base64 value, or raw XML, from a file instead.

.PARAMETER Deflated
    The message is deflate-compressed (SAMLRequest from an HTTP-Redirect URL).

.PARAMETER ExpectedAudience
    The Identifier (Entity ID) the app expects. Flags a mismatch.

.PARAMETER ExpectedReplyUrl
    The Reply URL (Assertion Consumer Service URL) the app expects. Flags a mismatch.

.PARAMETER VerifySignature
    Verify the XML signature(s) with the embedded certificate.

.PARAMETER TrustedThumbprint
    Thumbprint of the signing certificate the app trusts. Flags a different certificate.

.EXAMPLE
    Get-Clipboard | .\ConvertFrom-SamlResponse.ps1 -ExpectedAudience 'https://app.contoso.com/saml' -VerifySignature

.EXAMPLE
    .\ConvertFrom-SamlResponse.ps1 -Path .\samlresponse.txt -TrustedThumbprint 'A1B2C3...' -VerifySignature

.EXAMPLE
    .\ConvertFrom-SamlResponse.ps1 -SamlMessage $samlRequestFromUrl -Deflated

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : none (Windows PowerShell 5.1 and PowerShell 7)
    Permissions : none, runs entirely offline

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1

[CmdletBinding(DefaultParameterSetName = 'Value')]
param(
    [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Value')]
    [ValidateNotNullOrEmpty()]
    [string]$SamlMessage,

    [Parameter(Mandatory, ParameterSetName = 'File')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$Path,

    [switch]$Deflated,

    [string]$ExpectedAudience,

    [string]$ExpectedReplyUrl,

    [switch]$VerifySignature,

    [string]$TrustedThumbprint
)

begin {
    $ErrorActionPreference = 'Stop'
    Add-Type -AssemblyName System.Security
}

process {
    $text = if ($PSCmdlet.ParameterSetName -eq 'File') { Get-Content -Path $Path -Raw } else { $SamlMessage }
    $text = $text.Trim()

    # Accept raw XML, base64, or URL-encoded base64
    if ($text.StartsWith('<')) {
        $xmlText = $text
    }
    else {
        if ($text -match '%[0-9A-Fa-f]{2}') { $text = [Uri]::UnescapeDataString($text) }
        $text = $text -replace '^(SAMLResponse|SAMLRequest)=', '' -replace '\s', ''
        $bytes = [Convert]::FromBase64String($text)
        if ($Deflated) {
            $in = New-Object System.IO.MemoryStream(, $bytes)
            $deflate = New-Object System.IO.Compression.DeflateStream($in, [System.IO.Compression.CompressionMode]::Decompress)
            $reader = New-Object System.IO.StreamReader($deflate, [Text.Encoding]::UTF8)
            $xmlText = $reader.ReadToEnd()
            $reader.Dispose()
        }
        else {
            $xmlText = [Text.Encoding]::UTF8.GetString($bytes)
        }
    }

    $doc = New-Object System.Xml.XmlDocument
    $doc.PreserveWhitespace = $true
    $doc.XmlResolver = $null   # never fetch external entities
    $doc.LoadXml($xmlText)

    $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol')
    $ns.AddNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion')
    $ns.AddNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')

    $root = $doc.DocumentElement
    $now = [DateTime]::UtcNow
    $warnings = New-Object System.Collections.Generic.List[string]

    function Get-Text { param($Node, [string]$XPath) $n = $Node.SelectSingleNode($XPath, $ns); if ($n) { $n.InnerText.Trim() } else { $null } }
    function Get-Attr { param($Node, [string]$XPath, [string]$Name) $n = $Node.SelectSingleNode($XPath, $ns); if ($n) { $n.GetAttribute($Name) } else { $null } }
    function ConvertTo-UtcDate { param([string]$Value) if ($Value) { [DateTime]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) } else { $null } }

    # ---- AuthnRequest (SP -> IdP) ----
    if ($root.LocalName -eq 'AuthnRequest') {
        return [PSCustomObject]@{
            MessageType           = 'AuthnRequest (app asking the identity provider to sign the user in)'
            Issuer                = Get-Text $root 'saml:Issuer'
            Id                    = $root.GetAttribute('ID')
            IssueInstant          = $root.GetAttribute('IssueInstant')
            Destination           = $root.GetAttribute('Destination')
            AssertionConsumerUrl  = $root.GetAttribute('AssertionConsumerServiceURL')
            ProtocolBinding       = $root.GetAttribute('ProtocolBinding')
            NameIdPolicy          = Get-Attr $root 'samlp:NameIDPolicy' 'Format'
            RequestedAuthnContext = (@($root.SelectNodes('samlp:RequestedAuthnContext/saml:AuthnContextClassRef', $ns) | ForEach-Object { $_.InnerText }) -join ', ')
            ForceAuthn            = $root.GetAttribute('ForceAuthn')
            Signed                = [bool]$root.SelectSingleNode('ds:Signature', $ns)
            Warnings              = if ($root.SelectSingleNode('samlp:RequestedAuthnContext', $ns)) { 'RequestedAuthnContext is set: if the user signs in another way Entra ID returns AADSTS75011' } else { '' }
        }
    }

    if ($root.LocalName -ne 'Response') { throw "Unexpected SAML message type '$($root.LocalName)'." }

    # ---- Response ----
    $statusCode = Get-Attr $root 'samlp:Status/samlp:StatusCode' 'Value'
    $subStatus  = Get-Attr $root 'samlp:Status/samlp:StatusCode/samlp:StatusCode' 'Value'
    $statusMsg  = Get-Text $root 'samlp:Status/samlp:StatusMessage'
    if ($statusCode -notmatch ':Success$') { $warnings.Add("Status is not Success: $statusCode $subStatus $statusMsg".Trim()) }

    if ($root.SelectSingleNode('saml:EncryptedAssertion', $ns)) {
        $warnings.Add('Assertion is encrypted: only the app (with its private key) can read the claims')
    }

    $assertion = $root.SelectSingleNode('saml:Assertion', $ns)
    $claims = [ordered]@{}
    $a = $null
    if ($assertion) {
        foreach ($attr in $assertion.SelectNodes('saml:AttributeStatement/saml:Attribute', $ns)) {
            $claims[$attr.GetAttribute('Name')] = (@($attr.SelectNodes('saml:AttributeValue', $ns) | ForEach-Object { $_.InnerText }) -join '; ')
        }

        $conditions   = $assertion.SelectSingleNode('saml:Conditions', $ns)
        $notBefore    = if ($conditions) { ConvertTo-UtcDate $conditions.GetAttribute('NotBefore') } else { $null }
        $notOnOrAfter = if ($conditions) { ConvertTo-UtcDate $conditions.GetAttribute('NotOnOrAfter') } else { $null }
        $audiences    = @($assertion.SelectNodes('saml:Conditions/saml:AudienceRestriction/saml:Audience', $ns) | ForEach-Object { $_.InnerText.Trim() })
        $recipient    = Get-Attr $assertion 'saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData' 'Recipient'

        if ($notOnOrAfter -and $notOnOrAfter -lt $now) { $warnings.Add("Assertion expired at $($notOnOrAfter.ToString('u')) (normal for an old capture; a fresh one failing here means clock skew)") }
        if ($notBefore -and $notBefore -gt $now.AddMinutes(5)) { $warnings.Add('Assertion not valid yet: check clock on the app server') }
        if ($ExpectedAudience -and ($audiences -notcontains $ExpectedAudience)) { $warnings.Add("Audience '$($audiences -join ', ')' does not match expected '$ExpectedAudience' (fix the Identifier / Entity ID)") }
        if ($ExpectedReplyUrl -and $recipient -and $recipient -ne $ExpectedReplyUrl) { $warnings.Add("Recipient '$recipient' does not match expected Reply URL '$ExpectedReplyUrl' (AADSTS50011 territory)") }
        if (-not (Get-Text $assertion 'saml:Subject/saml:NameID')) { $warnings.Add('No NameID in the subject') }

        $a = [ordered]@{
            AssertionIssuer = Get-Text $assertion 'saml:Issuer'
            NameId          = Get-Text $assertion 'saml:Subject/saml:NameID'
            NameIdFormat    = Get-Attr $assertion 'saml:Subject/saml:NameID' 'Format'
            Audience        = ($audiences -join ', ')
            Recipient       = $recipient
            NotBeforeUtc    = $notBefore
            NotOnOrAfterUtc = $notOnOrAfter
            AuthnInstantUtc = ConvertTo-UtcDate (Get-Attr $assertion 'saml:AuthnStatement' 'AuthnInstant')
            AuthnContext    = Get-Text $assertion 'saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef'
            SessionIndex    = Get-Attr $assertion 'saml:AuthnStatement' 'SessionIndex'
        }
    }
    elseif (-not $root.SelectSingleNode('saml:EncryptedAssertion', $ns)) {
        $warnings.Add('No assertion in the response')
    }

    # ---- Signatures ----
    $sigNodes = @($doc.SelectNodes('//ds:Signature', $ns))
    $responseSigned  = [bool]$root.SelectSingleNode('ds:Signature', $ns)
    $assertionSigned = [bool]($assertion -and $assertion.SelectSingleNode('ds:Signature', $ns))
    if ($assertion -and -not $assertionSigned -and -not $responseSigned) { $warnings.Add('Nothing is signed: the app must reject this') }

    $sigMethods = @($sigNodes | ForEach-Object { $_.SelectSingleNode('ds:SignedInfo/ds:SignatureMethod', $ns).GetAttribute('Algorithm') } | Sort-Object -Unique)
    $digMethods = @($sigNodes | ForEach-Object { $_.SelectSingleNode('ds:SignedInfo/ds:Reference/ds:DigestMethod', $ns).GetAttribute('Algorithm') } | Sort-Object -Unique)
    if (($sigMethods + $digMethods) -match 'sha1') { $warnings.Add('SHA-1 used for signing: switch the app to SHA-256') }

    $cert = $null
    $certB64 = Get-Text $doc '//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate'
    if ($certB64) {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String(($certB64 -replace '\s', '')))
        if ($cert.NotAfter.ToUniversalTime() -lt $now) { $warnings.Add("Signing certificate expired on $($cert.NotAfter.ToString('yyyy-MM-dd'))") }
        if ($TrustedThumbprint -and $cert.Thumbprint -ne ($TrustedThumbprint -replace '[\s:]', '').ToUpperInvariant()) {
            $warnings.Add("Signed with certificate $($cert.Thumbprint), not the trusted $TrustedThumbprint (app has the wrong or an old certificate)")
        }
    }

    $sigCheck = 'Not checked'
    if ($VerifySignature) {
        if (-not $cert) { $sigCheck = 'No certificate in the message to verify with' }
        else {
            $results = foreach ($s in $sigNodes) {
                $signed = New-Object System.Security.Cryptography.Xml.SignedXml($s.ParentNode -as [System.Xml.XmlElement])
                $signed.LoadXml($s)
                $where = $s.ParentNode.LocalName
                if ($signed.CheckSignature($cert, $true)) { "$where signature valid" } else { "$where signature INVALID" }
            }
            $sigCheck = $results -join '; '
            if ($sigCheck -match 'INVALID') { $warnings.Add('Signature check failed: the message was altered or signed with a different key') }
        }
    }

    $out = [ordered]@{
        MessageType       = 'Response (identity provider -> app)'
        Status            = (($statusCode, $subStatus | Where-Object { $_ } | ForEach-Object { ($_ -split ':')[-1] }) -join ' / ')
        StatusMessage     = $statusMsg
        Destination       = $root.GetAttribute('Destination')
        Issuer            = Get-Text $root 'saml:Issuer'
        InResponseTo      = $root.GetAttribute('InResponseTo')
        IssueInstantUtc   = ConvertTo-UtcDate $root.GetAttribute('IssueInstant')
    }
    if ($a) { foreach ($k in $a.Keys) { $out[$k] = $a[$k] } }
    $out['Claims']           = [PSCustomObject]$claims
    $out['ResponseSigned']   = $responseSigned
    $out['AssertionSigned']  = $assertionSigned
    $out['SignatureMethod']  = ($sigMethods | ForEach-Object { ($_ -split '#')[-1] }) -join ', '
    $out['DigestMethod']     = ($digMethods | ForEach-Object { ($_ -split '#')[-1] }) -join ', '
    $out['CertThumbprint']   = if ($cert) { $cert.Thumbprint } else { $null }
    $out['CertSubject']      = if ($cert) { $cert.Subject } else { $null }
    $out['CertExpires']      = if ($cert) { $cert.NotAfter } else { $null }
    $out['SignatureCheck']   = $sigCheck
    $out['Warnings']         = $warnings -join '; '
    [PSCustomObject]$out
}
