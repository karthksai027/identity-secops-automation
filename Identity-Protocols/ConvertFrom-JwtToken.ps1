<#
.SYNOPSIS
    Decodes an OAuth 2.0 access token or OpenID Connect ID token (JWT), explains the claims that matter, and can verify its signature against the issuer's published keys.

.DESCRIPTION
    When an API returns 401 or an app says "insufficient privileges", the answer is usually in
    the token. This script splits the JWT, decodes the header and payload, and pulls out the
    claims an identity engineer actually looks at:

      Who      : upn / preferred_username, oid, tid, idtyp (user or app)
      For what : aud (which API the token is for), scp (delegated scopes) or roles (app roles)
      How      : amr (pwd, mfa, rsa, fido...), acr, auth_time, appid / azp (the client app)
      When     : iat, nbf, exp, and how long is left
      Version  : ver 1.0 (sts.windows.net) or 2.0 (login.microsoftonline.com/.../v2.0)

    It also raises plain-English warnings: expired, not yet valid, no MFA in amr, app-only token
    with no roles, delegated token with no scopes, signed with "none".

    With -VerifySignature it reads the issuer's OpenID Connect discovery document, downloads the
    signing keys (JWKS), finds the key by kid, and checks the RS256/RS384/RS512 signature.
    Use -JwksPath to verify against a saved JWKS file (offline or air-gapped).

    Note: Microsoft Graph access tokens are deliberately not verifiable by anyone but Graph
    (they carry a nonce in the header). A failed check on a Graph token is expected.

    Tokens are bearer credentials. Decode them on your own machine and don't paste live tokens
    into online decoders. The script never sends the token anywhere.

.PARAMETER Token
    The JWT (with or without a leading "Bearer "). Accepts pipeline input.

.PARAMETER VerifySignature
    Verify the signature using the issuer's published keys.

.PARAMETER JwksPath
    Path to a JWKS JSON file to verify against instead of downloading the keys.

.PARAMETER Raw
    Also return the full decoded header and payload.

.EXAMPLE
    Get-Clipboard | .\ConvertFrom-JwtToken.ps1
    Decodes a token you copied from browser developer tools or an API client.

.EXAMPLE
    .\ConvertFrom-JwtToken.ps1 -Token $idToken -VerifySignature

.EXAMPLE
    .\ConvertFrom-JwtToken.ps1 -Token $token -VerifySignature -JwksPath .\keys.json -Raw

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : none (works on Windows PowerShell 5.1 and PowerShell 7)
    Network     : only with -VerifySignature and no -JwksPath (HTTPS to the token issuer)
    Permissions : none

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [ValidateNotNullOrEmpty()]
    [string]$Token,

    [switch]$VerifySignature,

    [string]$JwksPath,

    [switch]$Raw
)

begin {
    $ErrorActionPreference = 'Stop'

    function ConvertFrom-Base64Url {
        param([Parameter(Mandatory)][string]$Value)
        $s = $Value.Replace('-', '+').Replace('_', '/')
        switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } 1 { throw 'Invalid base64url length.' } }
        [Convert]::FromBase64String($s)
    }

    function ConvertFrom-UnixTime {
        param($Seconds)
        if ($null -eq $Seconds -or "$Seconds" -eq '') { return $null }
        [DateTimeOffset]::FromUnixTimeSeconds([long]$Seconds).UtcDateTime
    }

    function Get-JsonWebKeySet {
        param([string]$Issuer, [string]$KeySetPath)
        if ($KeySetPath) { return (Get-Content -Path $KeySetPath -Raw | ConvertFrom-Json) }
        if (-not $Issuer -or $Issuer -notmatch '^https://') { throw "Token issuer '$Issuer' is not an https URL; use -JwksPath." }
        # v1 Entra tokens use https://sts.windows.net/{tid}/ ; discovery lives on login.microsoftonline.com
        $discoBase = if ($Issuer -match '^https://sts\.windows\.net/([^/]+)/?$') { "https://login.microsoftonline.com/$($Matches[1])" } else { $Issuer.TrimEnd('/') }
        $disco = Invoke-RestMethod -Uri "$discoBase/.well-known/openid-configuration" -UseBasicParsing
        Invoke-RestMethod -Uri $disco.jwks_uri -UseBasicParsing
    }

    $amrMeaning = @{
        pwd = 'password'; mfa = 'multi-factor'; rsa = 'certificate / Windows Hello / FIDO2 key'; otp = 'one-time code';
        sms = 'SMS'; fido = 'FIDO2'; wia = 'Windows integrated auth'; ngcmfa = 'Windows Hello MFA'; kba = 'knowledge-based'
    }
}

process {
    $jwt = $Token.Trim() -replace '^(?i)bearer\s+', ''
    $parts = $jwt.Split('.')
    if ($parts.Count -eq 5) { throw 'This is an encrypted token (JWE). It can only be read by the API it was issued for.' }
    if ($parts.Count -ne 3) { throw "Not a JWT: expected 3 dot-separated parts, found $($parts.Count)." }

    $header  = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[0])) | ConvertFrom-Json
    $payload = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[1])) | ConvertFrom-Json
    $p = $payload

    $now     = [DateTime]::UtcNow
    $exp     = ConvertFrom-UnixTime $p.exp
    $nbf     = ConvertFrom-UnixTime $p.nbf
    $iat     = ConvertFrom-UnixTime $p.iat
    $amr     = @($p.amr | Where-Object { $_ })
    $scopes  = if ($p.scp) { @("$($p.scp)" -split ' ' | Where-Object { $_ }) } else { @() }
    $roles   = @($p.roles | Where-Object { $_ })
    $hasUser = [bool]($p.upn -or $p.preferred_username -or $p.unique_name -or $p.name)
    $tokenType = if ($p.scp) { 'Access token (delegated, on behalf of a user)' }
                 elseif ($p.idtyp -eq 'app' -or -not $hasUser) { 'Access token (app-only, client credentials)' }
                 else { 'ID token (OpenID Connect)' }

    $warnings = New-Object System.Collections.Generic.List[string]
    if ("$($header.alg)" -eq 'none') { $warnings.Add('alg is "none": the token is unsigned and must never be trusted') }
    if ($exp -and $exp -lt $now) { $warnings.Add("Expired $([int]($now - $exp).TotalMinutes) minute(s) ago") }
    if ($nbf -and $nbf -gt $now.AddMinutes(5)) { $warnings.Add('Not valid yet (nbf is in the future; check clock skew)') }
    if ($hasUser -and $amr.Count -gt 0 -and ($amr -notcontains 'mfa') -and -not ($amr | Where-Object { $_ -in 'rsa', 'fido', 'ngcmfa' })) { $warnings.Add('No MFA in amr: the user signed in with a single factor') }
    if ($tokenType -like 'Access token (app-only*' -and $roles.Count -eq 0) { $warnings.Add('App-only token with no roles: the app has no application permissions on this API') }
    if ($tokenType -like 'Access token (delegated*' -and $scopes.Count -eq 0) { $warnings.Add('Delegated token with no scp: no delegated permissions were granted') }
    if ($header.nonce) { $warnings.Add('Header has a nonce (Microsoft Graph token): third parties cannot verify this signature by design') }

    $sigResult = 'Not checked'
    if ($VerifySignature) {
        try {
            $alg = "$($header.alg)"
            if ($alg -notmatch '^RS(256|384|512)$') { throw "Unsupported algorithm '$alg' (RS256/384/512 only)." }
            $jwks = Get-JsonWebKeySet -Issuer $p.iss -KeySetPath $JwksPath
            $key  = @($jwks.keys) | Where-Object { $_.kid -eq $header.kid } | Select-Object -First 1
            if (-not $key) { throw "No key with kid '$($header.kid)' in the issuer's JWKS." }

            $rsaParams = New-Object System.Security.Cryptography.RSAParameters
            $rsaParams.Modulus  = ConvertFrom-Base64Url $key.n
            $rsaParams.Exponent = ConvertFrom-Base64Url $key.e
            $rsa = [System.Security.Cryptography.RSA]::Create()
            $rsa.ImportParameters($rsaParams)

            $hashName = switch ($alg) { 'RS256' { 'SHA256' } 'RS384' { 'SHA384' } 'RS512' { 'SHA512' } }
            $data = [Text.Encoding]::ASCII.GetBytes("$($parts[0]).$($parts[1])")
            $sig  = ConvertFrom-Base64Url $parts[2]
            $ok = $rsa.VerifyData($data, $sig, [System.Security.Cryptography.HashAlgorithmName]::new($hashName), [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $sigResult = if ($ok) { "Valid ($alg, kid $($header.kid))" } else { 'INVALID: the token was altered or signed with a different key' }
            if (-not $ok) { $warnings.Add('Signature is invalid') }
        }
        catch {
            $sigResult = "Could not verify: $($_.Exception.Message)"
        }
    }

    $result = [PSCustomObject]@{
        TokenType        = $tokenType
        Version          = $p.ver
        Issuer           = $p.iss
        TenantId         = $p.tid
        Audience         = $p.aud
        ClientAppId      = if ($p.appid) { $p.appid } else { $p.azp }
        ClientAppName    = $p.app_displayname
        User             = if ($p.upn) { $p.upn } elseif ($p.preferred_username) { $p.preferred_username } else { $p.unique_name }
        ObjectId         = $p.oid
        Scopes           = ($scopes -join ' ')
        Roles            = ($roles -join ', ')
        AuthMethods      = (($amr | ForEach-Object { if ($amrMeaning.ContainsKey("$_")) { "$_ ($($amrMeaning["$_"]))" } else { "$_" } }) -join ', ')
        AuthContext      = (@($p.acrs) + @($p.acr) | Where-Object { $_ }) -join ', '
        IssuedUtc        = $iat
        NotBeforeUtc     = $nbf
        ExpiresUtc       = $exp
        MinutesLeft      = if ($exp) { [int][math]::Floor(($exp - $now).TotalMinutes) } else { $null }
        Algorithm        = $header.alg
        KeyId            = $header.kid
        Signature        = $sigResult
        Warnings         = $warnings -join '; '
    }
    if ($Raw) {
        $result | Add-Member -NotePropertyName Header -NotePropertyValue $header
        $result | Add-Member -NotePropertyName Payload -NotePropertyValue $payload
    }
    $result
}
