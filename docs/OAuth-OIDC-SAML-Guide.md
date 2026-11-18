# OAuth 2.0, OpenID Connect and SAML: my working notes

These are the notes I keep for troubleshooting sign-in and app integration problems in Microsoft Entra ID. The scripts in `Identity-Protocols` and `Entra-ID-Governance` are built around them.

## The three protocols in one table

| | OAuth 2.0 | OpenID Connect (OIDC) | SAML 2.0 |
|---|---|---|---|
| What it's for | **Authorisation**: letting an app call an API | **Authentication**: proving who the user is (built on top of OAuth 2.0) | **Authentication** (and attributes) for web SSO |
| What you get | Access token (+ refresh token) | ID token (+ OAuth tokens) | SAML assertion (signed XML) |
| Format | JWT in Entra ID (format isn't set by the spec) | Always a JWT | XML |
| Typical use | APIs, Microsoft Graph, daemons | Modern web, SPA and mobile sign-in | Older or enterprise SaaS (Salesforce, ServiceNow, Workday...) |
| Where in Entra | App registrations > API permissions | App registrations > Authentication | Enterprise applications > Single sign-on > SAML |

Rule of thumb: **ID tokens are for the app, access tokens are for the API.** An app should never send an ID token to an API, and should never try to read an access token meant for someone else's API (Graph tokens in particular).

## OAuth 2.0 flows

| Flow | Who uses it | Use it? |
|---|---|---|
| Authorisation code + PKCE | Web apps, SPAs, mobile and desktop apps signing a user in | **Yes**, the default for anything with a user |
| Client credentials | Daemons, scripts, back-end services (no user) | **Yes**, with a certificate, managed identity or federated credential rather than a secret |
| On-behalf-of (OBO) | An API calling another API as the signed-in user | Yes, for middle-tier APIs |
| Device code | Devices with no browser or keyboard (Teams Rooms, CLI tools) | Only where needed. It's abused for **device code phishing**; block it with the Conditional Access "Authentication flows" condition for everyone else |
| Implicit | Old SPAs (tokens returned in the URL) | **No.** Replaced by auth code + PKCE |
| ROPC (password grant) | Legacy apps that post the password directly | **No.** No MFA, no CA prompts, a favourite of password spray |

How to spot them: `Get-EntraAppRegistrationSecurityReport.ps1` flags apps with implicit or public client flows switched on, and `SC-200-Threat-Hunting/Identity/device_code_and_ropc_signins.kql` shows who actually uses device code and ROPC.

## Token claims worth knowing

| Claim | Meaning | Why it matters |
|---|---|---|
| `aud` | Who the token is for (the API) | Wrong audience = the API returns 401 |
| `iss` | Who issued it (`sts.windows.net/{tid}/` is v1, `login.microsoftonline.com/{tid}/v2.0` is v2) | APIs must validate it |
| `tid` | Tenant ID | Multi-tenant apps must check it |
| `oid` | The user's or app's object ID | The stable ID to key on, not the UPN |
| `scp` | Delegated permissions (user + app) | Missing scope = the app wasn't granted that permission |
| `roles` | Application permissions or app roles | App-only tokens carry `roles`, never `scp` |
| `appid` / `azp` | The client app that requested the token | Who's calling |
| `amr` | How the user authenticated (`pwd`, `mfa`, `rsa`...) | No `mfa` = single-factor sign-in |
| `acrs` | Conditional Access authentication context satisfied | Step-up checks |
| `idtyp` | `app` or `user` (if the optional claim is enabled) | Tells app-only from delegated |
| `exp` / `nbf` / `iat` | Expiry, not before, issued at (Unix time) | Clock skew and expired-token errors |

Decode a token with `Identity-Protocols/ConvertFrom-JwtToken.ps1` (add `-VerifySignature` to check it against the issuer's keys). Microsoft Graph access tokens can't be verified by anyone but Graph, by design.

## SAML terms, mapped to the Entra ID portal

| SAML term | Entra ID portal label | Common mistake |
|---|---|---|
| Entity ID / Audience | Identifier (Entity ID) | Doesn't match what the app sends: AADSTS700016 |
| Assertion Consumer Service (ACS) URL | Reply URL | Doesn't match the AuthnRequest: AADSTS50011 |
| NameID | Unique User Identifier (Name ID) | App expects email, gets UPN (or the reverse) |
| Attributes / claims | Attributes & Claims | Missing or misnamed claim the app needs for roles |
| Signing certificate | SAML Certificates | Expired, or rolled in Entra but not uploaded to the app |
| RequestedAuthnContext | (comes from the app) | App demands a sign-in method the user didn't use: AADSTS75011 |
| Sign-on URL / RelayState | Sign on URL / Relay State | Wrong deep link after sign-in |

Troubleshoot with `Identity-Protocols/ConvertFrom-SamlResponse.ps1` (paste the SAMLResponse from the browser) and `Identity-Protocols/Test-SamlFederationMetadata.ps1` (check the certificates on either side). `Entra-ID-Governance/Get-EntraSsoAppReport.ps1` finds SAML certificates that are about to expire across the tenant.

## Error codes I see most

| Code | What it means | Where to look |
|---|---|---|
| AADSTS50011 | Reply URL in the request doesn't match the app registration | Redirect URIs / Reply URL |
| AADSTS700016 | Application (or SAML Identifier) not found in the tenant | Client ID, Entity ID, wrong tenant |
| AADSTS65001 | User or admin hasn't consented to the permissions | API permissions, admin consent |
| AADSTS50105 | User isn't assigned to the app ("assignment required" is on) | Enterprise app > Users and groups |
| AADSTS7000215 | Invalid client secret | Secret expired or the value (not the ID) wasn't copied |
| AADSTS50076 | MFA required by policy | Conditional Access |
| AADSTS50079 | User needs to register for MFA | Authentication methods |
| AADSTS53003 | Blocked by Conditional Access | Sign-in log > Conditional Access tab |
| AADSTS50126 | Wrong username or password | Sign-in logs (lots of these = password spray) |
| AADSTS75011 | SAML RequestedAuthnContext doesn't match how the user signed in | App's SAML request settings |

The sign-in logs in Entra ID always show the code, the app, the Conditional Access result and the authentication details. Start there.

## Safe handling

- Tokens and SAML assertions are bearer credentials until they expire. Decode them locally, never in online decoders, and delete captures afterwards.
- Prefer certificates, managed identities and workload identity federation over client secrets.
- Keep redirect URIs exact, HTTPS, and on domains you control.
