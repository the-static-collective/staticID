# FILEPORT 003 · STATIC ID first application adapter

**Target:** `the-static-collective/fileport` (Neon-first). **Current:** ready-to-integrate library; no Fileport production login switched on from this repo alone.

## Intended operator experience

1. Visit `https://fileport.abundent.org` and choose **Unlock with STATIC ID**.
2. Browser redirects to the existing Supabase OAuth 2.1 server, which uses the **HUMKIN consent and existing Proton login** when sign-in is needed.
3. User reviews permission for Fileport, approves, and returns to Fileport over HTTPS.
4. Fileport validates signed ID/access tokens, requires the exact previously approved **Supabase owner subject UUID**, and creates a short-lived HttpOnly application cookie.
5. Owner APIs check that cookie plus the app's own authorization decision. Invited recipients continue to use ordinary Fileport share links **without any login**.

No Fileport TOTP seed, no new Proton QR code, no new Supabase project.

## Required one-time steps, in order

1. Verify the existing HUMKIN Proton sign-in works and note its Supabase project (do not migrate anyone).
2. In that Supabase project's **Authentication → OAuth Server**, confirm OAuth is enabled, the consent path is the existing HUMKIN `/oauth/consent/`, and the Site URL correctly serves that path. **Do not change the Site URL without assessing other dependent apps.**
3. Confirm JWT signing supports **ES256 or RS256**. The `openid` ID-token flow requires an asymmetric key. Coordinate any key changes with HUMKIN; do not rotate blindly.
4. Register **Fileport** as a **Confidential** OAuth application with exact redirect URI `https://fileport.abundent.org/api/static-id/callback` and code+PKCE.
5. Obtain the **verified current Supabase auth.users.id UUID** of the existing owner account, not an email/guess or a new identity.
6. Configure Fileport Cloudflare encrypted secrets / server variables:

| Name | Value / nature |
| --- | --- |
| `STATIC_ID_ISSUER` | `https://<existing-humkin-supabase-ref>.supabase.co/auth/v1` (server setting) |
| `STATIC_ID_APP_ORIGIN` | `https://fileport.abundent.org` (server setting) |
| `STATIC_ID_CLIENT_ID` | ID from *Fileport* OAuth registration (server setting) |
| `STATIC_ID_CLIENT_SECRET` | Confidential OAuth secret (**encrypted**) |
| `STATIC_ID_OWNER_SUB` | Exact owner account UUID (**encrypted**) |
| `STATIC_ID_COOKIE_KEY` | Unique 32-byte base64url encryption key (**encrypted**) |

Generation of the last value should be built into the future onboarding UI; for the first deployment, Cloudflare secret management remains a one-time operational step. Do not paste any value into chat or GitHub.

7. Deploy a Fileport PR importing `@the-static-collective/static-id/cloudflare`, route `/api/static-id/*` **before** the existing API-config health check, and change owner authorization to **STATIC ID OR the existing emergency admin token**, never to any unverified user.
8. Modify browser owner requests to send same-origin cookies; present STATIC ID as the primary login button and the existing admin token only through an explicit recovery panel. Keep invitation cookies separate.
9. Test unconfigured, invalid JWT, another account, wrong client, expired token, no Origin for mutations, request replay, and logout. Verify a real account sign-in through a test Fileport deployment *before* merging / switching the main UI.

**Important:** Cloudflare Pages Functions must support `nodejs_compat` for Fileport's existing AWS SDK; STATIC ID's library itself is WebCrypto and dependency-free.

## Fileport owner API integration concept

```js
import {handleStaticIdRequest,requireStaticIdOwner} from "@the-static-collective/static-id/cloudflare";

// Place before the normal /api/ request handler:
const identityResponse = await handleStaticIdRequest(request, env);
if (identityResponse) return identityResponse;

// Within the owner handler:
const verifiedStaticOwner = await requireStaticIdOwner(request, env);
const emergencyOperator = await adminAuthorized(request, env);
if (!verifiedStaticOwner && !emergencyOperator) return error("Owner login required",401);
```

Existing `FILEPORT_ADMIN_TOKEN` is **not bound to a person by copying its plaintext into Supabase**. It's a separate Cloudflare-held break-glass secret. Identity binding uses the exact Supabase `sub` UUID. Never grant roles on the basis of a user-editable email, display name, or `user_metadata`.

## Cross-service architecture

- Identity and proof of sign-in: Supabase Auth (existing).
- Local app authorization: each application / its own database (Neon for Fileport/Freeport).
- Proton Authenticator: existing owner enrollment, only at the central identity entry point.
- STATIC ID: reusable adapter and protocol contract, not a new password/OTP database.
- Cloudflare: app runtime and protected cookie termination; no shared subdomain-wide cookie.

## Not solved by 001

Long-lived owner sessions, 2FA assurance `aal2`, per-project delegation, decentralized key identity, backend-to-backend machine auth, fresh token revocation on every read, and simultaneous logout across applications. These need separate work and real-world validation.
