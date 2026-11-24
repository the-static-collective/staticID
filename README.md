# STATIC ID · One identity, independent applications

STATIC ID is the Static Collective's **reusable authentication adapter**, built around the **existing HUMKIN Proton Authenticator → Supabase Auth** identity. Apps do **not** get their own TOTP seeds and do **not** copy HUMKIN's service-role key. A single identity may have different, explicitly granted roles across independently owned applications and databases.

**Status:** Fileport is the first live OAuth pilot; the owner reported successful sign-in. Protected operations, logout and recovery still require live verification. See [STATIC ID 002 application onboarding](docs/ONBOARDING.md) for connecting additional applications without recreating the existing identity.

## Source of truth: existing HUMKIN login

See [HUMKIN owner enrollment](https://github.com/the-static-collective/HUMKIN/blob/main/docs/HUMKIN-PROTON-AUTHENTICATOR.md) and [HUMKIN OAuth consent](https://github.com/the-static-collective/HUMKIN/blob/main/docs/TOWER-MCP-OAUTH-012.md).

- The **HUMKIN Radio** entry in Proton Authenticator is already handled by the existing `humkin-proton-login` Edge Function; this component does **not** ask to pair again.
- HUMKIN's TOTP is currently a **single login factor**, not native Supabase MFA `aal2`. Do not claim it is two independent factors.
- The existing Supabase project owns the accounts, signed sessions, and OAuth authorization server.
- The consent page, OAuth server enablement, app registration, and asymmetric signing status need **independent live verification** before any production login claims.

## New package

No npm runtime dependencies. Node 22+ for tests.

- `src/oidc.mjs`: random PKCE verifier/state/nonce, OAuth code exchange, Web Crypto **ES256/RS256** JWT validation against trusted issuer JWKS, strict audience/nonce/expiry checks, pinned owner ID, AES-256-GCM sealed cookies.
- `src/cloudflare.mjs`: Cloudflare Pages/Workers same-origin login/callback/status/logout routes; `requireStaticIdOwner` for owner-only APIs with CSRF origin checks for writes.
- `tests/identity.test.mjs`: cryptographically signed synthetic ID/access JWTs, OAuth flow, token refusal, wrong account, wrong app, cookie tampering, wrong origin.
- `docs/FILEPORT-ADAPTER.md`: exact zero-downtime Fileport integration and setup steps.
- `docs/SECURITY.md`: non-claims and future multi-user work.

### API

```js
import { handleStaticIdRequest, requireStaticIdOwner }
  from "@the-static-collective/static-id/cloudflare";

// In a Cloudflare Pages catch-all, before main API routing:
const auth = await handleStaticIdRequest(request, env);
if (auth) return auth;

// In an owner-only API:
const owner = await requireStaticIdOwner(request, env);
if (!owner) return new Response("Forbidden", {status: 403});
```

Use `/api/static-id/login` to start an OAuth redirect, `/api/static-id/callback` for the exact registered return URL, `/api/static-id/status` to check login, and `POST /api/static-id/logout` from the same origin.

**Each app registers a separate OAuth client and pins its owner subject.** The browser sees no OAuth client secret, no private database string, no Proton seed, no Supabase service-role key, and no upstream JWT stored in readable JS storage. Protected app requests are authorized server-side.

## One-time identity infrastructure

The identity provider is the **existing Supabase Auth project** already used by HUMKIN. Enable its OAuth 2.1 server, reuse the existing verified HUMKIN consent page, and register Fileport as its own confidential OAuth client **only when existing HUMKIN login and consent have been tested**. Don't change HUMKIN's auth Site URL or JWT signing keys blindly. For the first Fileport client, registered redirect URL:

`https://fileport.abundent.org/api/static-id/callback`

For Fileport's Cloudflare runtime, **encrypted** secrets/settings are listed in [FILEPORT-ADAPTER](docs/FILEPORT-ADAPTER.md). Current `FILEPORT_ADMIN_TOKEN` remains a separate emergency recovery path until the new login is tested and intentionally adopted.

## Release constraints

This pilot intentionally caps application sessions at **one hour**, bounded by the upstream Supabase access token lifetime. It has **no silent refresh, centralized logout propagation, per-user invites, multi-tenant roles, SCIM, or portable session across domains**. The browser obtains an independent secure cookie per app through the common IdP. Cross-app SSO is a *redirect-based login flow*, not a shared cookie across all subdomains.

For longer lived sessions: add a server-side refresh-token store, rotation handling and revocation, then separately audit it; **never** put long-lived refresh tokens in page JavaScript or a public URL.

The source repository can be public because **no secrets are committed**, but deployed secrets and security configuration must be private.

Official references: [Supabase OAuth 2.1 overview](https://supabase.com/docs/guides/auth/oauth-server), [OAuth flows](https://supabase.com/docs/guides/auth/oauth-server/oauth-flows), [token security](https://supabase.com/docs/guides/auth/oauth-server/token-security).

## Testing

`npm run check` runs signing and negative-path tests. Tests use generated synthetic keys and make **no live service changes**.

## Application onboarding

`npm run onboard -- plan PROJECT https://APP.abundent.org App Name` previews a new app registration. `apply` performs explicitly confirmed local provisioning and `probe` checks anonymous access. See [the complete onboarding guide](docs/ONBOARDING.md). No existing application is modified automatically.

## Application registry

`npm run registry -- list` reports identity relationships, declared capabilities and outstanding evidence checks. See [STATIC ID 003](docs/REGISTRY.md). This inventory does not grant access or store credentials.

## Village Gate

`npm run gate:build` creates a public, credential-free app launcher from the registry. See [STATIC ID 004 — Village Gate](docs/VILLAGE-GATE.md) for deployment and DNS setup. The Gate does not grant or manage permissions.
