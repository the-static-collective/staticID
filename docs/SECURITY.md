# STATIC ID · Security and authority boundaries

- **Authentication:** Signature+issuer+audience+nonce validated for signed OIDC ID token. Access token validated separately; mandatory OAuth `client_id` matches the application registration.
- **Authorization:** Exact pinned Supabase `auth.users.id` UUID is the only owner in 001. Email verified during callback. Roles for other users are **not implemented**, not inferred from email or editable metadata.
- **Original Proton enrollment:** Remains within the existing HUMKIN Supabase Edge Function. STATIC ID does **not** see a six-digit code or store a TOTP seed.
- **Sessions:** App-specific AES-256-GCM `__Host-` HttpOnly Secure SameSite=Lax cookies; origin-bound encrypted payload, maximum 1 hour, bounded by access token expiry. The protected handler re-verifies the signed access token and owner UUID. Session does not auto-refresh. Cookies do not contain refresh tokens.
- **CSRF:** Owner mutation requests MUST include exact same-origin `Origin` header. The app's own legacy token path is independent and also requires hardening before wider multiuser access.
- **Logout:** Clears this application's cookie. It does **not** revoke the central Supabase session or log out of other apps.
- **State changes:** No production Supabase Auth settings, HUMKIN tables, Neon data, or Cloudflare secrets are changed by building this repo.
- **Key management:** The app cookie AES key must be independent from the OAuth client secret, R2 keys, Neon credentials, and the Fileport emergency admin token. Never reuse or expose secrets across apps. To rotate, replace the server secret; old cookies will fail authentication.
- **Authorization trace:** A successful signature alone never grants admission. Each application's resource permissions remain separate; no implicit access to Neon or Supabase service role.
- **Operational security:** Rate-limit auth start/callback at Cloudflare and retain HUMKIN's existing TOTP throttling; monitor abnormal login, timeout, and untrusted origin failures without logging credentials.
- **Known missing features:** server-side session invalidation/revocation, automatic token refresh, multi-user grants, auditable consent receipts in STATIC ID, session anomaly alerts, passkeys. Do not claim production-grade SSO until an independently verified live test exists.

Explicitly keep `auth.abundent.org` as a *future* branding target, not a required DNS hostname in this first stage.
