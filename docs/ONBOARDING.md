# STATIC ID 002 · Application onboarding

Fileport is the first live pilot. The owner reported successful login after the Cloudflare-compatible token exchange and JWKS fixes. This is user-reported success, not an independent protected-operation audit.

## Connect another server-side application

1. Review the application's adapter and pin the current tested STATIC ID release. Use `handleStaticIdRequest` before normal API routing and `requireStaticIdOwner` on protected operations. Keep existing recovery, app permissions and invite flows unchanged. The app must already have its custom domain attached to its Cloudflare Pages project.
2. Run `npm run onboard -- plan PROJECT https://APP.abundent.org App Name`. This is entirely offline. Review the exact callback and target.
3. In the existing pantry-gate Supabase project, create one confidential OAuth client in Authentication → OAuth Apps, with the plan's exact callback and default Basic client authentication. Keep dynamic registration disabled. Reuse the verified existing owner UID. Never recreate the Proton enrollment, change global redirects, or rotate signing keys.
4. Run `npm run onboard -- apply PROJECT https://APP.abundent.org App Name` on your own computer with Node 22+. Use the Cloudflare account ID and an account-scoped Cloudflare Pages Edit API token. The CLI asks for values in hidden terminal prompts, generates an independent cookie encryption key, checks the named production project and its exact attached domain, refuses existing STATIC ID secret bindings, and asks for explicit confirmation before a targeted PATCH. Only four new encrypted secret bindings and missing nonsecret issuer/origin values are written. Unrelated bindings and preview are untouched. Secrets are not intentionally written to disk, printed, or committed. Provider tooling and terminal/OS security remain the user's responsibility. A failed/ambiguous write is a HOLD: inspect the dashboard, do not blindly retry. An existing partial configuration needs a separate reviewed recovery procedure.
5. Deploy the reviewed application code through its existing pipeline. Ensure its Wrangler configuration agrees with the two nonsecret routing values. Run `npm run onboard -- probe PROJECT https://APP.abundent.org App Name`. An anonymous-denied result proves only that an unauthenticated caller isn't reported as authenticated.
6. In a browser, test login with the existing Proton factor, check authenticated status, exercise a protected read, logout and confirm status returns false. Test recovery without deleting the existing recovery secret. Wrong account, expired/replayed callback and CSRF remain mandatory synthetic tests; perform live negative checks where safe.

## Boundaries

No production changes were made by building this tool. It is a local, explicit, first-install workflow for server-backed Cloudflare Pages apps only. The user still registers the client manually; a future opt-in admin registration adapter would require a highly privileged Supabase secret, which we deliberately don't ask for in this version. No shared browser cookie, permanent refresh token, cross-app logout, or multi-user delegation. No dependency on FISHBONE or TinyFish. Cloudflare API writes follow the targeted Pages encrypted-binding PATCH used by Wrangler, with metadata verification; synthetic fixtures cover the request shape but live API writes have not yet been exercised. A scoped Cloudflare API token is still an account capability: keep it local and revoke when no longer needed.

## Sources

- https://supabase.com/docs/guides/auth/oauth-server/getting-started
- https://developers.cloudflare.com/workers/wrangler/commands/pages/
- https://github.com/cloudflare/workers-sdk/blob/main/packages/wrangler/src/pages/secret/index.ts

## Pilot registry

| App | Origin | Status |
| --- | --- | --- |
| HUMKIN | https://humkin.abundent.org | Existing identity and consent host |
| Fileport | https://fileport.abundent.org | Owner-reported successful OAuth login; protected operations/logout/recovery verification still open |
| Future apps | Per exact registered domain | Not connected |
