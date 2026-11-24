# STATIC ID 003 · Application Registry

A versioned inventory of identity relationships, declared application capabilities and narrowly scoped evidence. The registry is **descriptive**, never an OAuth provider, role grant, access-control list or secret store. Runtime authorization remains with each independent app.

## Commands

Node.js 22+, no additional packages. From this repository:

- `npm run registry -- list` — offline fleet report.
- `npm run registry -- show fileport` — Fileport's exact callback, declared capabilities, check history summary and outstanding checks.
- `npm run registry -- probe fileport` — one anonymous HTTPS status request; no browser cookies, client secret or OAuth credentials. Stores a local, metadata-only receipt. A passing anonymous response does not prove protected endpoints are secure.
- `npm run registry -- attest fileport protected-read pass` — interactively record a personally observed check. This is an operator attestation, not automated verification. Supported checks: anonymous-denied, owner-login, protected-read, logout, recovery. Results: pass, fail, hold.

The registry manifest is `registry/apps.json`. Add an app only after its exact origin, Pages project and capabilities are reviewed. A candidate is not a connected app; retired apps are not probed. No wildcard domains. All current capabilities are declarations, not permission to operate. Extend the fixed capability vocabulary through code review rather than accepting arbitrary strings or implied privileges.

## Evidence and limits

Initial Fileport owner-login observation is a user report dated 2026-11-24. HUMKIN is the declared consent host. Fileport protected-read, logout, recovery and anonymous-denied checks start open. There is no claim of independent login verification.

New observations stay in ignored `.static-id/registry-receipts/`. Only the app ID, check, method, result and UTC date are stored, not page content, user IDs, client IDs, cookies or tokens. Receipts use canonical content hashes for local integrity; hashes are not signatures or attestations of truth. Contradictory same-day observations HOLD; the latest date is used, and passes older than 30 days are flagged stale. No automatic production promotion, revocation, registration, role changes, deployment or polling occurs. The registry works without FISHBONE or TinyFish. Its public probe is not a network sandbox; run it only for domains you control. A real signed-in protected-operation test must be done on the user's browser.

## Pilot verification

For Fileport, open the existing owner interface using STATIC ID, perform a harmless protected read, then log out and check the status endpoint. Test the established emergency recovery path without changing or deleting the token. Record each result only after actually observing it. Do not expose credentials in a receipt or conversation.

STATIC ID 002 remains the provisioning workflow; STATIC ID 003 records the relationship and evidence. No new application has been connected or existing identity configuration changed by this feature.
