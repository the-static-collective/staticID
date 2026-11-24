# STATIC ID 004 · Village Gate

A public, static, credential-free directory at the intended custom domain `id.abundent.org`. It is deliberately **not** a new OAuth provider, a session aggregator, a protected operator console, or a site that collects passwords. Each app's own server enforces authorization. The Gate's public projection of registry/apps.json excludes identity provider internals, callback URLs, operational receipts and recovery details; only eligible app names, public origins, a fixed allowlist of user-facing capabilities and launch links are emitted. Candidate and retired entries are excluded. Labels are declarations, not live health or actual grants. The complete local operator registry remains STATIC ID 003.

## Deploy without a subscription

1. In this public GitHub repo's Settings → Pages, select **GitHub Actions** as the build/deploy source. No secrets required. Run the Publish Village Gate workflow on main. Confirm the actual Pages site is published at the URL reported by the deploy job.
2. Before DNS cutover, verify domain ownership with GitHub if not already verified, and in the same repo's Settings → Pages, assign custom domain `id.abundent.org`. Do not change HUMKIN's Pages custom domain, existing consent host, Supabase Site URL, or OAuth registration. GitHub Actions publishing does not automatically set a custom domain from CNAME files.
3. Porkbun is the registrar; Cloudflare is the live authoritative DNS. Porkbun's Cloudflare connector has confirmed the intended dry run for a new DNS-only CNAME `id.abundent.org → the-static-collective.github.io`. Re-read the exact record before creating it; do not change wildcard, apex, mail, nameservers or other applications. Only add DNS after the GitHub Pages domain is bound and under the owner's control to avoid dangling-domain takeover risk. Do not buy Porkbun hosting; no active hosting exists on this domain.
4. Confirm HTTPS at the custom domain and enforce HTTPS in GitHub Pages once certificate issuance permits. Verify the page and its two app links; no change to Fileport's OAuth client or HUMKIN consent is required.
5. Rollback if needed: remove only the newly created exact CNAME after coordinating with the owner; leave all other DNS and apps unchanged.

## Development

`npm run gate:build` produces the three dedicated static files in gate-dist/. `npm run check` includes public projection, markup and build tests. No npm runtime dependencies, CDN scripts, analytics, cross-origin login probing, localStorage or cookies. A CSS-only illustration is part of the page. Actual protected dashboards and delegated access need a separately reviewed server-side adapter and are out of scope here.
