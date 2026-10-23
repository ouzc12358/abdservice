# Secure Cloudflare Worker deployment

This deployment keeps the upstream tunnel engine in `_worker.js` and places `src/index.js` in front of it as a security gateway.

The active deployment target is the neutral, independent Worker `worker-20261023` at `https://worker-20261023.fatdot.workers.dev`. It uses its own KV namespace, rate-limit namespaces, Analytics Engine dataset, and encrypted secrets. The earlier Worker and its data are not modified by this configuration.

Do not paste `_worker.js` directly into the deployed Worker. It cannot read the existing `enc:v1:` encrypted KV without `src/security.js`. Always deploy `src/index.js` using `wrangler.jsonc`; the upstream `wrangler.toml` is not the production configuration. Do not regenerate `DATA_ENCRYPTION_KEY` when updating code. A successful upload is not acceptance: login, authenticated config, subscription, and a real tunnel request must be checked separately.

## Security model

- `ADMIN`, `KEY`, `SESSION_SECRET`, and `DATA_ENCRYPTION_KEY` are Cloudflare encrypted secrets.
- Browser administration uses an HMAC-SHA256, 24-hour, user-agent-bound session instead of the upstream deterministic MD5 browser cookie.
- Sensitive KV values are encrypted again with AES-256-GCM and key-specific authenticated data. Existing plaintext values are migrated after their first successful read.
- Login and admin requests use native Cloudflare Rate Limiting bindings.
- State-changing admin calls require an exact same-origin `Origin` header.
- Workers Observability redacts query strings so subscription tokens do not appear in invocation URLs.
- Upstream IP/URL logging is disabled by default with `OFF_LOG=true`.

## Commands

```sh
npm install
npm test
npx wrangler types
npm run deploy:dry
npx wrangler whoami
npm run deploy
```

The four required secrets must be created before the final deployment. Never commit `.dev.vars`, `.env`, or a secrets JSON file.

On macOS, `scripts/generate-deploy-secrets.mjs` creates a mode-0600 temporary secrets file and backs up all four generated values in Login Keychain under service `worker-20261023.cloudflare`. The deployment file must be removed immediately after the first upload; later deployments preserve the Cloudflare Secrets with `--keep-vars`.

## GitHub automatic deployment

`.github/workflows/deploy-worker.yml` is the deployment bridge. It deploys the checked-in secure wrapper on pushes to `main`; every six hours it resolves the current `cmliu/edgetunnel` `main` branch to an immutable commit SHA, refreshes only `_worker.js` from that exact commit, then deploys the wrapper with the existing KV, secret, rate-limit, and Analytics Engine bindings. Manual dispatch can choose either source. It intentionally does not use Cloudflare's direct source upload integration: that integration would deploy the raw `_worker.js` and bypass the security wrapper, KV encryption layer, and rate-limit bindings.

Scheduled runs first require the existing production `/login` endpoint to pass the public smoke test. This prevents an account suspension or edge/runtime incident from causing repeated unattended deployments. A manual dispatch skips that baseline gate so a reviewed recovery build can still be deployed.

Before enabling the workflow in GitHub, add:

- Repository secret `CLOUDFLARE_API_TOKEN`: an account-scoped API token with `Workers Scripts: Edit`, `Workers KV Storage: Edit`, and `Account Settings: Read` only. Do not grant DNS, Routes, Pages, Access, Billing, or global account-admin permissions; do not use the Wrangler OAuth token or a global API key in GitHub.
- Repository variable `CLOUDFLARE_ACCOUNT_ID`: the Cloudflare account ID for this Worker.
- Repository variable `AUTO_DEPLOY_ENABLED`: keep it unset or set to `false` until the new `worker-20261023` endpoint passes a manual production smoke test; set it to `true` only afterward. Manual workflow dispatch remains available for a reviewed recovery build.

The workflow never stores or prints Worker secrets. It runs `npm test`, performs a Wrangler dry-run, records the immutable upstream commit and SHA-256 in the job log/deployment message, deploys, and then checks `/login` for a successful response plus the security headers. A failed smoke check leaves the GitHub run failed for review; it does not rewrite KV data.

If an upstream update breaks the public smoke check, the workflow automatically rolls traffic back to the previous 100% version. The failed update remains visible in the GitHub run and Cloudflare deployment history for review.

Do not enable the schedule if the new Worker returns Cloudflare `1101`. Verify the new `/login` endpoint before enabling GitHub secrets and the scheduled workflow.

## Custom domain hardening

The initial deployment uses `workers.dev`. After choosing a Cloudflare-managed hostname, add that route and then protect `/admin*` and `/login` with Cloudflare Access and zone-level WAF rules. A hostname is intentionally not guessed or created by this repository.
