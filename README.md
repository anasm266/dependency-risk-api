# SentinelFlow

SentinelFlow is a backend-focused supply-chain security control plane for GitHub repositories. It scans JavaScript dependency trees, evaluates install-time risk against configurable policies, stores audit evidence, and can notify external systems through signed webhooks.

The product is built around a common security workflow:

1. A repository is connected through a GitHub App.
2. A scan is queued for a branch, commit, or pull request.
3. A worker downloads the repository archive, inspects the lockfile, and normalizes dependency-risk signals.
4. A policy engine decides whether the dependency state passes or needs review.
5. Results are persisted, displayed in the dashboard, written to audit logs, and optionally delivered to external webhook receivers.

In short: SentinelFlow answers the question, "Did this dependency change introduce install-time behavior that should block or require review?"

## Live Demo

The hosted demo is available at:

```text
https://sentinelflow-api.onrender.com
```

API documentation:

```text
https://sentinelflow-api.onrender.com/docs
```

The hosted demo uses a repository allowlist, so scans are limited to configured repositories. This keeps public demo usage controlled while still exercising the real GitHub, PostgreSQL, worker, policy, and webhook paths.

The dashboard includes a `try demo` button. Demo mode creates a limited session with seeded sample repositories, scan results, findings, audit logs, a webhook endpoint, and delivery history. It is intended for reviewers who want to evaluate the product without installing the GitHub App.

## Why This Exists

Modern npm projects routinely install hundreds or thousands of transitive packages. A package can run code during installation through lifecycle scripts such as `install`, `preinstall`, or `postinstall`. That behavior is legitimate for some packages, but it is also a common path for supply-chain attacks because install scripts execute before application code is ever imported.

SentinelFlow treats dependency changes as a backend security workflow rather than a static report. It combines policy evaluation, durable jobs, persistence, auditability, GitHub integration, and webhook delivery so the result resembles the kind of system used in production engineering organizations.

## Current Capabilities

- GitHub OAuth login with server-side sessions.
- GitHub App repository sync and webhook ingestion.
- Repository allowlist for controlled public scanning.
- Manual scans from the dashboard.
- Pull request and push webhook handling.
- GitHub check-run updates for scan results.
- PostgreSQL-backed data model with handwritten SQL migrations.
- Postgres job queue using `FOR UPDATE SKIP LOCKED`.
- Transactional outbox for scan-completed events.
- Signed outbound webhook delivery with replay support.
- Policy controls for lifecycle scripts, secret reads, network egress, new risky packages, and blast radius.
- Grouped findings display that preserves raw evidence while keeping the UI readable.
- Audit logs for scan and policy actions.
- OpenAPI documentation.
- Prometheus-style metrics endpoint.
- Unit, integration, browser, and load-test scaffolding.

## Product Concepts

### Scan Status

| Status        | Meaning                                               |
| ------------- | ----------------------------------------------------- |
| `queued`      | A scan job has been created but not processed yet.    |
| `running`     | A worker has claimed the scan job.                    |
| `succeeded`   | The repository passed the active policy.              |
| `failed`      | The repository produced policy-blocking findings.     |
| `unsupported` | The scanner cannot analyze the repository format yet. |

`failed` does not mean the repository build is broken. It means SentinelFlow found dependency behavior that violates the configured policy.

### Policy Controls

| Control                    | Purpose                                                                             |
| -------------------------- | ----------------------------------------------------------------------------------- |
| Block lifecycle scripts    | Flags dependencies that run install-time scripts.                                   |
| Block secret reads         | Flags scanner evidence that indicates secret/canary access.                         |
| New risky package approval | Adds review pressure when a risky package is newly introduced.                      |
| Max blast radius           | Flags packages that are depended on by more packages than the configured threshold. |

### Findings

Findings are grouped by package and lockfile path. Raw evidence remains stored in the database, while the dashboard shows a compact row with combined reasons.

Example:

```text
medium | fsevents@2.3.3 | playwright/node_modules/fsevents | lifecycle script, optional platform package, new risky dependency
```

This means `fsevents` was found under `playwright`, it runs a lifecycle script, it is a newly introduced risky package under the current policy, and it is treated as medium severity because lockfile evidence marks it as an optional platform package.

### Webhooks And Deliveries

Webhook endpoints are URLs that receive scan-completed events from SentinelFlow. They are useful for integrating with Slack bots, internal dashboards, logging systems, CI workflows, or security automation.

Each outbound webhook is delivered through a durable job. Delivery attempts are stored with status, response code, latency, and a response excerpt. Failed deliveries can be replayed from the dashboard.

Outbound webhook requests include an HMAC signature header:

```text
x-sentinelflow-signature-256: sha256=<digest>
```

## Architecture

```mermaid
flowchart LR
  User["User"] --> Web["React Dashboard"]
  Web --> API["Fastify API"]
  GitHub["GitHub App"] --> API
  API --> DB[("PostgreSQL")]
  API --> Jobs["jobs table"]
  Jobs --> Worker["Worker"]
  Worker --> GitHubApi["GitHub Archive API"]
  Worker --> Scanner["Scanner Adapter"]
  Scanner --> Policy["Policy Engine"]
  Policy --> DB
  DB --> Outbox["outbox_events"]
  Outbox --> Worker
  Worker --> Receiver["External Webhook Receiver"]
  Worker --> Checks["GitHub Check Runs"]
```

## Repository Layout

```text
apps/
  api/       Fastify REST API, auth, GitHub callbacks, dashboard serving
  web/       Vite + React dashboard
  worker/    background job processor and scanner adapter

packages/
  contracts/ shared schemas, policy logic, HMAC helpers, grouping helpers
  db/        migrations, in-memory store, PostgreSQL store

tests/
  e2e/       Playwright dashboard smoke tests

k6/
  smoke.js   load-test smoke script
```

## Backend Design Decisions

### Fastify Instead Of Serverless Workers

SentinelFlow uses Fastify to demonstrate conventional backend API structure: middleware, cookies, CORS, secure headers, structured routes, error handling, request IDs, OpenAPI, and testable server composition. This intentionally exercises backend-framework fundamentals instead of relying on an edge-only request handler.

### PostgreSQL As The System Of Record

PostgreSQL stores users, sessions, GitHub installations, repositories, policies, scans, findings, jobs, outbox events, webhook endpoints, deliveries, idempotency keys, and audit logs. The schema is managed through handwritten SQL migrations so indexes, constraints, and relationships are explicit.

### Server-Side Sessions

The browser dashboard uses secure HTTP-only cookies backed by server-side session records. This keeps GitHub OAuth tokens and session state out of browser storage.

### Postgres Job Queue

Jobs are stored in PostgreSQL and claimed with `FOR UPDATE SKIP LOCKED`. This gives the worker durable retry behavior without introducing a separate queue dependency for the core demo.

Job types include:

- `manual_scan`
- `pr_scan`
- `github_check_update`
- `webhook_delivery`

### Transactional Outbox

When a scan completes, SentinelFlow writes the scan result and the `scan.completed` outbox event in the same transaction. A worker later creates and sends webhook deliveries. This avoids the common reliability bug where a database write succeeds but the external notification is lost.

### Idempotency

Manual scan creation and webhook replay accept `Idempotency-Key` headers. Repeated requests with the same key return the original result instead of creating duplicate work.

### Controlled Repository Allowlist

Public scanning is restricted by `SCAN_REPO_ALLOWLIST`. Arbitrary repository scanning can be expensive and risky because the worker downloads archives and runs dependency analysis. The allowlist keeps the hosted demo safe while preserving the production pattern for authorization and policy checks.

## Scanner Behavior

The current scanner path focuses on npm `package-lock.json` repositories.

For each supported repository, the worker:

1. Downloads the GitHub archive for the requested commit or branch.
2. Requires `package-lock.json`.
3. Parses dependency entries and lockfile metadata.
4. Preserves clean package names, nested package paths, versions, optional/dev/platform evidence, and raw lockfile paths.
5. Runs the InstallSentry CLI adapter when available.
6. Normalizes scanner output into policy findings.
7. Persists final findings with severity, rule ID, package, version, title, and evidence.

Unsupported package-manager formats currently produce an `unsupported` scan result instead of a misleading pass or failure.

## API Overview

OpenAPI documentation is served at:

```text
/docs
/docs/json
```

Primary routes:

| Route                                            | Purpose                                                                        |
| ------------------------------------------------ | ------------------------------------------------------------------------------ |
| `GET /health`                                    | Liveness check.                                                                |
| `GET /ready`                                     | Database readiness check.                                                      |
| `GET /metrics`                                   | Prometheus-style metrics. Protected in production when `METRICS_TOKEN` is set. |
| `GET /auth/github/start`                         | Starts GitHub OAuth login.                                                     |
| `GET /auth/github/callback`                      | Completes GitHub OAuth login.                                                  |
| `GET /auth/github/install`                       | Redirects to GitHub App installation.                                          |
| `POST /auth/demo/login`                          | Starts a limited public demo session.                                          |
| `POST /github/webhook`                           | Receives GitHub App webhooks.                                                  |
| `GET /v1/me`                                     | Current user.                                                                  |
| `GET /v1/repos`                                  | Connected repositories.                                                        |
| `GET /v1/repos/:repoId/policy`                   | Repository policy.                                                             |
| `PUT /v1/repos/:repoId/policy`                   | Update repository policy.                                                      |
| `POST /v1/repos/:repoId/scans`                   | Queue a manual scan.                                                           |
| `GET /v1/scans/:scanId`                          | Scan metadata.                                                                 |
| `GET /v1/scans/:scanId/findings`                 | Raw persisted findings.                                                        |
| `GET /v1/audit-logs`                             | Audit events.                                                                  |
| `GET /v1/webhook-endpoints`                      | Outbound webhook endpoints.                                                    |
| `POST /v1/webhook-endpoints`                     | Create an outbound webhook endpoint.                                           |
| `GET /v1/webhook-deliveries`                     | Delivery history.                                                              |
| `POST /v1/webhook-deliveries/:deliveryId/replay` | Replay a delivery.                                                             |

## Local Development

### Prerequisites

- Node.js 22 or newer.
- npm 10 or newer.
- Docker Desktop for PostgreSQL-backed integration tests.
- k6 for the optional load smoke test.

### Install

```bash
npm install
```

### Start PostgreSQL And Redis

```bash
docker compose up -d
```

### Configure Environment

Create a local environment file from the example:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

The default local database URL is:

```text
postgres://sentinelflow:sentinelflow@localhost:5432/sentinelflow
```

### Run Migrations

```bash
npm run db:migrate
```

### Start Development Servers

In separate terminals:

```bash
npm run dev:api
npm run dev:worker
npm run dev:web
```

Default local URLs:

| Service   | URL                          |
| --------- | ---------------------------- |
| API       | `http://localhost:4000`      |
| Dashboard | `http://localhost:5173`      |
| OpenAPI   | `http://localhost:4000/docs` |

### Local And Public Demo Login

`/auth/demo/login` seeds a limited reviewer session and is enabled by default. `/auth/dev/login` is available only in non-production environments for local development and is disabled in production.

## Running A GitHub App Integration

A self-hosted instance needs a GitHub App with these permissions:

| Permission    | Access         |
| ------------- | -------------- |
| Metadata      | Read           |
| Contents      | Read           |
| Pull requests | Read           |
| Checks        | Read and write |

Webhook events:

- `installation`
- `installation_repositories`
- `pull_request`
- `push`

Required production environment variables:

```text
NODE_ENV=production
DATABASE_URL=<postgres connection string>
WEB_ORIGIN=<dashboard origin>
PUBLIC_APP_URL=<public app URL>
API_BASE_URL=<public API URL>
SESSION_SECRET=<random 32+ byte secret>
GITHUB_APP_ID=<GitHub App ID>
GITHUB_CLIENT_ID=<OAuth client ID>
GITHUB_CLIENT_SECRET=<OAuth client secret>
GITHUB_APP_SLUG=<GitHub App slug>
GITHUB_APP_PRIVATE_KEY=<PEM private key with escaped newlines if stored as one line>
GITHUB_WEBHOOK_SECRET=<GitHub webhook secret>
SCAN_REPO_ALLOWLIST=owner/repo,owner/another-repo
```

Useful optional variables:

```text
RUN_WORKER_IN_API=true
MIGRATE_ON_STARTUP=true
METRICS_TOKEN=<token required for /metrics in production>
DEMO_LOGIN_ENABLED=true
SCANNER_TIMEOUT_MS=120000
SCANNER_MAX_OUTPUT_BYTES=200000
```

## Deployment

The repository includes a Render Blueprint:

```text
render.yaml
```

The provided Render configuration runs the API and worker in the same web service by setting:

```text
RUN_WORKER_IN_API=true
MIGRATE_ON_STARTUP=true
```

This is useful for a small hosted demo and free-tier deployment. A production deployment should split the API and worker into separate services so web requests and background scans scale independently.

Recommended hosted components:

| Component                    | Example Provider                             |
| ---------------------------- | -------------------------------------------- |
| API + dashboard              | Render web service                           |
| Worker                       | Render background worker or separate service |
| PostgreSQL                   | Neon, Supabase, Render Postgres, or RDS      |
| Webhook receiver for testing | webhook.site or httpbin                      |

## Testing

Run unit and integration tests:

```bash
npm test
```

Run with PostgreSQL integration enabled:

```bash
DATABASE_URL=postgres://sentinelflow:sentinelflow@localhost:5432/sentinelflow npm test
```

PowerShell:

```powershell
$env:DATABASE_URL="postgres://sentinelflow:sentinelflow@localhost:5432/sentinelflow"
npm test
```

Run typecheck:

```bash
npm run typecheck
```

Run build:

```bash
npm run build
```

Run lint:

```bash
npm run lint
```

Run browser smoke tests:

```bash
npm run test:e2e
```

Run load smoke test when k6 is installed:

```bash
npm run test:load
```

## Example User Workflow

1. Open the dashboard.
2. Click `try demo` for a seeded reviewer session, or sign in with GitHub for a real repository connection.
3. Select a repository in the sidebar.
4. Adjust policy settings.
5. Click `scan`.
6. Review scan status and grouped findings.
7. Add a webhook endpoint if external notification is needed.
8. Review delivery history and replay failed deliveries when necessary.
9. Use audit logs to trace scan and policy activity.

## Example Webhook Test

Use a disposable receiver to verify outbound delivery:

```text
https://httpbin.org/post
```

Or use a request inspector such as:

```text
https://webhook.site/
```

After adding the endpoint and running a scan, the deliveries table should show a `scan.completed` delivery with status `delivered` and HTTP status `200` when the receiver accepts the request.

## Security And Reliability Notes

- GitHub webhook requests are verified with HMAC signatures.
- Outbound webhooks are signed with endpoint-specific HMAC secrets.
- Browser sessions use HTTP-only cookies.
- Production dev login is disabled.
- API errors use `application/problem+json`.
- Stable GET responses use ETags.
- Mutating async endpoints support idempotency keys where duplicate work would be harmful.
- Scan completion and outbox event creation happen in one database transaction.
- Worker jobs retry with backoff and eventually dead-letter.
- Metrics are protected in production when `METRICS_TOKEN` is configured.

## Known Limitations

- The scanner currently supports npm `package-lock.json` repositories. Repositories using only `pnpm-lock.yaml`, `yarn.lock`, Cargo, Poetry, Maven, or other lockfile formats are marked `unsupported`.
- Hosted public scanning is intentionally restricted by `SCAN_REPO_ALLOWLIST`.
- The free-tier single-service deployment is suitable for demonstration, not sustained production traffic.
- InstallSentry is consumed through a CLI adapter in this version rather than refactored into a library.
- The dashboard is intentionally simple and backend-focused.

## Future Work

- Add pnpm and yarn lockfile scanners.
- Add a scan detail drawer that exposes raw evidence behind each grouped finding.
- Add per-organization policy templates.
- Split API and worker services in production.
- Add Slack or Discord webhook templates.
- Add richer GitHub PR annotations.
- Add repository onboarding for unsupported lockfiles.
- Add a public sample-data mode for demos without GitHub installation.

## Engineering Focus

SentinelFlow is designed to demonstrate backend engineering depth:

- Relational schema design and migrations.
- GitHub App authentication and webhook verification.
- Server-side sessions and authorization checks.
- REST API design with OpenAPI.
- Background processing and job locking.
- Transactional outbox reliability.
- Webhook delivery and replay.
- Policy evaluation and normalized security findings.
- Structured testing across units, integration, browser smoke tests, and load-test scaffolding.
