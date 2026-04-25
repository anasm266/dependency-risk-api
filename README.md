# SentinelFlow

SentinelFlow is a backend-focused supply-chain risk control plane for GitHub
repositories. It watches dependency changes, evaluates install-time risk, and
turns the result into policy decisions, PR checks, audit logs, and signed
webhook events.

The project is intentionally built around backend fundamentals: Fastify,
PostgreSQL, migrations, GitHub App webhooks, server-side sessions, a durable job
queue, a transactional outbox, OpenAPI, observability hooks, and a thorough test
suite.

## Stack

- TypeScript npm workspaces
- Fastify REST API
- PostgreSQL with handwritten SQL migrations
- Postgres-backed job queue using `FOR UPDATE SKIP LOCKED`
- Transactional outbox for outbound webhooks
- Vite + React dashboard
- Vitest, Playwright, and k6

## Local quick start

```bash
npm install
npm run build
npm test
```

API-only development works without Docker by using the in-memory store:

```bash
npm run dev:api
```

Full local integration requires Docker Desktop for Postgres and Redis:

```bash
docker compose up -d
cp .env.example .env
npm run db:migrate
npm run dev:api
npm run dev:worker
npm run dev:web
```

## Apps and packages

- `apps/api`: Fastify API, auth, GitHub webhooks, REST resources.
- `apps/worker`: job processor, InstallSentry adapter, policy execution.
- `apps/web`: restrained operator dashboard.
- `packages/contracts`: shared schemas, policy logic, crypto helpers.
- `packages/db`: migrations, in-memory store, Postgres store.

## External setup checkpoints

You will need these when moving from local/demo mode to the public demo:

1. Docker Desktop for full integration tests.
2. A GitHub App with webhook secret, OAuth client ID/secret, and Checks write
   permission.
3. Neon Postgres connection string.
4. Upstash Redis URL if enabling distributed rate limiting/cache.
5. Render services for API and worker deployment.
