import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import fastifyStatic from "@fastify/static";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from "fastify";
import { access } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ZodError } from "zod";
import {
  createWebhookEndpointRequestSchema,
  manualScanRequestSchema,
  normalizeLimit,
  problem,
  signHmacSha256,
  updatePolicyRequestSchema,
  verifyHmacSha256,
  weakEtag,
  type Policy,
} from "@sentinelflow/contracts";
import type { SentinelStore, UserRecord } from "@sentinelflow/db";
import { loadConfig, type ApiConfig } from "./config.js";

declare module "fastify" {
  interface FastifyRequest {
    rawBody?: Buffer;
  }
}

interface BuildAppOptions {
  store: SentinelStore;
  config?: ApiConfig;
}

interface AuthenticatedRequest extends FastifyRequest {
  user: UserRecord;
}

interface MetricsState {
  requests: number;
  errors: number;
  byRoute: Map<string, number>;
}

export async function buildApp(
  options: BuildAppOptions,
): Promise<FastifyInstance> {
  const config = options.config ?? loadConfig();
  const store = options.store;
  const metrics: MetricsState = {
    requests: 0,
    errors: 0,
    byRoute: new Map(),
  };

  const app = Fastify({
    logger:
      config.nodeEnv === "test"
        ? false
        : {
            level: config.nodeEnv === "production" ? "info" : "debug",
          },
    genReqId: (request) =>
      String(request.headers["x-request-id"] ?? crypto.randomUUID()),
  });

  app.addContentTypeParser(
    "application/json",
    { parseAs: "buffer" },
    (request, body, done) => {
      const raw = Buffer.isBuffer(body) ? body : Buffer.from(body);
      request.rawBody = raw;
      if (!raw.length) {
        done(null, {});
        return;
      }
      try {
        done(null, JSON.parse(raw.toString("utf8")) as unknown);
      } catch (error) {
        done(error as Error);
      }
    },
  );

  await app.register(helmet);
  await app.register(cors, {
    origin: config.webOrigin,
    credentials: true,
  });
  await app.register(cookie, {
    secret: config.sessionSecret,
  });
  await app.register(swagger, {
    openapi: {
      info: {
        title: "SentinelFlow API",
        version: "0.1.0",
      },
    },
  });
  await app.register(swaggerUi, {
    routePrefix: "/docs",
  });

  if (config.nodeEnv === "production") {
    const webDist = resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../../web/dist",
    );
    try {
      await access(webDist);
      await app.register(fastifyStatic, {
        root: webDist,
        prefix: "/",
        wildcard: false,
      });
      app.setNotFoundHandler((request, reply) => {
        if (
          request.method === "GET" &&
          !request.url.startsWith("/v1/") &&
          !request.url.startsWith("/auth/") &&
          !request.url.startsWith("/github/") &&
          !request.url.startsWith("/docs") &&
          !request.url.startsWith("/health") &&
          !request.url.startsWith("/ready") &&
          !request.url.startsWith("/metrics")
        ) {
          return reply.sendFile("index.html");
        }
        sendProblem(reply, 404, "Not Found");
      });
    } catch {
      app.log.warn({ webDist }, "web build not found; dashboard disabled");
    }
  }

  app.addHook("onRequest", async (request, reply) => {
    metrics.requests += 1;
    const key = `${request.method} ${request.routeOptions.url ?? request.url}`;
    metrics.byRoute.set(key, (metrics.byRoute.get(key) ?? 0) + 1);
    reply.header("x-request-id", request.id);
  });

  app.setErrorHandler((error, request, reply) => {
    metrics.errors += 1;
    if (error instanceof HttpError) {
      sendProblem(reply, error.statusCode, error.message, error.detail);
      return;
    }
    if (error instanceof ZodError) {
      sendProblem(reply, 400, "Invalid request", error.issues[0]?.message);
      return;
    }
    if (isFastifyLikeError(error)) {
      sendProblem(reply, error.statusCode, error.message);
      return;
    }
    request.log.error({ err: error }, "unhandled request error");
    sendProblem(reply, 500, "Internal Server Error");
  });

  app.get("/health", async () => ({
    ok: true,
    service: "sentinelflow-api",
  }));

  app.get("/ready", async (_request, reply) => {
    const health = await store.health();
    return reply.code(health.ok ? 200 : 503).send(health);
  });

  app.get("/metrics", async (request, reply) => {
    if (
      config.nodeEnv === "production" &&
      (!config.metricsToken ||
        request.headers["x-metrics-token"] !== config.metricsToken)
    ) {
      sendProblem(reply, 404, "Not Found");
      return;
    }
    const lines = [
      "# HELP sentinelflow_http_requests_total Total HTTP requests.",
      "# TYPE sentinelflow_http_requests_total counter",
      `sentinelflow_http_requests_total ${metrics.requests}`,
      "# HELP sentinelflow_http_errors_total Total HTTP errors.",
      "# TYPE sentinelflow_http_errors_total counter",
      `sentinelflow_http_errors_total ${metrics.errors}`,
    ];
    for (const [route, count] of metrics.byRoute.entries()) {
      lines.push(
        `sentinelflow_http_route_requests_total{route=${JSON.stringify(route)}} ${count}`,
      );
    }
    return reply.type("text/plain").send(lines.join("\n"));
  });

  app.post("/auth/dev/login", async (_request, reply) => {
    if (config.nodeEnv === "production") {
      sendProblem(reply, 404, "Not Found");
      return;
    }
    const user = await store.seedDemoData();
    const sessionResult = await store.createSessionFromGitHub({
      githubId: user.githubId,
      login: user.login,
      avatarUrl: user.avatarUrl,
    });
    setSessionCookie(reply, sessionResult.session.id, config);
    return { user: sessionResult.user };
  });

  app.post("/auth/demo/login", async (_request, reply) => {
    if (!config.demoLoginEnabled) {
      sendProblem(reply, 404, "Not Found");
      return;
    }
    const user = await store.seedDemoData();
    const sessionResult = await store.createSessionFromGitHub({
      githubId: user.githubId,
      login: user.login,
      avatarUrl: user.avatarUrl,
    });
    setSessionCookie(reply, sessionResult.session.id, config);
    return { user: sessionResult.user };
  });

  app.get("/auth/github/start", async (_request, reply) => {
    if (!config.githubClientId) {
      sendProblem(reply, 503, "GitHub OAuth is not configured");
      return;
    }
    const state = crypto.randomUUID();
    reply.setCookie("sf_oauth_state", state, cookieOptions(config, 10 * 60));
    const params = new URLSearchParams({
      client_id: config.githubClientId,
      redirect_uri: `${config.apiBaseUrl}/auth/github/callback`,
      scope: "read:user",
      state,
    });
    return reply.redirect(`https://github.com/login/oauth/authorize?${params}`);
  });

  app.get("/auth/github/callback", async (request, reply) => {
    const query = request.query as { code?: string; state?: string };
    const expectedState = request.cookies["sf_oauth_state"];
    if (!query.code || !query.state || query.state !== expectedState) {
      sendProblem(reply, 400, "Invalid OAuth callback");
      return;
    }
    if (!config.githubClientId || !config.githubClientSecret) {
      sendProblem(reply, 503, "GitHub OAuth is not configured");
      return;
    }

    const tokenResponse = await fetch(
      "https://github.com/login/oauth/access_token",
      {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          client_id: config.githubClientId,
          client_secret: config.githubClientSecret,
          code: query.code,
          redirect_uri: `${config.apiBaseUrl}/auth/github/callback`,
        }),
      },
    );
    const tokenBody = (await tokenResponse.json()) as { access_token?: string };
    if (!tokenBody.access_token) {
      sendProblem(reply, 502, "GitHub OAuth token exchange failed");
      return;
    }
    const profileResponse = await fetch("https://api.github.com/user", {
      headers: {
        authorization: `Bearer ${tokenBody.access_token}`,
        accept: "application/vnd.github+json",
      },
    });
    const profile = (await profileResponse.json()) as {
      id?: number;
      login?: string;
      avatar_url?: string;
    };
    if (!profile.id || !profile.login) {
      sendProblem(reply, 502, "GitHub profile fetch failed");
      return;
    }
    const { session } = await store.createSessionFromGitHub({
      githubId: String(profile.id),
      login: profile.login,
      avatarUrl: profile.avatar_url ?? null,
    });
    const user = await store.getUserBySession(session.id);
    if (user) {
      for (const fullName of config.scanRepoAllowlist) {
        await store.upsertRepo({
          fullName,
          defaultBranch: fullName.endsWith("/installsentry")
            ? "master"
            : "main",
          private: false,
          userId: user.id,
        });
      }
    }
    setSessionCookie(reply, session.id, config);
    return reply.redirect(config.publicAppUrl);
  });

  app.get("/auth/github/install", async (_request, reply) => {
    return reply.redirect(
      `https://github.com/apps/${config.githubAppSlug}/installations/new`,
    );
  });

  app.post("/auth/logout", async (request, reply) => {
    const sessionId = request.cookies["sf_session"];
    if (sessionId) {
      await store.deleteSession(sessionId);
    }
    reply.clearCookie("sf_session", { path: "/" });
    return reply.code(204).send();
  });

  app.post("/github/webhook", async (request, reply) => {
    const rawBody =
      request.rawBody ?? Buffer.from(JSON.stringify(request.body ?? {}));
    const signature = request.headers["x-hub-signature-256"];
    if (
      !verifyHmacSha256(
        config.githubWebhookSecret,
        rawBody,
        Array.isArray(signature) ? signature[0] : signature,
      )
    ) {
      sendProblem(reply, 401, "Invalid GitHub webhook signature");
      return;
    }

    const event = String(request.headers["x-github-event"] ?? "");
    const delivery = String(
      request.headers["x-github-delivery"] ?? crypto.randomUUID(),
    );
    await handleGitHubWebhook(event, delivery, request.body, store, config);
    return reply.code(202).send({ accepted: true, event, delivery });
  });

  app.addHook("preHandler", async (request, reply) => {
    if (!request.url.startsWith("/v1/")) {
      return;
    }
    const sessionId = request.cookies["sf_session"];
    if (!sessionId) {
      sendProblem(reply, 401, "Authentication required");
      return;
    }
    const user = await store.getUserBySession(sessionId);
    if (!user) {
      sendProblem(reply, 401, "Authentication required");
      return;
    }
    (request as AuthenticatedRequest).user = user;
  });

  app.get("/v1/me", async (request) => ({
    user: (request as AuthenticatedRequest).user,
  }));

  app.get("/v1/repos", async (request, reply) => {
    const user = (request as AuthenticatedRequest).user;
    const query = request.query as { limit?: string; cursor?: string };
    const page = await store.listRepos(
      user.id,
      withCursor({ limit: normalizeLimit(query.limit) }, query.cursor),
    );
    return sendWithEtag(request, reply, page);
  });

  app.get("/v1/repos/:repoId", async (request, reply) => {
    const user = (request as AuthenticatedRequest).user;
    const { repoId } = request.params as { repoId: string };
    const repo = await store.getRepo(user.id, repoId);
    if (!repo) {
      sendProblem(reply, 404, "Repository not found");
      return;
    }
    return sendWithEtag(request, reply, repo);
  });

  app.get("/v1/repos/:repoId/policy", async (request, reply) => {
    const user = (request as AuthenticatedRequest).user;
    const { repoId } = request.params as { repoId: string };
    const repo = await store.getRepo(user.id, repoId);
    if (!repo) {
      sendProblem(reply, 404, "Repository not found");
      return;
    }
    return sendWithEtag(request, reply, await store.getPolicy(repoId));
  });

  app.put("/v1/repos/:repoId/policy", async (request, reply) => {
    const user = (request as AuthenticatedRequest).user;
    const { repoId } = request.params as { repoId: string };
    const patch = stripUndefined(
      updatePolicyRequestSchema.parse(request.body),
    ) as Partial<Policy>;
    const policy = await store.updatePolicy(user.id, repoId, patch);
    return reply.send(policy);
  });

  app.post("/v1/repos/:repoId/scans", async (request, reply) => {
    const user = (request as AuthenticatedRequest).user;
    const { repoId } = request.params as { repoId: string };
    const repo = await store.getRepo(user.id, repoId);
    if (!repo) {
      sendProblem(reply, 404, "Repository not found");
      return;
    }
    if (
      !config.scanRepoAllowlist.has(repo.fullName) &&
      !repo.fullName.startsWith("sentinelflow-demo/")
    ) {
      sendProblem(reply, 403, "Repository is not allowlisted for scanning");
      return;
    }
    const body = manualScanRequestSchema.parse(request.body ?? {});
    const scanInput: Parameters<typeof store.createScan>[0] = {
      userId: user.id,
      repoId,
      source: "manual",
      commitSha: body.commitSha ?? repo.defaultBranch,
    };
    if (body.reason) {
      scanInput.reason = body.reason;
    }
    const scanIdempotencyKey = headerValue(request.headers["idempotency-key"]);
    if (scanIdempotencyKey) {
      scanInput.idempotencyKey = scanIdempotencyKey;
    }
    const result = await store.createScan(scanInput);
    return reply
      .code(result.reused ? 200 : 202)
      .header("location", `/v1/scans/${result.scan.id}`)
      .send({ scan: result.scan, jobId: result.job.id, reused: result.reused });
  });

  app.get("/v1/scans/:scanId", async (request, reply) => {
    const user = (request as AuthenticatedRequest).user;
    const { scanId } = request.params as { scanId: string };
    const scan = await store.getScan(user.id, scanId);
    if (!scan) {
      sendProblem(reply, 404, "Scan not found");
      return;
    }
    return sendWithEtag(request, reply, scan);
  });

  app.get("/v1/scans/:scanId/findings", async (request, reply) => {
    const user = (request as AuthenticatedRequest).user;
    const { scanId } = request.params as { scanId: string };
    const scan = await store.getScan(user.id, scanId);
    if (!scan) {
      sendProblem(reply, 404, "Scan not found");
      return;
    }
    return sendWithEtag(request, reply, {
      items: await store.listFindings(user.id, scanId),
    });
  });

  app.get("/v1/audit-logs", async (request, reply) => {
    const user = (request as AuthenticatedRequest).user;
    const query = request.query as { limit?: string; cursor?: string };
    const logs = await store.listAuditLogs(
      user.id,
      withCursor({ limit: normalizeLimit(query.limit) }, query.cursor),
    );
    return sendWithEtag(request, reply, logs);
  });

  app.get("/v1/webhook-endpoints", async (request, reply) => {
    const user = (request as AuthenticatedRequest).user;
    return sendWithEtag(request, reply, {
      items: await store.listWebhookEndpoints(user.id),
    });
  });

  app.post("/v1/webhook-endpoints", async (request, reply) => {
    const user = (request as AuthenticatedRequest).user;
    const body = createWebhookEndpointRequestSchema.parse(request.body);
    const endpoint = await store.createWebhookEndpoint({
      userId: user.id,
      url: body.url,
      description: body.description ?? null,
    });
    return reply.code(201).send(endpoint);
  });

  app.get("/v1/webhook-deliveries", async (request, reply) => {
    const user = (request as AuthenticatedRequest).user;
    return sendWithEtag(request, reply, {
      items: await store.listWebhookDeliveries(user.id),
    });
  });

  app.post(
    "/v1/webhook-deliveries/:deliveryId/replay",
    async (request, reply) => {
      const user = (request as AuthenticatedRequest).user;
      const { deliveryId } = request.params as { deliveryId: string };
      const replayInput: Parameters<typeof store.replayWebhookDelivery>[0] = {
        userId: user.id,
        deliveryId,
      };
      const replayIdempotencyKey = headerValue(
        request.headers["idempotency-key"],
      );
      if (replayIdempotencyKey) {
        replayInput.idempotencyKey = replayIdempotencyKey;
      }
      const result = await store.replayWebhookDelivery(replayInput);
      return reply
        .code(result.reused ? 200 : 202)
        .header("location", `/v1/webhook-deliveries`)
        .send(result);
    },
  );

  return app;
}

async function handleGitHubWebhook(
  event: string,
  delivery: string,
  body: unknown,
  store: SentinelStore,
  config: ApiConfig,
) {
  const payload = body as Record<string, any>;
  if (event === "installation") {
    const installation = payload["installation"];
    const account = installation?.account;
    if (installation?.id && account?.login) {
      await store.upsertInstallation({
        id: String(installation.id),
        accountLogin: String(account.login),
        accountType: String(account.type ?? "User"),
        suspendedAt: installation.suspended_at ?? null,
      });
      const repos = Array.isArray(payload["repositories"])
        ? payload["repositories"]
        : [];
      for (const repo of repos) {
        await store.upsertRepo({
          fullName: String(repo.full_name),
          defaultBranch: String(repo.default_branch ?? "main"),
          private: Boolean(repo.private),
          installationId: String(installation.id),
        });
      }
    }
    return;
  }

  if (event === "installation_repositories") {
    const installation = payload["installation"];
    const repos = Array.isArray(payload["repositories_added"])
      ? payload["repositories_added"]
      : [];
    for (const repo of repos) {
      await store.upsertRepo({
        fullName: String(repo.full_name),
        defaultBranch: String(repo.default_branch ?? "main"),
        private: Boolean(repo.private),
        installationId: installation?.id ? String(installation.id) : null,
      });
    }
    return;
  }

  if (event === "pull_request") {
    const action = String(payload["action"] ?? "");
    if (!["opened", "synchronize", "reopened"].includes(action)) {
      return;
    }
    const repoPayload = payload["repository"];
    const fullName = String(repoPayload?.full_name ?? "");
    if (!fullName || !config.scanRepoAllowlist.has(fullName)) {
      await store.enqueueJob({
        type: "github_check_update",
        payload: {
          delivery,
          conclusion: "neutral",
          summary:
            "Repository is not allowlisted for SentinelFlow demo scanning.",
        },
      });
      return;
    }
    const systemUser = await store.seedDemoData();
    const repo = await store.upsertRepo({
      fullName,
      defaultBranch: String(repoPayload.default_branch ?? "main"),
      private: Boolean(repoPayload.private),
      installationId: payload["installation"]?.id
        ? String(payload["installation"].id)
        : null,
      userId: systemUser.id,
    });
    await store.createScan({
      userId: systemUser.id,
      repoId: repo.id,
      source: "pull_request",
      commitSha: payload["pull_request"]?.head?.sha ?? null,
      pullRequestNumber: Number(
        payload["pull_request"]?.number ?? payload["number"] ?? 0,
      ),
      idempotencyKey: `${event}:${delivery}`,
    });
    return;
  }

  if (event === "push") {
    const repoPayload = payload["repository"];
    const fullName = String(repoPayload?.full_name ?? "");
    if (!fullName || !config.scanRepoAllowlist.has(fullName)) {
      return;
    }
    const systemUser = await store.seedDemoData();
    const repo = await store.upsertRepo({
      fullName,
      defaultBranch: String(repoPayload.default_branch ?? "main"),
      private: Boolean(repoPayload.private),
      installationId: payload["installation"]?.id
        ? String(payload["installation"].id)
        : null,
      userId: systemUser.id,
    });
    await store.createScan({
      userId: systemUser.id,
      repoId: repo.id,
      source: "push",
      commitSha: String(payload["after"] ?? ""),
      idempotencyKey: `${event}:${delivery}`,
    });
  }
}

function sendWithEtag(
  request: FastifyRequest,
  reply: FastifyReply,
  body: unknown,
): FastifyReply {
  const etag = weakEtag(body);
  reply.header("etag", etag);
  if (request.headers["if-none-match"] === etag) {
    return reply.code(304).send();
  }
  return reply.send(body);
}

function sendProblem(
  reply: FastifyReply,
  status: number,
  title: string,
  detail?: string,
): FastifyReply {
  return reply
    .code(status)
    .type("application/problem+json")
    .send(problem(status, title, detail));
}

function setSessionCookie(
  reply: FastifyReply,
  sessionId: string,
  config: ApiConfig,
) {
  reply.setCookie(
    "sf_session",
    sessionId,
    cookieOptions(config, 60 * 60 * 24 * 14),
  );
}

function cookieOptions(config: ApiConfig, maxAgeSeconds: number) {
  return {
    path: "/",
    httpOnly: true,
    sameSite: "lax" as const,
    secure: config.nodeEnv === "production",
    maxAge: maxAgeSeconds,
  };
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function withCursor<T extends { limit: number }>(
  base: T,
  cursor: string | undefined,
): T & {
  cursor?: string;
} {
  return cursor ? { ...base, cursor } : base;
}

function stripUndefined<T extends Record<string, unknown>>(
  value: T,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => entry !== undefined),
  );
}

function isFastifyLikeError(
  error: unknown,
): error is { statusCode: number; message: string } {
  return (
    typeof error === "object" &&
    error !== null &&
    "statusCode" in error &&
    typeof (error as { statusCode?: unknown }).statusCode === "number" &&
    "message" in error &&
    typeof (error as { message?: unknown }).message === "string"
  );
}

class HttpError extends Error {
  constructor(
    readonly statusCode: number,
    message: string,
    readonly detail?: string,
  ) {
    super(message);
  }
}

export function createGitHubWebhookSignature(
  secret: string,
  body: string | Buffer,
): string {
  return signHmacSha256(secret, body);
}
