import { describe, expect, it } from "vitest";
import { MemoryStore } from "@sentinelflow/db";
import { buildApp, createGitHubWebhookSignature } from "../src/server.js";
import { loadConfig } from "../src/config.js";

async function testApp() {
  const store = new MemoryStore();
  const app = await buildApp({
    store,
    config: loadConfig({
      NODE_ENV: "test",
      PORT: "0",
      WEB_ORIGIN: "http://localhost:5173",
      PUBLIC_APP_URL: "http://localhost:5173",
      API_BASE_URL: "http://localhost:4000",
      SESSION_SECRET: "test-session-secret-32-bytes",
      GITHUB_WEBHOOK_SECRET: "test-webhook-secret",
      SCAN_REPO_ALLOWLIST: "anasm266/installsentry,anasm266/any-map",
    }),
  });
  await app.ready();
  const login = await app.inject({ method: "POST", url: "/auth/dev/login" });
  const cookie = login.headers["set-cookie"];
  return { app, store, cookie: Array.isArray(cookie) ? cookie[0] : cookie };
}

describe("SentinelFlow API", () => {
  it("allows public demo login without enabling production dev login", async () => {
    const store = new MemoryStore();
    const app = await buildApp({
      store,
      config: loadConfig({
        NODE_ENV: "production",
        PORT: "0",
        WEB_ORIGIN: "https://example.com",
        PUBLIC_APP_URL: "https://example.com",
        API_BASE_URL: "https://example.com",
        SESSION_SECRET: "test-session-secret-32-bytes",
        GITHUB_WEBHOOK_SECRET: "test-webhook-secret",
      }),
    });
    await app.ready();

    const dev = await app.inject({ method: "POST", url: "/auth/dev/login" });
    const demo = await app.inject({
      method: "POST",
      url: "/auth/demo/login",
    });
    const cookie = demo.headers["set-cookie"];
    const repos = await app.inject({
      method: "GET",
      url: "/v1/repos",
      headers: { cookie: Array.isArray(cookie) ? cookie[0] : (cookie ?? "") },
    });

    expect(dev.statusCode).toBe(404);
    expect(demo.statusCode).toBe(200);
    expect(demo.json().user.login).toBe("demo-reviewer");
    expect(
      repos.json().items.map((repo: { fullName: string }) => repo.fullName),
    ).toContain("sentinelflow-demo/risky-npm-app");
    await app.close();
  });

  it("requires auth for v1 routes and uses problem-json", async () => {
    const { app } = await testApp();
    const response = await app.inject({ method: "GET", url: "/v1/me" });

    expect(response.statusCode).toBe(401);
    expect(response.headers["content-type"]).toContain(
      "application/problem+json",
    );
    await app.close();
  });

  it("lists repos, emits etags, and returns 304 on match", async () => {
    const { app, cookie } = await testApp();
    const response = await app.inject({
      method: "GET",
      url: "/v1/repos",
      headers: { cookie: cookie ?? "" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers["etag"]).toBeDefined();
    expect(response.json().items.length).toBeGreaterThan(0);

    const cached = await app.inject({
      method: "GET",
      url: "/v1/repos",
      headers: {
        cookie: cookie ?? "",
        "if-none-match": String(response.headers["etag"]),
      },
    });
    expect(cached.statusCode).toBe(304);
    await app.close();
  });

  it("updates policy and queues manual scans idempotently", async () => {
    const { app, cookie } = await testApp();
    const repos = await app.inject({
      method: "GET",
      url: "/v1/repos",
      headers: { cookie: cookie ?? "" },
    });
    const repoId = repos.json().items[0].id as string;

    const policy = await app.inject({
      method: "PUT",
      url: `/v1/repos/${repoId}/policy`,
      headers: { cookie: cookie ?? "" },
      payload: {
        maxBlastRadius: 12,
        allowedNetworkHosts: ["registry.npmjs.org"],
      },
    });
    expect(policy.statusCode).toBe(200);
    expect(policy.json().maxBlastRadius).toBe(12);

    const first = await app.inject({
      method: "POST",
      url: `/v1/repos/${repoId}/scans`,
      headers: {
        cookie: cookie ?? "",
        "idempotency-key": "scan-once",
      },
      payload: { reason: "test" },
    });
    const second = await app.inject({
      method: "POST",
      url: `/v1/repos/${repoId}/scans`,
      headers: {
        cookie: cookie ?? "",
        "idempotency-key": "scan-once",
      },
      payload: { reason: "test" },
    });

    expect(first.statusCode).toBe(202);
    expect(second.statusCode).toBe(200);
    expect(first.json().scan.id).toBe(second.json().scan.id);
    await app.close();
  });

  it("verifies GitHub webhook signatures and queues PR scans", async () => {
    const { app } = await testApp();
    const payload = JSON.stringify({
      action: "opened",
      installation: { id: 123 },
      repository: {
        full_name: "anasm266/installsentry",
        default_branch: "master",
        private: false,
      },
      pull_request: {
        number: 9,
        head: { sha: "abc1234567" },
      },
    });

    const response = await app.inject({
      method: "POST",
      url: "/github/webhook",
      headers: {
        "content-type": "application/json",
        "x-github-event": "pull_request",
        "x-github-delivery": "delivery-1",
        "x-hub-signature-256": createGitHubWebhookSignature(
          "test-webhook-secret",
          payload,
        ),
      },
      payload,
    });

    expect(response.statusCode).toBe(202);
    await app.close();
  });

  it("rejects invalid GitHub webhook signatures", async () => {
    const { app } = await testApp();
    const response = await app.inject({
      method: "POST",
      url: "/github/webhook",
      headers: {
        "content-type": "application/json",
        "x-github-event": "pull_request",
        "x-hub-signature-256": "sha256=bad",
      },
      payload: {},
    });

    expect(response.statusCode).toBe(401);
    await app.close();
  });
});
