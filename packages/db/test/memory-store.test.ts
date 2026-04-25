import { describe, expect, it } from "vitest";
import { MemoryStore } from "../src/index.js";

describe("MemoryStore", () => {
  it("queues scans idempotently and claims work once", async () => {
    const store = new MemoryStore();
    const { user } = await store.createSessionFromGitHub({
      githubId: "test-user",
      login: "test-user",
    });
    const repo = await store.upsertRepo({
      fullName: "example/npm-app",
      defaultBranch: "main",
      private: false,
      userId: user.id,
    });

    const first = await store.createScan({
      userId: user.id,
      repoId: repo.id,
      source: "manual",
      idempotencyKey: "same-request",
    });
    const second = await store.createScan({
      userId: user.id,
      repoId: repo.id,
      source: "manual",
      idempotencyKey: "same-request",
    });

    expect(first.scan.id).toBe(second.scan.id);
    expect(second.reused).toBe(true);

    const claimed = await store.claimJob("worker-1", ["manual_scan"]);
    expect(claimed?.id).toBe(first.job.id);
    expect(await store.claimJob("worker-2", ["manual_scan"])).toBeNull();

    const logs = await store.listAuditLogs(user.id, { limit: 10 });
    expect(logs.items[0]).toMatchObject({
      action: "scan.queued",
      repoFullName: repo.fullName,
    });
  });

  it("persists scan findings and queues webhook deliveries", async () => {
    const store = new MemoryStore();
    const { user } = await store.createSessionFromGitHub({
      githubId: "webhook-test-user",
      login: "webhook-test-user",
    });
    await store.createWebhookEndpoint({
      userId: user.id,
      url: "https://example.com/webhook",
      description: "test",
    });
    const repo = await store.upsertRepo({
      fullName: "example/webhook-app",
      defaultBranch: "main",
      private: false,
      userId: user.id,
    });
    const { scan } = await store.createScan({
      userId: user.id,
      repoId: repo.id,
      source: "manual",
    });

    await store.finishScan({
      scanId: scan.id,
      status: "failed",
      findings: [
        {
          ruleId: "secret_read",
          packageName: "bad-pkg",
          packageVersion: "1.0.0",
          evidence: { canary: "NPM_TOKEN" },
          severity: "critical",
          title: "bad-pkg read a secret canary",
        },
      ],
    });

    const findings = await store.listFindings(user.id, scan.id);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
    expect(await store.listWebhookDeliveries(user.id)).toHaveLength(1);
  });

  it("seeds a reviewer demo with sample repos, findings, and deliveries", async () => {
    const store = new MemoryStore();
    const user = await store.seedDemoData();
    const repos = await store.listRepos(user.id, { limit: 10 });
    const riskyRepo = repos.items.find(
      (repo) => repo.fullName === "sentinelflow-demo/risky-npm-app",
    );

    expect(user.login).toBe("demo-reviewer");
    expect(repos.items.map((repo) => repo.fullName)).toEqual([
      "sentinelflow-demo/clean-npm-service",
      "sentinelflow-demo/pnpm-library",
      "sentinelflow-demo/risky-npm-app",
    ]);
    expect(riskyRepo?.latestScanStatus).toBe("failed");
    expect(await store.listWebhookDeliveries(user.id)).not.toHaveLength(0);
  });

  it("dead-letters repeatedly failing jobs", async () => {
    const store = new MemoryStore();
    const job = await store.enqueueJob({
      type: "manual_scan",
      payload: {},
      maxAttempts: 1,
    });

    await store.failJob(job.id, "boom");
    const claimed = await store.claimJob("worker", ["manual_scan"]);
    expect(claimed).toBeNull();
  });
});
