import { describe, expect, it } from "vitest";
import { PostgresStore, createPool } from "../src/index.js";

const databaseUrl = process.env["DATABASE_URL"];
const describeIfDatabase = databaseUrl ? describe : describe.skip;

describeIfDatabase("PostgresStore integration", () => {
  it("creates sessions, repos, policies, scans, findings, and webhook deliveries", async () => {
    const store = new PostgresStore(createPool(databaseUrl!));
    try {
      const { user } = await store.createSessionFromGitHub({
        githubId: `test-${crypto.randomUUID()}`,
        login: "integration-test",
        avatarUrl: null,
      });
      const repo = await store.upsertRepo({
        fullName: `anasm266/integration-${crypto.randomUUID()}`,
        defaultBranch: "main",
        private: false,
        userId: user.id,
      });
      await store.updatePolicy(user.id, repo.id, { maxBlastRadius: 7 });
      expect(await store.getPolicy(repo.id)).toMatchObject({
        maxBlastRadius: 7,
      });

      await store.createWebhookEndpoint({
        userId: user.id,
        url: "https://example.com/sentinelflow",
        description: "integration",
      });
      const { scan } = await store.createScan({
        userId: user.id,
        repoId: repo.id,
        source: "manual",
        idempotencyKey: "integration-once",
      });
      const duplicate = await store.createScan({
        userId: user.id,
        repoId: repo.id,
        source: "manual",
        idempotencyKey: "integration-once",
      });

      expect(duplicate.reused).toBe(true);
      expect(duplicate.scan.id).toBe(scan.id);

      const claimed = await store.claimJob("pg-worker", ["manual_scan"]);
      expect(claimed?.payload["scanId"]).toBe(scan.id);

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

      const auditLogs = await store.listAuditLogs(user.id, { limit: 25 });
      expect(
        auditLogs.items.some(
          (log) =>
            log.action === "scan.queued" &&
            log.repoId === repo.id &&
            log.repoFullName === repo.fullName,
        ),
      ).toBe(true);

      const deliveries = await store.listWebhookDeliveries(user.id);
      expect(deliveries.length).toBeGreaterThan(0);
      const work = await store.getWebhookDeliveryWork(deliveries[0]!.id);
      expect(work?.endpointUrl).toBe("https://example.com/sentinelflow");
    } finally {
      await store.close();
    }
  });
});
