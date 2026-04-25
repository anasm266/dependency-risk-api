import { describe, expect, it } from "vitest";
import { MemoryStore } from "@sentinelflow/db";
import { processNextJob } from "../src/worker.js";

describe("worker", () => {
  it("processes a scan job and persists policy findings", async () => {
    const store = new MemoryStore();
    const user = await store.seedDemoData();
    const repo = (await store.listRepos(user.id, { limit: 1 })).items[0]!;
    const { scan } = await store.createScan({
      userId: user.id,
      repoId: repo.id,
      source: "manual",
    });

    const processed = await processNextJob({
      store,
      config: {
        workerId: "test-worker",
        scanRepoAllowlist: new Set([repo.fullName]),
        scannerTimeoutMs: 100,
        scannerMaxOutputBytes: 1000,
      },
      scanner: async () => ({
        findings: [
          {
            ruleId: "secret_read",
            packageName: "bad-pkg",
            packageVersion: "1.0.0",
            evidence: { canary: "NPM_TOKEN" },
          },
        ],
      }),
    });

    expect(processed).toBe(true);
    const updated = await store.getScan(user.id, scan.id);
    expect(updated?.status).toBe("failed");
    const findings = await store.listFindings(user.id, scan.id);
    expect(findings[0]?.severity).toBe("critical");
  });
});
