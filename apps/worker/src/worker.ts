import {
  evaluatePolicy,
  highestSeverity,
  signHmacSha256,
  type ScannerFindingInput,
} from "@sentinelflow/contracts";
import type { JobRecord, SentinelStore } from "@sentinelflow/db";
import {
  runScanner,
  ScannerUnsupportedError,
  type ScannerOptions,
} from "./scanner.js";

export interface WorkerConfig {
  workerId: string;
  scanRepoAllowlist: Set<string>;
  scannerTimeoutMs: number;
  scannerMaxOutputBytes: number;
  scannerFixtureDir?: string | undefined;
  githubToken?: string | undefined;
}

export interface WorkerDeps {
  store: SentinelStore;
  config: WorkerConfig;
  scanner?: (
    options: ScannerOptions,
  ) => Promise<{ findings: ScannerFindingInput[] }>;
}

export async function processNextJob(deps: WorkerDeps): Promise<boolean> {
  const job = await deps.store.claimJob(deps.config.workerId, [
    "manual_scan",
    "pr_scan",
    "webhook_delivery",
    "github_check_update",
  ]);
  if (!job) {
    return false;
  }

  try {
    await processJob(job, deps);
    await deps.store.completeJob(job.id);
    return true;
  } catch (error) {
    await deps.store.failJob(
      job.id,
      error instanceof Error ? error.message : String(error),
    );
    return true;
  }
}

export async function processJob(
  job: JobRecord,
  deps: WorkerDeps,
): Promise<void> {
  if (job.type === "manual_scan" || job.type === "pr_scan") {
    await processScanJob(job, deps);
    return;
  }
  if (job.type === "webhook_delivery") {
    await processWebhookDelivery(job, deps);
    return;
  }
  if (job.type === "github_check_update") {
    // GitHub App check-run mutation is intentionally isolated for credentialed deployment.
    return;
  }
  throw new Error(`unknown job type: ${job.type}`);
}

async function processScanJob(job: JobRecord, deps: WorkerDeps) {
  const scanId = requireString(job.payload["scanId"], "scanId");
  const repoId = requireString(job.payload["repoId"], "repoId");
  const userId = requireString(job.payload["userId"], "userId");
  const repo = await deps.store.getRepo(userId, repoId);
  if (!repo) {
    throw new Error("repo not found for scan job");
  }
  if (!deps.config.scanRepoAllowlist.has(repo.fullName)) {
    await deps.store.finishScan({
      scanId,
      status: "unsupported",
      findings: [],
      error: "repo is not allowlisted",
    });
    return;
  }

  try {
    const scanner = deps.scanner ?? runScanner;
    const scannerOptions: ScannerOptions = {
      repoFullName: repo.fullName,
      commitSha: nullableString(job.payload["commitSha"]),
      timeoutMs: deps.config.scannerTimeoutMs,
      maxOutputBytes: deps.config.scannerMaxOutputBytes,
    };
    if (deps.config.scannerFixtureDir) {
      scannerOptions.fixtureDir = deps.config.scannerFixtureDir;
    }
    if (deps.config.githubToken) {
      scannerOptions.githubToken = deps.config.githubToken;
    }
    const result = await scanner(scannerOptions);
    const policy = await deps.store.getPolicy(repo.id);
    const findings = evaluatePolicy(policy, result.findings);
    await deps.store.finishScan({
      scanId,
      status: findings.length ? "failed" : "succeeded",
      findings,
    });
    await deps.store.enqueueJob({
      type: "github_check_update",
      payload: {
        scanId,
        repoFullName: repo.fullName,
        conclusion: findings.length ? "failure" : "success",
        highestSeverity: highestSeverity(findings),
        findingCount: findings.length,
      },
    });
  } catch (error) {
    if (error instanceof ScannerUnsupportedError) {
      await deps.store.finishScan({
        scanId,
        status: "unsupported",
        findings: [],
        error: error.message,
      });
      return;
    }
    throw error;
  }
}

async function processWebhookDelivery(job: JobRecord, deps: WorkerDeps) {
  const deliveryId = requireString(job.payload["deliveryId"], "deliveryId");
  const work = await deps.store.getWebhookDeliveryWork(deliveryId);
  if (!work) {
    throw new Error("webhook delivery work not found");
  }

  const payload = JSON.stringify({
    id: work.eventId,
    type: work.eventType,
    createdAt: new Date().toISOString(),
    data: work.payload,
  });
  const started = Date.now();
  const response = await fetch(work.endpointUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "user-agent": "SentinelFlow/0.1",
      "x-sentinelflow-event": work.eventType,
      "x-sentinelflow-delivery": work.deliveryId,
      "x-sentinelflow-signature-256": signHmacSha256(
        work.endpointSecret,
        payload,
      ),
    },
    body: payload,
  });
  const responseText = await response.text();
  await deps.store.recordWebhookDelivery({
    deliveryId,
    status: response.ok ? "delivered" : "failed",
    statusCode: response.status,
    latencyMs: Date.now() - started,
    responseExcerpt: responseText.slice(0, 500),
  });
  if (!response.ok) {
    throw new Error(`webhook delivery failed with ${response.status}`);
  }
}

export function loadWorkerConfig(env = process.env): WorkerConfig {
  return {
    workerId: env["WORKER_ID"] ?? `worker-${process.pid}`,
    scanRepoAllowlist: new Set(
      (env["SCAN_REPO_ALLOWLIST"] ?? "anasm266/installsentry,anasm266/any-map")
        .split(",")
        .map((repo) => repo.trim())
        .filter(Boolean),
    ),
    scannerTimeoutMs: Number.parseInt(
      env["SCANNER_TIMEOUT_MS"] ?? "120000",
      10,
    ),
    scannerMaxOutputBytes: Number.parseInt(
      env["SCANNER_MAX_OUTPUT_BYTES"] ?? "200000",
      10,
    ),
    scannerFixtureDir: env["SCANNER_FIXTURE_DIR"],
    githubToken: env["GITHUB_TOKEN"],
  };
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string" || !value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}
