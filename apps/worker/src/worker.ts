import {
  evaluatePolicy,
  groupFindings,
  highestSeverity,
  signHmacSha256,
  type ScannerFindingInput,
} from "@sentinelflow/contracts";
import { createSign } from "node:crypto";
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
  githubAppId?: string | undefined;
  githubAppPrivateKey?: string | undefined;
  publicAppUrl: string;
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
    await processGitHubCheckUpdate(job, deps);
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
    const findingGroups = groupFindings(findings);
    await deps.store.finishScan({
      scanId,
      status: findings.length ? "failed" : "succeeded",
      findings,
    });
    await deps.store.enqueueJob({
      type: "github_check_update",
      payload: {
        scanId,
        userId,
        repoFullName: repo.fullName,
        installationId: repo.installationId,
        commitSha: job.payload["commitSha"],
        conclusion: findings.length ? "failure" : "success",
        highestSeverity: highestSeverity(findings),
        findingCount: findingGroups.length,
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

async function processGitHubCheckUpdate(job: JobRecord, deps: WorkerDeps) {
  if (!deps.config.githubAppId || !deps.config.githubAppPrivateKey) {
    return;
  }
  const repoFullName = requireString(
    job.payload["repoFullName"],
    "repoFullName",
  );
  const installationId = requireString(
    job.payload["installationId"],
    "installationId",
  );
  const commitSha = requireString(job.payload["commitSha"], "commitSha");
  const scanId =
    typeof job.payload["scanId"] === "string" ? job.payload["scanId"] : null;
  const conclusion = normalizeConclusion(job.payload["conclusion"]);
  const findingCount = Number(job.payload["findingCount"] ?? 0);
  const highestSeverity =
    typeof job.payload["highestSeverity"] === "string"
      ? job.payload["highestSeverity"]
      : "none";
  const [owner, repo] = repoFullName.split("/");
  if (!owner || !repo) {
    throw new Error(`invalid repo full name: ${repoFullName}`);
  }

  const token = await createInstallationToken({
    appId: deps.config.githubAppId,
    privateKey: deps.config.githubAppPrivateKey,
    installationId,
  });
  const detailsUrl = scanId
    ? `${deps.config.publicAppUrl.replace(/\/$/, "")}/?scan=${encodeURIComponent(scanId)}`
    : deps.config.publicAppUrl;
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/check-runs`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "content-type": "application/json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "SentinelFlow/0.1",
      },
      body: JSON.stringify({
        name: "SentinelFlow dependency policy",
        head_sha: commitSha,
        status: "completed",
        conclusion,
        details_url: detailsUrl,
        output: {
          title:
            conclusion === "success"
              ? "Dependency policy passed"
              : "Dependency policy needs review",
          summary:
            conclusion === "success"
              ? "SentinelFlow did not find policy-blocking npm install risk."
              : `SentinelFlow found ${findingCount} policy finding(s). Highest severity: ${highestSeverity}.`,
        },
      }),
    },
  );
  if (!response.ok) {
    throw new Error(
      `GitHub check-run update failed with ${response.status}: ${await response.text()}`,
    );
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
    githubAppId: env["GITHUB_APP_ID"],
    githubAppPrivateKey: normalizePrivateKey(env["GITHUB_APP_PRIVATE_KEY"]),
    publicAppUrl:
      env["PUBLIC_APP_URL"] ?? env["API_BASE_URL"] ?? "http://localhost:5173",
  };
}

async function createInstallationToken(input: {
  appId: string;
  privateKey: string;
  installationId: string;
}) {
  const jwt = createGitHubAppJwt(input.appId, input.privateKey);
  const response = await fetch(
    `https://api.github.com/app/installations/${input.installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${jwt}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "SentinelFlow/0.1",
      },
    },
  );
  if (!response.ok) {
    throw new Error(
      `GitHub installation token failed with ${response.status}: ${await response.text()}`,
    );
  }
  const body = (await response.json()) as { token?: string };
  if (!body.token) {
    throw new Error("GitHub installation token response did not include token");
  }
  return body.token;
}

function createGitHubAppJwt(appId: string, privateKey: string) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(
    JSON.stringify({ alg: "RS256", typ: "JWT" }),
  ).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      iat: now - 60,
      exp: now + 9 * 60,
      iss: appId,
    }),
  ).toString("base64url");
  const data = `${header}.${payload}`;
  const signature = createSign("RSA-SHA256")
    .update(data)
    .sign(privateKey, "base64url");
  return `${data}.${signature}`;
}

function normalizePrivateKey(value: string | undefined) {
  return value?.replace(/\\n/g, "\n").trim();
}

function normalizeConclusion(
  value: unknown,
): "success" | "failure" | "neutral" {
  return value === "success" || value === "failure" || value === "neutral"
    ? value
    : "neutral";
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
