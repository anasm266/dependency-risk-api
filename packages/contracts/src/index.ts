import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";

export const severitySchema = z.enum(["low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof severitySchema>;

export const scanStatusSchema = z.enum([
  "queued",
  "running",
  "succeeded",
  "failed",
  "unsupported",
]);
export type ScanStatus = z.infer<typeof scanStatusSchema>;

export const jobStatusSchema = z.enum([
  "queued",
  "running",
  "succeeded",
  "failed",
  "dead_lettered",
]);
export type JobStatus = z.infer<typeof jobStatusSchema>;

export const policySchema = z.object({
  blockLifecycleScripts: z.boolean().default(true),
  blockSecretReads: z.boolean().default(true),
  allowedNetworkHosts: z
    .array(z.string().min(1))
    .default(["registry.npmjs.org"]),
  maxBlastRadius: z.number().int().min(0).max(1000).default(40),
  requireApprovalForNewRiskyPackages: z.boolean().default(true),
});
export type Policy = z.infer<typeof policySchema>;

export const defaultPolicy: Policy = policySchema.parse({});

export const repoSchema = z.object({
  id: z.string().uuid(),
  fullName: z.string(),
  provider: z.literal("github"),
  defaultBranch: z.string(),
  private: z.boolean(),
  installationId: z.string().nullable(),
  latestScanStatus: scanStatusSchema.nullable(),
  latestScanId: z.string().uuid().nullable(),
  updatedAt: z.string(),
});
export type Repo = z.infer<typeof repoSchema>;

export const findingSchema = z.object({
  id: z.string().uuid(),
  scanId: z.string().uuid(),
  severity: severitySchema,
  ruleId: z.string(),
  packageName: z.string(),
  packageVersion: z.string().nullable(),
  title: z.string(),
  evidence: z.record(z.unknown()),
  createdAt: z.string(),
});
export type Finding = z.infer<typeof findingSchema>;

export const scanSchema = z.object({
  id: z.string().uuid(),
  repoId: z.string().uuid(),
  status: scanStatusSchema,
  source: z.enum(["manual", "pull_request", "push"]),
  commitSha: z.string().nullable(),
  pullRequestNumber: z.number().int().positive().nullable(),
  startedAt: z.string().nullable(),
  finishedAt: z.string().nullable(),
  createdAt: z.string(),
});
export type Scan = z.infer<typeof scanSchema>;

export const auditLogSchema = z.object({
  id: z.string().uuid(),
  actorUserId: z.string().uuid().nullable(),
  repoId: z.string().uuid().nullable(),
  action: z.string(),
  metadata: z.record(z.unknown()),
  createdAt: z.string(),
});
export type AuditLog = z.infer<typeof auditLogSchema>;

export const webhookEndpointSchema = z.object({
  id: z.string().uuid(),
  url: z.string().url(),
  active: z.boolean(),
  description: z.string().nullable(),
  createdAt: z.string(),
});
export type WebhookEndpoint = z.infer<typeof webhookEndpointSchema>;

export const webhookDeliverySchema = z.object({
  id: z.string().uuid(),
  endpointId: z.string().uuid(),
  eventType: z.string(),
  status: z.enum(["queued", "delivered", "failed"]),
  attempt: z.number().int().min(0),
  statusCode: z.number().int().nullable(),
  latencyMs: z.number().int().nullable(),
  responseExcerpt: z.string().nullable(),
  createdAt: z.string(),
});
export type WebhookDelivery = z.infer<typeof webhookDeliverySchema>;

export const manualScanRequestSchema = z.object({
  commitSha: z.string().min(7).max(64).optional(),
  reason: z.string().max(200).optional(),
});
export type ManualScanRequest = z.infer<typeof manualScanRequestSchema>;

export const updatePolicyRequestSchema = policySchema.partial().strict();
export type UpdatePolicyRequest = z.infer<typeof updatePolicyRequestSchema>;

export const createWebhookEndpointRequestSchema = z.object({
  url: z.string().url(),
  description: z.string().max(200).optional(),
});
export type CreateWebhookEndpointRequest = z.infer<
  typeof createWebhookEndpointRequestSchema
>;

export interface CursorPage<T> {
  items: T[];
  nextCursor: string | null;
}

export interface ProblemJson {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
}

export interface ScannerFindingInput {
  ruleId: string;
  packageName: string;
  packageVersion?: string | null;
  evidence: Record<string, unknown>;
  blastRadius?: number;
  isNewPackage?: boolean;
}

export interface PolicyFinding extends ScannerFindingInput {
  severity: Severity;
  title: string;
}

const severityRank: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function highestSeverity(
  findings: Array<{ severity: Severity }>,
): Severity | null {
  let highest: Severity | null = null;
  for (const finding of findings) {
    if (!highest || severityRank[finding.severity] > severityRank[highest]) {
      highest = finding.severity;
    }
  }
  return highest;
}

export function evaluatePolicy(
  policy: Policy,
  scannerFindings: ScannerFindingInput[],
): PolicyFinding[] {
  const findings: PolicyFinding[] = [];

  for (const finding of scannerFindings) {
    if (finding.ruleId === "lifecycle_script" && policy.blockLifecycleScripts) {
      findings.push({
        ...finding,
        severity: "high",
        title: `${finding.packageName} runs npm lifecycle scripts`,
      });
    }

    if (finding.ruleId === "secret_read" && policy.blockSecretReads) {
      findings.push({
        ...finding,
        severity: "critical",
        title: `${finding.packageName} read a secret canary`,
      });
    }

    if (finding.ruleId === "network_egress") {
      const host = String(finding.evidence["host"] ?? "");
      if (host && !policy.allowedNetworkHosts.includes(host)) {
        findings.push({
          ...finding,
          severity: "high",
          title: `${finding.packageName} contacted ${host}`,
        });
      }
    }

    if (
      finding.ruleId === "blast_radius" &&
      typeof finding.blastRadius === "number" &&
      finding.blastRadius > policy.maxBlastRadius
    ) {
      findings.push({
        ...finding,
        severity: finding.blastRadius >= 100 ? "critical" : "medium",
        title: `${finding.packageName} exceeds blast-radius threshold`,
      });
    }

    if (
      finding.isNewPackage &&
      policy.requireApprovalForNewRiskyPackages &&
      ["lifecycle_script", "network_egress", "secret_read"].includes(
        finding.ruleId,
      )
    ) {
      findings.push({
        ...finding,
        severity: "medium",
        title: `${finding.packageName} is a new risky dependency`,
      });
    }
  }

  return dedupePolicyFindings(findings);
}

function dedupePolicyFindings(findings: PolicyFinding[]): PolicyFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = [
      finding.ruleId,
      finding.packageName,
      finding.packageVersion ?? "",
      finding.title,
    ].join("\0");
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

export function encodeCursor(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

export function decodeCursor(cursor: string | undefined): string | null {
  if (!cursor) {
    return null;
  }
  try {
    return Buffer.from(cursor, "base64url").toString("utf8");
  } catch {
    return null;
  }
}

export function pageItems<T extends { id: string }>(
  items: T[],
  limit: number,
  cursor?: string,
): CursorPage<T> {
  const decoded = decodeCursor(cursor);
  const startIndex = decoded
    ? items.findIndex((item) => item.id === decoded) + 1
    : 0;
  const page = items.slice(
    Math.max(0, startIndex),
    Math.max(0, startIndex) + limit,
  );
  const last = page[page.length - 1];
  return {
    items: page,
    nextCursor: page.length === limit && last ? encodeCursor(last.id) : null,
  };
}

export function problem(
  status: number,
  title: string,
  detail?: string,
  type = "about:blank",
): ProblemJson {
  return {
    type,
    title,
    status,
    ...(detail ? { detail } : {}),
  };
}

export function weakEtag(input: unknown): string {
  const body = typeof input === "string" ? input : JSON.stringify(input);
  const digest = createHash("sha256").update(body).digest("base64url");
  return `W/"${digest}"`;
}

export function signHmacSha256(secret: string, body: string | Buffer): string {
  const digest = createHmac("sha256", secret).update(body).digest("hex");
  return `sha256=${digest}`;
}

export function verifyHmacSha256(
  secret: string,
  body: string | Buffer,
  signature: string | undefined,
): boolean {
  if (!secret || !signature?.startsWith("sha256=")) {
    return false;
  }
  const expected = signHmacSha256(secret, body);
  const expectedBytes = Buffer.from(expected);
  const actualBytes = Buffer.from(signature);
  return (
    expectedBytes.length === actualBytes.length &&
    timingSafeEqual(expectedBytes, actualBytes)
  );
}

export function normalizeLimit(
  value: string | undefined,
  fallback = 25,
  max = 100,
): number {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.min(parsed, max);
}

export function nowIso(): string {
  return new Date().toISOString();
}
