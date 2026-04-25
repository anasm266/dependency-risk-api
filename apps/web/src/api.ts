import type {
  AuditLog,
  CursorPage,
  Finding,
  Policy,
  Repo,
  Scan,
  WebhookDelivery,
  WebhookEndpoint,
} from "@sentinelflow/contracts";

const apiBase = import.meta.env["VITE_API_BASE_URL"] ?? "";

export interface User {
  id: string;
  login: string;
  avatarUrl: string | null;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "content-type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(
      body.detail ?? body.title ?? `request failed: ${response.status}`,
    );
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export function devLogin() {
  return api<{ user: User }>("/auth/dev/login", { method: "POST" });
}

export function demoLogin() {
  return api<{ user: User }>("/auth/demo/login", { method: "POST" });
}

export function me() {
  return api<{ user: User }>("/v1/me");
}

export function listRepos() {
  return api<CursorPage<Repo>>("/v1/repos");
}

export function getPolicy(repoId: string) {
  return api<Policy>(`/v1/repos/${repoId}/policy`);
}

export function updatePolicy(repoId: string, policy: Partial<Policy>) {
  return api<Policy>(`/v1/repos/${repoId}/policy`, {
    method: "PUT",
    body: JSON.stringify(policy),
  });
}

export function startScan(repoId: string) {
  return api<{ scan: Scan; jobId: string; reused: boolean }>(
    `/v1/repos/${repoId}/scans`,
    {
      method: "POST",
      headers: { "idempotency-key": crypto.randomUUID() },
      body: JSON.stringify({ reason: "dashboard" }),
    },
  );
}

export function getScan(scanId: string) {
  return api<Scan>(`/v1/scans/${scanId}`);
}

export function listFindings(scanId: string) {
  return api<{ items: Finding[] }>(`/v1/scans/${scanId}/findings`);
}

export function listWebhookEndpoints() {
  return api<{ items: WebhookEndpoint[] }>("/v1/webhook-endpoints");
}

export function createWebhookEndpoint(url: string, description?: string) {
  return api<WebhookEndpoint>("/v1/webhook-endpoints", {
    method: "POST",
    body: JSON.stringify({ url, description }),
  });
}

export function listWebhookDeliveries() {
  return api<{ items: WebhookDelivery[] }>("/v1/webhook-deliveries");
}

export function replayWebhookDelivery(deliveryId: string) {
  return api(`/v1/webhook-deliveries/${deliveryId}/replay`, {
    method: "POST",
    headers: { "idempotency-key": crypto.randomUUID() },
    body: "{}",
  });
}

export function listAuditLogs() {
  return api<CursorPage<AuditLog>>("/v1/audit-logs");
}
