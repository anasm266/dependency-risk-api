import { randomBytes, randomUUID } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import {
  defaultPolicy,
  nowIso,
  pageItems,
  type AuditLog,
  type CursorPage,
  type Finding,
  type JobStatus,
  type Policy,
  type PolicyFinding,
  type Repo,
  type Scan,
  type ScanStatus,
  type WebhookDelivery,
  type WebhookEndpoint,
} from "@sentinelflow/contracts";

const { Pool } = pg;

export interface UserRecord {
  id: string;
  githubId: string;
  login: string;
  avatarUrl: string | null;
  createdAt: string;
}

export interface SessionRecord {
  id: string;
  userId: string;
  expiresAt: string;
  createdAt: string;
}

export interface GitHubProfile {
  githubId: string;
  login: string;
  avatarUrl?: string | null;
}

export interface UpsertRepoInput {
  fullName: string;
  defaultBranch?: string;
  private?: boolean;
  installationId?: string | null;
  userId?: string;
}

export interface CreateScanInput {
  userId: string;
  repoId: string;
  source: "manual" | "pull_request" | "push";
  commitSha?: string | null;
  pullRequestNumber?: number | null;
  idempotencyKey?: string;
  reason?: string;
}

export interface JobRecord {
  id: string;
  type: string;
  status: JobStatus;
  payload: Record<string, unknown>;
  attempts: number;
  maxAttempts: number;
  runAt: string;
  lockedAt: string | null;
  lockedBy: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface OutboxEventRecord {
  id: string;
  eventType: string;
  payload: Record<string, unknown>;
  status: "queued" | "processing" | "delivered" | "failed";
  attempts: number;
  createdAt: string;
  updatedAt: string;
}

export interface SentinelStore {
  mode: "memory" | "postgres";
  health(): Promise<{ ok: boolean; mode: "memory" | "postgres" }>;
  close(): Promise<void>;
  seedDemoData(): Promise<UserRecord>;
  createSessionFromGitHub(profile: GitHubProfile): Promise<{
    user: UserRecord;
    session: SessionRecord;
  }>;
  getUserBySession(sessionId: string): Promise<UserRecord | null>;
  deleteSession(sessionId: string): Promise<void>;
  upsertInstallation(input: {
    id: string;
    accountLogin: string;
    accountType: string;
    suspendedAt?: string | null;
  }): Promise<void>;
  upsertRepo(input: UpsertRepoInput): Promise<Repo>;
  listRepos(userId: string, options: ListOptions): Promise<CursorPage<Repo>>;
  getRepo(userId: string, repoId: string): Promise<Repo | null>;
  getPolicy(repoId: string): Promise<Policy>;
  updatePolicy(
    userId: string,
    repoId: string,
    patch: Partial<Policy>,
  ): Promise<Policy>;
  createScan(input: CreateScanInput): Promise<{
    scan: Scan;
    job: JobRecord;
    reused: boolean;
  }>;
  getScan(userId: string, scanId: string): Promise<Scan | null>;
  listFindings(userId: string, scanId: string): Promise<Finding[]>;
  finishScan(input: {
    scanId: string;
    status: ScanStatus;
    findings: PolicyFinding[];
    error?: string | null;
  }): Promise<void>;
  listAuditLogs(
    userId: string,
    options: ListOptions,
  ): Promise<CursorPage<AuditLog>>;
  createWebhookEndpoint(input: {
    userId: string;
    url: string;
    description?: string | null;
  }): Promise<WebhookEndpoint>;
  listWebhookEndpoints(userId: string): Promise<WebhookEndpoint[]>;
  listWebhookDeliveries(userId: string): Promise<WebhookDelivery[]>;
  replayWebhookDelivery(input: {
    userId: string;
    deliveryId: string;
    idempotencyKey?: string;
  }): Promise<{ delivery: WebhookDelivery; job: JobRecord; reused: boolean }>;
  enqueueJob(input: {
    type: string;
    payload: Record<string, unknown>;
    runAt?: string;
    maxAttempts?: number;
  }): Promise<JobRecord>;
  claimJob(workerId: string, types?: string[]): Promise<JobRecord | null>;
  completeJob(jobId: string): Promise<void>;
  failJob(jobId: string, error: string): Promise<void>;
  enqueueOutboxEvent(input: {
    eventType: string;
    payload: Record<string, unknown>;
  }): Promise<OutboxEventRecord>;
  claimOutboxEvent(workerId: string): Promise<OutboxEventRecord | null>;
  markOutboxEventDelivered(eventId: string): Promise<void>;
  createWebhookDeliveriesForEvent(
    event: OutboxEventRecord,
  ): Promise<WebhookDelivery[]>;
  recordWebhookDelivery(input: {
    deliveryId: string;
    status: "delivered" | "failed";
    statusCode?: number | null;
    latencyMs?: number | null;
    responseExcerpt?: string | null;
  }): Promise<void>;
  getWebhookDeliveryWork(deliveryId: string): Promise<{
    deliveryId: string;
    endpointUrl: string;
    endpointSecret: string;
    eventId: string;
    eventType: string;
    payload: Record<string, unknown>;
  } | null>;
}

export interface ListOptions {
  limit: number;
  cursor?: string;
}

export class MemoryStore implements SentinelStore {
  readonly mode = "memory" as const;
  private users = new Map<string, UserRecord>();
  private usersByGithub = new Map<string, string>();
  private sessions = new Map<string, SessionRecord>();
  private installations = new Map<
    string,
    { id: string; accountLogin: string; accountType: string }
  >();
  private repos = new Map<string, Repo>();
  private reposByFullName = new Map<string, string>();
  private memberships = new Map<string, Set<string>>();
  private policies = new Map<string, Policy>();
  private scans = new Map<string, Scan & { error?: string | null }>();
  private findings = new Map<string, Finding[]>();
  private auditLogs: AuditLog[] = [];
  private webhookEndpoints = new Map<
    string,
    WebhookEndpoint & { userId: string; secret: string }
  >();
  private webhookDeliveries = new Map<
    string,
    WebhookDelivery & { userId: string; outboxEventId: string }
  >();
  private jobs = new Map<string, JobRecord>();
  private outboxEvents = new Map<string, OutboxEventRecord>();
  private idempotency = new Map<string, unknown>();

  async health() {
    return { ok: true, mode: this.mode };
  }

  async close() {
    return;
  }

  async seedDemoData(): Promise<UserRecord> {
    const { user } = await this.createSessionFromGitHub({
      githubId: "dev-user",
      login: "anasm266",
      avatarUrl: null,
    });

    await this.upsertRepo({
      fullName: "anasm266/installsentry",
      defaultBranch: "master",
      private: false,
      userId: user.id,
    });
    await this.upsertRepo({
      fullName: "anasm266/any-map",
      defaultBranch: "main",
      private: false,
      userId: user.id,
    });

    return user;
  }

  async createSessionFromGitHub(profile: GitHubProfile) {
    let userId = this.usersByGithub.get(profile.githubId);
    if (!userId) {
      userId = randomUUID();
      const user: UserRecord = {
        id: userId,
        githubId: profile.githubId,
        login: profile.login,
        avatarUrl: profile.avatarUrl ?? null,
        createdAt: nowIso(),
      };
      this.users.set(userId, user);
      this.usersByGithub.set(profile.githubId, userId);
    }

    const user = this.users.get(userId);
    if (!user) {
      throw new Error("user insert failed");
    }

    const session: SessionRecord = {
      id: randomBytes(32).toString("base64url"),
      userId,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 14).toISOString(),
      createdAt: nowIso(),
    };
    this.sessions.set(session.id, session);
    return { user, session };
  }

  async getUserBySession(sessionId: string) {
    const session = this.sessions.get(sessionId);
    if (!session || Date.parse(session.expiresAt) <= Date.now()) {
      return null;
    }
    return this.users.get(session.userId) ?? null;
  }

  async deleteSession(sessionId: string) {
    this.sessions.delete(sessionId);
  }

  async upsertInstallation(input: {
    id: string;
    accountLogin: string;
    accountType: string;
    suspendedAt?: string | null;
  }) {
    this.installations.set(input.id, {
      id: input.id,
      accountLogin: input.accountLogin,
      accountType: input.accountType,
    });
  }

  async upsertRepo(input: UpsertRepoInput): Promise<Repo> {
    const existingId = this.reposByFullName.get(input.fullName);
    const id = existingId ?? randomUUID();
    const existing = existingId ? this.repos.get(existingId) : null;
    const repo: Repo = {
      id,
      fullName: input.fullName,
      provider: "github",
      defaultBranch: input.defaultBranch ?? existing?.defaultBranch ?? "main",
      private: input.private ?? existing?.private ?? false,
      installationId: input.installationId ?? existing?.installationId ?? null,
      latestScanId: existing?.latestScanId ?? null,
      latestScanStatus: existing?.latestScanStatus ?? null,
      updatedAt: nowIso(),
    };
    this.repos.set(id, repo);
    this.reposByFullName.set(input.fullName, id);
    this.policies.set(id, this.policies.get(id) ?? defaultPolicy);

    if (input.userId) {
      const set = this.memberships.get(input.userId) ?? new Set<string>();
      set.add(id);
      this.memberships.set(input.userId, set);
    }

    return repo;
  }

  async listRepos(
    userId: string,
    options: ListOptions,
  ): Promise<CursorPage<Repo>> {
    const repoIds = this.memberships.get(userId) ?? new Set<string>();
    const repos = [...repoIds]
      .map((id) => this.repos.get(id))
      .filter((repo): repo is Repo => Boolean(repo))
      .sort((a, b) => a.fullName.localeCompare(b.fullName));
    return pageItems(repos, options.limit, options.cursor);
  }

  async getRepo(userId: string, repoId: string): Promise<Repo | null> {
    if (!this.memberships.get(userId)?.has(repoId)) {
      return null;
    }
    return this.repos.get(repoId) ?? null;
  }

  async getPolicy(repoId: string): Promise<Policy> {
    const policy = this.policies.get(repoId) ?? defaultPolicy;
    this.policies.set(repoId, policy);
    return policy;
  }

  async updatePolicy(
    userId: string,
    repoId: string,
    patch: Partial<Policy>,
  ): Promise<Policy> {
    if (!this.memberships.get(userId)?.has(repoId)) {
      throw new Error("repo not found");
    }
    const policy = { ...(await this.getPolicy(repoId)), ...patch };
    this.policies.set(repoId, policy);
    this.auditLogs.unshift({
      id: randomUUID(),
      actorUserId: userId,
      repoId,
      action: "policy.updated",
      metadata: patch,
      createdAt: nowIso(),
    });
    return policy;
  }

  async createScan(input: CreateScanInput) {
    const scope = `scan:${input.userId}:${input.repoId}`;
    const idem = input.idempotencyKey
      ? `${scope}:${input.idempotencyKey}`
      : null;
    const cached = idem ? this.idempotency.get(idem) : null;
    if (cached) {
      return { ...(cached as { scan: Scan; job: JobRecord }), reused: true };
    }

    const scan: Scan = {
      id: randomUUID(),
      repoId: input.repoId,
      status: "queued",
      source: input.source,
      commitSha: input.commitSha ?? null,
      pullRequestNumber: input.pullRequestNumber ?? null,
      startedAt: null,
      finishedAt: null,
      createdAt: nowIso(),
    };
    this.scans.set(scan.id, scan);
    this.findings.set(scan.id, []);

    const repo = this.repos.get(input.repoId);
    if (repo) {
      this.repos.set(repo.id, {
        ...repo,
        latestScanId: scan.id,
        latestScanStatus: scan.status,
        updatedAt: nowIso(),
      });
    }

    const job = await this.enqueueJob({
      type: input.source === "pull_request" ? "pr_scan" : "manual_scan",
      payload: {
        scanId: scan.id,
        repoId: input.repoId,
        userId: input.userId,
        commitSha: input.commitSha ?? null,
        pullRequestNumber: input.pullRequestNumber ?? null,
      },
    });

    this.auditLogs.unshift({
      id: randomUUID(),
      actorUserId: input.userId,
      repoId: input.repoId,
      action: "scan.queued",
      metadata: {
        scanId: scan.id,
        source: input.source,
        reason: input.reason ?? null,
      },
      createdAt: nowIso(),
    });

    if (idem) {
      this.idempotency.set(idem, { scan, job });
    }

    return { scan, job, reused: false };
  }

  async getScan(userId: string, scanId: string) {
    const scan = this.scans.get(scanId);
    if (!scan || !this.memberships.get(userId)?.has(scan.repoId)) {
      return null;
    }
    return scan;
  }

  async listFindings(userId: string, scanId: string) {
    const scan = await this.getScan(userId, scanId);
    if (!scan) {
      return [];
    }
    return this.findings.get(scanId) ?? [];
  }

  async finishScan(input: {
    scanId: string;
    status: ScanStatus;
    findings: PolicyFinding[];
    error?: string | null;
  }) {
    const scan = this.scans.get(input.scanId);
    if (!scan) {
      return;
    }
    const finished: Scan = {
      ...scan,
      status: input.status,
      startedAt: scan.startedAt ?? nowIso(),
      finishedAt: nowIso(),
    };
    this.scans.set(scan.id, finished);
    const repo = this.repos.get(scan.repoId);
    if (repo) {
      this.repos.set(repo.id, {
        ...repo,
        latestScanId: scan.id,
        latestScanStatus: input.status,
        updatedAt: nowIso(),
      });
    }
    this.findings.set(
      scan.id,
      input.findings.map((finding) => ({
        id: randomUUID(),
        scanId: scan.id,
        severity: finding.severity,
        ruleId: finding.ruleId,
        packageName: finding.packageName,
        packageVersion: finding.packageVersion ?? null,
        title: finding.title,
        evidence: finding.evidence,
        createdAt: nowIso(),
      })),
    );
    const event = await this.enqueueOutboxEvent({
      eventType: "scan.completed",
      payload: { scanId: scan.id, repoId: scan.repoId, status: input.status },
    });
    await this.createWebhookDeliveriesForEvent(event);
  }

  async listAuditLogs(_userId: string, options: ListOptions) {
    return pageItems(this.auditLogs, options.limit, options.cursor);
  }

  async createWebhookEndpoint(input: {
    userId: string;
    url: string;
    description?: string | null;
  }): Promise<WebhookEndpoint> {
    const endpoint = {
      id: randomUUID(),
      url: input.url,
      active: true,
      description: input.description ?? null,
      createdAt: nowIso(),
    };
    this.webhookEndpoints.set(endpoint.id, {
      ...endpoint,
      userId: input.userId,
      secret: randomBytes(32).toString("base64url"),
    });
    return endpoint;
  }

  async listWebhookEndpoints(userId: string) {
    return [...this.webhookEndpoints.values()]
      .filter((endpoint) => endpoint.userId === userId)
      .map(({ secret: _secret, userId: _userId, ...endpoint }) => endpoint);
  }

  async listWebhookDeliveries(userId: string) {
    return [...this.webhookDeliveries.values()]
      .filter((delivery) => delivery.userId === userId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(
        ({ userId: _userId, outboxEventId: _outboxEventId, ...delivery }) =>
          delivery,
      );
  }

  async replayWebhookDelivery(input: {
    userId: string;
    deliveryId: string;
    idempotencyKey?: string;
  }) {
    const scope = `replay:${input.userId}:${input.deliveryId}`;
    const idem = input.idempotencyKey
      ? `${scope}:${input.idempotencyKey}`
      : null;
    const cached = idem ? this.idempotency.get(idem) : null;
    if (cached) {
      return {
        ...(cached as { delivery: WebhookDelivery; job: JobRecord }),
        reused: true,
      };
    }
    const original = this.webhookDeliveries.get(input.deliveryId);
    if (!original || original.userId !== input.userId) {
      throw new Error("delivery not found");
    }
    const delivery = {
      ...original,
      id: randomUUID(),
      status: "queued" as const,
      attempt: original.attempt + 1,
      statusCode: null,
      latencyMs: null,
      responseExcerpt: null,
      createdAt: nowIso(),
    };
    this.webhookDeliveries.set(delivery.id, delivery);
    const job = await this.enqueueJob({
      type: "webhook_delivery",
      payload: { deliveryId: delivery.id },
    });
    const response = { delivery, job };
    if (idem) {
      this.idempotency.set(idem, response);
    }
    return { ...response, reused: false };
  }

  async enqueueJob(input: {
    type: string;
    payload: Record<string, unknown>;
    runAt?: string;
    maxAttempts?: number;
  }) {
    const job: JobRecord = {
      id: randomUUID(),
      type: input.type,
      status: "queued",
      payload: input.payload,
      attempts: 0,
      maxAttempts: input.maxAttempts ?? 5,
      runAt: input.runAt ?? nowIso(),
      lockedAt: null,
      lockedBy: null,
      lastError: null,
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };
    this.jobs.set(job.id, job);
    return job;
  }

  async claimJob(workerId: string, types?: string[]) {
    const now = Date.now();
    const job = [...this.jobs.values()]
      .filter(
        (candidate) =>
          candidate.status === "queued" &&
          Date.parse(candidate.runAt) <= now &&
          (!types?.length || types.includes(candidate.type)),
      )
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0];
    if (!job) {
      return null;
    }
    const claimed: JobRecord = {
      ...job,
      status: "running",
      lockedAt: nowIso(),
      lockedBy: workerId,
      updatedAt: nowIso(),
    };
    this.jobs.set(job.id, claimed);
    return claimed;
  }

  async completeJob(jobId: string) {
    const job = this.jobs.get(jobId);
    if (job) {
      this.jobs.set(jobId, {
        ...job,
        status: "succeeded",
        updatedAt: nowIso(),
      });
    }
  }

  async failJob(jobId: string, error: string) {
    const job = this.jobs.get(jobId);
    if (!job) {
      return;
    }
    const attempts = job.attempts + 1;
    const status = attempts >= job.maxAttempts ? "dead_lettered" : "queued";
    const delayMs = Math.min(60_000, 1000 * 2 ** attempts);
    this.jobs.set(jobId, {
      ...job,
      status,
      attempts,
      lockedAt: null,
      lockedBy: null,
      lastError: error.slice(0, 1000),
      runAt: new Date(Date.now() + delayMs).toISOString(),
      updatedAt: nowIso(),
    });
  }

  async enqueueOutboxEvent(input: {
    eventType: string;
    payload: Record<string, unknown>;
  }) {
    const event: OutboxEventRecord = {
      id: randomUUID(),
      eventType: input.eventType,
      payload: input.payload,
      status: "queued",
      attempts: 0,
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };
    this.outboxEvents.set(event.id, event);
    return event;
  }

  async claimOutboxEvent(_workerId: string) {
    const event = [...this.outboxEvents.values()]
      .filter((candidate) => candidate.status === "queued")
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0];
    if (!event) {
      return null;
    }
    const claimed: OutboxEventRecord = {
      ...event,
      status: "processing",
      attempts: event.attempts + 1,
      updatedAt: nowIso(),
    };
    this.outboxEvents.set(event.id, claimed);
    return claimed;
  }

  async markOutboxEventDelivered(eventId: string) {
    const event = this.outboxEvents.get(eventId);
    if (event) {
      this.outboxEvents.set(eventId, {
        ...event,
        status: "delivered",
        updatedAt: nowIso(),
      });
    }
  }

  async createWebhookDeliveriesForEvent(event: OutboxEventRecord) {
    const deliveries: WebhookDelivery[] = [];
    for (const endpoint of this.webhookEndpoints.values()) {
      if (!endpoint.active) {
        continue;
      }
      const delivery = {
        id: randomUUID(),
        endpointId: endpoint.id,
        eventType: event.eventType,
        status: "queued" as const,
        attempt: 0,
        statusCode: null,
        latencyMs: null,
        responseExcerpt: null,
        createdAt: nowIso(),
      };
      this.webhookDeliveries.set(delivery.id, {
        ...delivery,
        userId: endpoint.userId,
        outboxEventId: event.id,
      });
      deliveries.push(delivery);
      await this.enqueueJob({
        type: "webhook_delivery",
        payload: { deliveryId: delivery.id },
      });
    }
    return deliveries;
  }

  async recordWebhookDelivery(input: {
    deliveryId: string;
    status: "delivered" | "failed";
    statusCode?: number | null;
    latencyMs?: number | null;
    responseExcerpt?: string | null;
  }) {
    const delivery = this.webhookDeliveries.get(input.deliveryId);
    if (!delivery) {
      return;
    }
    this.webhookDeliveries.set(input.deliveryId, {
      ...delivery,
      status: input.status,
      statusCode: input.statusCode ?? null,
      latencyMs: input.latencyMs ?? null,
      responseExcerpt: input.responseExcerpt ?? null,
    });
  }

  async getWebhookDeliveryWork(deliveryId: string) {
    const delivery = this.webhookDeliveries.get(deliveryId);
    if (!delivery) {
      return null;
    }
    const endpoint = this.webhookEndpoints.get(delivery.endpointId);
    const event = this.outboxEvents.get(delivery.outboxEventId);
    if (!endpoint || !event) {
      return null;
    }
    return {
      deliveryId,
      endpointUrl: endpoint.url,
      endpointSecret: endpoint.secret,
      eventId: event.id,
      eventType: event.eventType,
      payload: event.payload,
    };
  }
}

export class PostgresStore implements SentinelStore {
  readonly mode = "postgres" as const;
  constructor(private readonly pool: pg.Pool) {}

  async health() {
    await this.pool.query("select 1");
    return { ok: true, mode: this.mode };
  }

  async close() {
    await this.pool.end();
  }

  async seedDemoData(): Promise<UserRecord> {
    const { user } = await this.createSessionFromGitHub({
      githubId: "dev-user",
      login: "anasm266",
      avatarUrl: null,
    });
    await this.upsertRepo({
      fullName: "anasm266/installsentry",
      defaultBranch: "master",
      private: false,
      userId: user.id,
    });
    await this.upsertRepo({
      fullName: "anasm266/any-map",
      defaultBranch: "main",
      private: false,
      userId: user.id,
    });
    return user;
  }

  async createSessionFromGitHub(profile: GitHubProfile) {
    const userId = randomUUID();
    const userResult = await this.pool.query(
      `insert into users (id, github_id, login, avatar_url)
       values ($1, $2, $3, $4)
       on conflict (github_id) do update
       set login = excluded.login, avatar_url = excluded.avatar_url
       returning id, github_id, login, avatar_url, created_at`,
      [userId, profile.githubId, profile.login, profile.avatarUrl ?? null],
    );
    const user = mapUser(userResult.rows[0]);
    const sessionId = randomBytes(32).toString("base64url");
    const sessionResult = await this.pool.query(
      `insert into sessions (id, user_id, expires_at)
       values ($1, $2, now() + interval '14 days')
       returning id, user_id, expires_at, created_at`,
      [sessionId, user.id],
    );
    return { user, session: mapSession(sessionResult.rows[0]) };
  }

  async getUserBySession(sessionId: string) {
    const result = await this.pool.query(
      `select u.id, u.github_id, u.login, u.avatar_url, u.created_at
       from sessions s
       join users u on u.id = s.user_id
       where s.id = $1 and s.expires_at > now()`,
      [sessionId],
    );
    return result.rows[0] ? mapUser(result.rows[0]) : null;
  }

  async deleteSession(sessionId: string) {
    await this.pool.query("delete from sessions where id = $1", [sessionId]);
  }

  async upsertInstallation(input: {
    id: string;
    accountLogin: string;
    accountType: string;
    suspendedAt?: string | null;
  }) {
    await this.pool.query(
      `insert into github_installations (id, account_login, account_type, suspended_at)
       values ($1, $2, $3, $4)
       on conflict (id) do update
       set account_login = excluded.account_login,
           account_type = excluded.account_type,
           suspended_at = excluded.suspended_at,
           updated_at = now()`,
      [
        input.id,
        input.accountLogin,
        input.accountType,
        input.suspendedAt ?? null,
      ],
    );
  }

  async upsertRepo(input: UpsertRepoInput): Promise<Repo> {
    const result = await this.pool.query(
      `insert into repos (id, full_name, default_branch, private, installation_id)
       values ($1, $2, $3, $4, $5)
       on conflict (full_name) do update
       set default_branch = excluded.default_branch,
           private = excluded.private,
           installation_id = excluded.installation_id,
           updated_at = now()
       returning *`,
      [
        randomUUID(),
        input.fullName,
        input.defaultBranch ?? "main",
        input.private ?? false,
        input.installationId ?? null,
      ],
    );
    const repo = mapRepo(result.rows[0]);
    await this.pool.query(
      `insert into policies (repo_id)
       values ($1)
       on conflict (repo_id) do nothing`,
      [repo.id],
    );
    if (input.userId) {
      await this.pool.query(
        `insert into repo_memberships (user_id, repo_id)
         values ($1, $2)
         on conflict do nothing`,
        [input.userId, repo.id],
      );
    }
    return repo;
  }

  async listRepos(
    userId: string,
    options: ListOptions,
  ): Promise<CursorPage<Repo>> {
    const params: unknown[] = [userId, options.limit + 1];
    let cursorClause = "";
    if (options.cursor) {
      params.push(options.cursor);
      cursorClause = "and r.id::text > $3";
    }
    const result = await this.pool.query(
      `select r.*
       from repos r
       join repo_memberships rm on rm.repo_id = r.id
       where rm.user_id = $1 ${cursorClause}
       order by r.id asc
       limit $2`,
      params,
    );
    const repos = result.rows.map(mapRepo);
    const items = repos.slice(0, options.limit);
    return {
      items,
      nextCursor:
        repos.length > options.limit
          ? (items[items.length - 1]?.id ?? null)
          : null,
    };
  }

  async getRepo(userId: string, repoId: string): Promise<Repo | null> {
    const result = await this.pool.query(
      `select r.*
       from repos r
       join repo_memberships rm on rm.repo_id = r.id
       where rm.user_id = $1 and r.id = $2`,
      [userId, repoId],
    );
    return result.rows[0] ? mapRepo(result.rows[0]) : null;
  }

  async getPolicy(repoId: string): Promise<Policy> {
    await this.pool.query(
      `insert into policies (repo_id)
       values ($1)
       on conflict (repo_id) do nothing`,
      [repoId],
    );
    const result = await this.pool.query(
      "select * from policies where repo_id = $1",
      [repoId],
    );
    return mapPolicy(result.rows[0]);
  }

  async updatePolicy(userId: string, repoId: string, patch: Partial<Policy>) {
    const current = await this.getPolicy(repoId);
    const next = { ...current, ...patch };
    await this.pool.query(
      `update policies
       set block_lifecycle_scripts = $2,
           block_secret_reads = $3,
           allowed_network_hosts = $4,
           max_blast_radius = $5,
           require_approval_for_new_risky_packages = $6,
           updated_at = now()
       where repo_id = $1`,
      [
        repoId,
        next.blockLifecycleScripts,
        next.blockSecretReads,
        next.allowedNetworkHosts,
        next.maxBlastRadius,
        next.requireApprovalForNewRiskyPackages,
      ],
    );
    await this.insertAudit(userId, repoId, "policy.updated", patch);
    return next;
  }

  async createScan(input: CreateScanInput) {
    const client = await this.pool.connect();
    const scope = `scan:${input.userId}:${input.repoId}`;
    const idemKey = input.idempotencyKey
      ? `${scope}:${input.idempotencyKey}`
      : null;
    try {
      await client.query("begin");
      if (idemKey) {
        const cached = await client.query(
          "select response from idempotency_keys where scope = $1 and key = $2",
          [scope, input.idempotencyKey],
        );
        if (cached.rows[0]) {
          await client.query("commit");
          return { ...cached.rows[0].response, reused: true };
        }
      }

      const scanId = randomUUID();
      const scanResult = await client.query(
        `insert into scans (id, repo_id, status, source, commit_sha, pull_request_number)
         values ($1, $2, 'queued', $3, $4, $5)
         returning *`,
        [
          scanId,
          input.repoId,
          input.source,
          input.commitSha ?? null,
          input.pullRequestNumber ?? null,
        ],
      );
      const scan = mapScan(scanResult.rows[0]);
      await client.query(
        `update repos
         set latest_scan_id = $1, latest_scan_status = $2, updated_at = now()
         where id = $3`,
        [scan.id, scan.status, input.repoId],
      );
      const jobResult = await client.query(
        `insert into jobs (id, type, status, payload)
         values ($1, $2, 'queued', $3)
         returning *`,
        [
          randomUUID(),
          input.source === "pull_request" ? "pr_scan" : "manual_scan",
          {
            scanId: scan.id,
            repoId: input.repoId,
            userId: input.userId,
            commitSha: input.commitSha ?? null,
            pullRequestNumber: input.pullRequestNumber ?? null,
          },
        ],
      );
      const job = mapJob(jobResult.rows[0]);
      await client.query(
        `insert into audit_logs (id, actor_user_id, repo_id, action, metadata)
         values ($1, $2, $3, 'scan.queued', $4)`,
        [
          randomUUID(),
          input.userId,
          input.repoId,
          {
            scanId: scan.id,
            source: input.source,
            reason: input.reason ?? null,
          },
        ],
      );
      const response = { scan, job };
      if (idemKey && input.idempotencyKey) {
        await client.query(
          `insert into idempotency_keys (scope, key, response)
           values ($1, $2, $3)`,
          [scope, input.idempotencyKey, response],
        );
      }
      await client.query("commit");
      return { scan, job, reused: false };
    } catch (error) {
      await client.query("rollback");
      throw error;
    } finally {
      client.release();
    }
  }

  async getScan(userId: string, scanId: string) {
    const result = await this.pool.query(
      `select s.*
       from scans s
       join repo_memberships rm on rm.repo_id = s.repo_id
       where rm.user_id = $1 and s.id = $2`,
      [userId, scanId],
    );
    return result.rows[0] ? mapScan(result.rows[0]) : null;
  }

  async listFindings(userId: string, scanId: string) {
    const scan = await this.getScan(userId, scanId);
    if (!scan) {
      return [];
    }
    const result = await this.pool.query(
      "select * from findings where scan_id = $1 order by created_at asc",
      [scanId],
    );
    return result.rows.map(mapFinding);
  }

  async finishScan(input: {
    scanId: string;
    status: ScanStatus;
    findings: PolicyFinding[];
    error?: string | null;
  }) {
    const client = await this.pool.connect();
    try {
      await client.query("begin");
      const scanResult = await client.query(
        `update scans
         set status = $2,
             started_at = coalesce(started_at, now()),
             finished_at = now(),
             error = $3
         where id = $1
         returning *`,
        [input.scanId, input.status, input.error ?? null],
      );
      const scan = mapScan(scanResult.rows[0]);
      await client.query("delete from findings where scan_id = $1", [
        input.scanId,
      ]);
      for (const finding of input.findings) {
        await client.query(
          `insert into findings
           (id, scan_id, severity, rule_id, package_name, package_version, title, evidence)
           values ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [
            randomUUID(),
            scan.id,
            finding.severity,
            finding.ruleId,
            finding.packageName,
            finding.packageVersion ?? null,
            finding.title,
            finding.evidence,
          ],
        );
      }
      await client.query(
        `update repos
         set latest_scan_id = $1, latest_scan_status = $2, updated_at = now()
         where id = $3`,
        [scan.id, input.status, scan.repoId],
      );
      const eventId = randomUUID();
      await client.query(
        `insert into outbox_events (id, event_type, payload)
         values ($1, 'scan.completed', $2)`,
        [
          eventId,
          { scanId: scan.id, repoId: scan.repoId, status: input.status },
        ],
      );
      await client.query("commit");
      const event = await this.getOutboxEvent(eventId);
      if (event) {
        await this.createWebhookDeliveriesForEvent(event);
      }
    } catch (error) {
      await client.query("rollback");
      throw error;
    } finally {
      client.release();
    }
  }

  async listAuditLogs(_userId: string, options: ListOptions) {
    const result = await this.pool.query(
      "select * from audit_logs order by created_at desc limit $1",
      [options.limit],
    );
    return {
      items: result.rows.map(mapAuditLog),
      nextCursor: null,
    };
  }

  async createWebhookEndpoint(input: {
    userId: string;
    url: string;
    description?: string | null;
  }) {
    const result = await this.pool.query(
      `insert into webhook_endpoints (id, user_id, url, secret, description)
       values ($1, $2, $3, $4, $5)
       returning *`,
      [
        randomUUID(),
        input.userId,
        input.url,
        randomBytes(32).toString("base64url"),
        input.description ?? null,
      ],
    );
    return mapWebhookEndpoint(result.rows[0]);
  }

  async listWebhookEndpoints(userId: string) {
    const result = await this.pool.query(
      "select * from webhook_endpoints where user_id = $1 order by created_at desc",
      [userId],
    );
    return result.rows.map(mapWebhookEndpoint);
  }

  async listWebhookDeliveries(userId: string) {
    const result = await this.pool.query(
      `select wd.*
       from webhook_deliveries wd
       join webhook_endpoints we on we.id = wd.endpoint_id
       where we.user_id = $1
       order by wd.created_at desc
       limit 100`,
      [userId],
    );
    return result.rows.map(mapWebhookDelivery);
  }

  async replayWebhookDelivery(input: {
    userId: string;
    deliveryId: string;
    idempotencyKey?: string;
  }) {
    const original = await this.pool.query(
      `select wd.*
       from webhook_deliveries wd
       join webhook_endpoints we on we.id = wd.endpoint_id
       where wd.id = $1 and we.user_id = $2`,
      [input.deliveryId, input.userId],
    );
    if (!original.rows[0]) {
      throw new Error("delivery not found");
    }
    const deliveryResult = await this.pool.query(
      `insert into webhook_deliveries
       (id, endpoint_id, outbox_event_id, event_type, status, attempt)
       values ($1, $2, $3, $4, 'queued', $5)
       returning *`,
      [
        randomUUID(),
        original.rows[0].endpoint_id,
        original.rows[0].outbox_event_id,
        original.rows[0].event_type,
        Number(original.rows[0].attempt) + 1,
      ],
    );
    const delivery = mapWebhookDelivery(deliveryResult.rows[0]);
    const job = await this.enqueueJob({
      type: "webhook_delivery",
      payload: { deliveryId: delivery.id },
    });
    return { delivery, job, reused: false };
  }

  async enqueueJob(input: {
    type: string;
    payload: Record<string, unknown>;
    runAt?: string;
    maxAttempts?: number;
  }) {
    const result = await this.pool.query(
      `insert into jobs (id, type, status, payload, run_at, max_attempts)
       values ($1, $2, 'queued', $3, $4, $5)
       returning *`,
      [
        randomUUID(),
        input.type,
        input.payload,
        input.runAt ?? new Date(),
        input.maxAttempts ?? 5,
      ],
    );
    return mapJob(result.rows[0]);
  }

  async claimJob(workerId: string, types?: string[]) {
    const result = await this.pool.query(
      `update jobs
       set status = 'running',
           locked_at = now(),
           locked_by = $1,
           updated_at = now()
       where id = (
         select id
         from jobs
         where status = 'queued'
           and run_at <= now()
           and ($2::text[] is null or type = any($2::text[]))
         order by created_at asc
         for update skip locked
         limit 1
       )
       returning *`,
      [workerId, types?.length ? types : null],
    );
    return result.rows[0] ? mapJob(result.rows[0]) : null;
  }

  async completeJob(jobId: string) {
    await this.pool.query(
      `update jobs
       set status = 'succeeded', updated_at = now()
       where id = $1`,
      [jobId],
    );
  }

  async failJob(jobId: string, error: string) {
    await this.pool.query(
      `update jobs
       set attempts = attempts + 1,
           status = case when attempts + 1 >= max_attempts then 'dead_lettered' else 'queued' end,
           run_at = now() + make_interval(secs => least(60, power(2, attempts + 1)::int)),
           locked_at = null,
           locked_by = null,
           last_error = $2,
           updated_at = now()
       where id = $1`,
      [jobId, error.slice(0, 1000)],
    );
  }

  async enqueueOutboxEvent(input: {
    eventType: string;
    payload: Record<string, unknown>;
  }) {
    const result = await this.pool.query(
      `insert into outbox_events (id, event_type, payload)
       values ($1, $2, $3)
       returning *`,
      [randomUUID(), input.eventType, input.payload],
    );
    return mapOutboxEvent(result.rows[0]);
  }

  async claimOutboxEvent(_workerId: string) {
    const result = await this.pool.query(
      `update outbox_events
       set status = 'processing',
           attempts = attempts + 1,
           updated_at = now()
       where id = (
         select id
         from outbox_events
         where status = 'queued'
         order by created_at asc
         for update skip locked
         limit 1
       )
       returning *`,
    );
    return result.rows[0] ? mapOutboxEvent(result.rows[0]) : null;
  }

  async markOutboxEventDelivered(eventId: string) {
    await this.pool.query(
      "update outbox_events set status = 'delivered', updated_at = now() where id = $1",
      [eventId],
    );
  }

  async createWebhookDeliveriesForEvent(event: OutboxEventRecord) {
    const endpoints = await this.pool.query(
      "select * from webhook_endpoints where active = true",
    );
    const deliveries: WebhookDelivery[] = [];
    for (const endpoint of endpoints.rows) {
      const result = await this.pool.query(
        `insert into webhook_deliveries
         (id, endpoint_id, outbox_event_id, event_type, status)
         values ($1, $2, $3, $4, 'queued')
         returning *`,
        [randomUUID(), endpoint.id, event.id, event.eventType],
      );
      const delivery = mapWebhookDelivery(result.rows[0]);
      deliveries.push(delivery);
      await this.enqueueJob({
        type: "webhook_delivery",
        payload: { deliveryId: delivery.id },
      });
    }
    return deliveries;
  }

  async recordWebhookDelivery(input: {
    deliveryId: string;
    status: "delivered" | "failed";
    statusCode?: number | null;
    latencyMs?: number | null;
    responseExcerpt?: string | null;
  }) {
    await this.pool.query(
      `update webhook_deliveries
       set status = $2,
           status_code = $3,
           latency_ms = $4,
           response_excerpt = $5,
           updated_at = now()
       where id = $1`,
      [
        input.deliveryId,
        input.status,
        input.statusCode ?? null,
        input.latencyMs ?? null,
        input.responseExcerpt ?? null,
      ],
    );
  }

  async getWebhookDeliveryWork(deliveryId: string) {
    const result = await this.pool.query(
      `select wd.id as delivery_id,
              we.url as endpoint_url,
              we.secret as endpoint_secret,
              oe.id as event_id,
              oe.event_type,
              oe.payload
       from webhook_deliveries wd
       join webhook_endpoints we on we.id = wd.endpoint_id
       join outbox_events oe on oe.id = wd.outbox_event_id
       where wd.id = $1`,
      [deliveryId],
    );
    const row = result.rows[0];
    if (!row) {
      return null;
    }
    return {
      deliveryId: String(row.delivery_id),
      endpointUrl: String(row.endpoint_url),
      endpointSecret: String(row.endpoint_secret),
      eventId: String(row.event_id),
      eventType: String(row.event_type),
      payload: asRecord(row.payload),
    };
  }

  private async insertAudit(
    userId: string | null,
    repoId: string | null,
    action: string,
    metadata: Record<string, unknown>,
  ) {
    await this.pool.query(
      `insert into audit_logs (id, actor_user_id, repo_id, action, metadata)
       values ($1, $2, $3, $4, $5)`,
      [randomUUID(), userId, repoId, action, metadata],
    );
  }

  private async getOutboxEvent(eventId: string) {
    const result = await this.pool.query(
      "select * from outbox_events where id = $1",
      [eventId],
    );
    return result.rows[0] ? mapOutboxEvent(result.rows[0]) : null;
  }
}

export function createPool(connectionString: string): pg.Pool {
  return new Pool({ connectionString });
}

export async function createStoreFromEnv(
  env = process.env,
): Promise<SentinelStore> {
  if (env["DATABASE_URL"]) {
    return new PostgresStore(createPool(env["DATABASE_URL"]));
  }
  const store = new MemoryStore();
  await store.seedDemoData();
  return store;
}

export async function runMigrations(connectionString: string): Promise<void> {
  const pool = createPool(connectionString);
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query(
      "create table if not exists schema_migrations (id text primary key, applied_at timestamptz not null default now())",
    );

    const migrationsDir = join(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "migrations",
    );
    const files = (await readdir(migrationsDir))
      .filter((file) => file.endsWith(".sql"))
      .sort();

    for (const file of files) {
      const applied = await client.query(
        "select 1 from schema_migrations where id = $1",
        [file],
      );
      if (applied.rowCount) {
        continue;
      }
      const sql = await readFile(join(migrationsDir, file), "utf8");
      await client.query(sql);
      await client.query("insert into schema_migrations (id) values ($1)", [
        file,
      ]);
    }

    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

function mapUser(row: Record<string, unknown>): UserRecord {
  return {
    id: String(row["id"]),
    githubId: String(row["github_id"]),
    login: String(row["login"]),
    avatarUrl: nullableString(row["avatar_url"]),
    createdAt: toIso(row["created_at"]),
  };
}

function mapSession(row: Record<string, unknown>): SessionRecord {
  return {
    id: String(row["id"]),
    userId: String(row["user_id"]),
    expiresAt: toIso(row["expires_at"]),
    createdAt: toIso(row["created_at"]),
  };
}

function mapRepo(row: Record<string, unknown>): Repo {
  return {
    id: String(row["id"]),
    provider: "github",
    fullName: String(row["full_name"]),
    defaultBranch: String(row["default_branch"]),
    private: Boolean(row["private"]),
    installationId: nullableString(row["installation_id"]),
    latestScanId: nullableString(row["latest_scan_id"]),
    latestScanStatus: nullableString(
      row["latest_scan_status"],
    ) as ScanStatus | null,
    updatedAt: toIso(row["updated_at"]),
  };
}

function mapPolicy(row: Record<string, unknown>): Policy {
  return {
    blockLifecycleScripts: Boolean(row["block_lifecycle_scripts"]),
    blockSecretReads: Boolean(row["block_secret_reads"]),
    allowedNetworkHosts: Array.isArray(row["allowed_network_hosts"])
      ? (row["allowed_network_hosts"] as string[])
      : defaultPolicy.allowedNetworkHosts,
    maxBlastRadius: Number(row["max_blast_radius"]),
    requireApprovalForNewRiskyPackages: Boolean(
      row["require_approval_for_new_risky_packages"],
    ),
  };
}

function mapScan(row: Record<string, unknown>): Scan {
  return {
    id: String(row["id"]),
    repoId: String(row["repo_id"]),
    status: String(row["status"]) as ScanStatus,
    source: String(row["source"]) as Scan["source"],
    commitSha: nullableString(row["commit_sha"]),
    pullRequestNumber:
      row["pull_request_number"] === null ||
      row["pull_request_number"] === undefined
        ? null
        : Number(row["pull_request_number"]),
    startedAt: nullableIso(row["started_at"]),
    finishedAt: nullableIso(row["finished_at"]),
    createdAt: toIso(row["created_at"]),
  };
}

function mapFinding(row: Record<string, unknown>): Finding {
  return {
    id: String(row["id"]),
    scanId: String(row["scan_id"]),
    severity: String(row["severity"]) as Finding["severity"],
    ruleId: String(row["rule_id"]),
    packageName: String(row["package_name"]),
    packageVersion: nullableString(row["package_version"]),
    title: String(row["title"]),
    evidence: asRecord(row["evidence"]),
    createdAt: toIso(row["created_at"]),
  };
}

function mapJob(row: Record<string, unknown>): JobRecord {
  return {
    id: String(row["id"]),
    type: String(row["type"]),
    status: String(row["status"]) as JobStatus,
    payload: asRecord(row["payload"]),
    attempts: Number(row["attempts"]),
    maxAttempts: Number(row["max_attempts"]),
    runAt: toIso(row["run_at"]),
    lockedAt: nullableIso(row["locked_at"]),
    lockedBy: nullableString(row["locked_by"]),
    lastError: nullableString(row["last_error"]),
    createdAt: toIso(row["created_at"]),
    updatedAt: toIso(row["updated_at"]),
  };
}

function mapAuditLog(row: Record<string, unknown>): AuditLog {
  return {
    id: String(row["id"]),
    actorUserId: nullableString(row["actor_user_id"]),
    repoId: nullableString(row["repo_id"]),
    action: String(row["action"]),
    metadata: asRecord(row["metadata"]),
    createdAt: toIso(row["created_at"]),
  };
}

function mapWebhookEndpoint(row: Record<string, unknown>): WebhookEndpoint {
  return {
    id: String(row["id"]),
    url: String(row["url"]),
    active: Boolean(row["active"]),
    description: nullableString(row["description"]),
    createdAt: toIso(row["created_at"]),
  };
}

function mapWebhookDelivery(row: Record<string, unknown>): WebhookDelivery {
  return {
    id: String(row["id"]),
    endpointId: String(row["endpoint_id"]),
    eventType: String(row["event_type"]),
    status: String(row["status"]) as WebhookDelivery["status"],
    attempt: Number(row["attempt"]),
    statusCode: row["status_code"] === null ? null : Number(row["status_code"]),
    latencyMs: row["latency_ms"] === null ? null : Number(row["latency_ms"]),
    responseExcerpt: nullableString(row["response_excerpt"]),
    createdAt: toIso(row["created_at"]),
  };
}

function mapOutboxEvent(row: Record<string, unknown>): OutboxEventRecord {
  return {
    id: String(row["id"]),
    eventType: String(row["event_type"]),
    payload: asRecord(row["payload"]),
    status: String(row["status"]) as OutboxEventRecord["status"],
    attempts: Number(row["attempts"]),
    createdAt: toIso(row["created_at"]),
    updatedAt: toIso(row["updated_at"]),
  };
}

function nullableString(value: unknown): string | null {
  return value === null || value === undefined ? null : String(value);
}

function nullableIso(value: unknown): string | null {
  return value === null || value === undefined ? null : toIso(value);
}

function toIso(value: unknown): string {
  return value instanceof Date
    ? value.toISOString()
    : new Date(String(value)).toISOString();
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}
