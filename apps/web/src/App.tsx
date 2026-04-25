import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  Bell,
  Github,
  Play,
  RotateCcw,
  ShieldCheck,
} from "lucide-react";
import type {
  AuditLog,
  Finding,
  FindingGroup,
  Policy,
  Repo,
  Scan,
  WebhookDelivery,
  WebhookEndpoint,
} from "@sentinelflow/contracts";
import {
  createWebhookEndpoint,
  devLogin,
  getPolicy,
  getScan,
  listAuditLogs,
  listFindings,
  listRepos,
  listWebhookDeliveries,
  listWebhookEndpoints,
  me,
  replayWebhookDelivery,
  startScan,
  updatePolicy,
  type User,
} from "./api.js";

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [activeRepoId, setActiveRepoId] = useState<string | null>(null);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [endpoints, setEndpoints] = useState<WebhookEndpoint[]>([]);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [endpointUrl, setEndpointUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const activeRepo = useMemo(
    () => repos.find((repo) => repo.id === activeRepoId) ?? repos[0] ?? null,
    [activeRepoId, repos],
  );
  const findingGroups = useMemo(
    () => groupDashboardFindings(findings),
    [findings],
  );

  useEffect(() => {
    void bootstrap();
  }, []);

  useEffect(() => {
    if (activeRepo) {
      void loadRepoDetail(activeRepo.id, activeRepo.latestScanId);
    }
  }, [activeRepo?.id]);

  async function bootstrap() {
    try {
      const session = await me();
      setUser(session.user);
      await refreshAll();
    } catch {
      setUser(null);
    }
  }

  async function refreshAll() {
    const [repoPage, endpointPage, deliveryPage, auditPage] = await Promise.all(
      [
        listRepos(),
        listWebhookEndpoints(),
        listWebhookDeliveries(),
        listAuditLogs(),
      ],
    );
    setRepos(repoPage.items);
    setEndpoints(endpointPage.items);
    setDeliveries(deliveryPage.items);
    setAuditLogs(auditPage.items);
    setActiveRepoId((current) => current ?? repoPage.items[0]?.id ?? null);
  }

  async function loadRepoDetail(repoId: string, latestScanId: string | null) {
    setError(null);
    const nextPolicy = await getPolicy(repoId);
    setPolicy(nextPolicy);
    if (latestScanId) {
      const [nextScan, nextFindings] = await Promise.all([
        getScan(latestScanId),
        listFindings(latestScanId),
      ]);
      setScan(nextScan);
      setFindings(nextFindings.items);
    } else {
      setScan(null);
      setFindings([]);
    }
  }

  async function loginDev() {
    setBusy(true);
    setError(null);
    try {
      const result = await devLogin();
      setUser(result.user);
      await refreshAll();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function runScan() {
    if (!activeRepo) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result = await startScan(activeRepo.id);
      setScan(result.scan);
      await refreshAll();
      window.setTimeout(() => {
        void refreshAll();
      }, 3500);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function savePolicy(next: Partial<Policy>) {
    if (!activeRepo || !policy) {
      return;
    }
    const updated = await updatePolicy(activeRepo.id, { ...policy, ...next });
    setPolicy(updated);
  }

  async function addEndpoint() {
    if (!endpointUrl.trim()) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await createWebhookEndpoint(endpointUrl.trim());
      setEndpointUrl("");
      const endpointPage = await listWebhookEndpoints();
      setEndpoints(endpointPage.items);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function replay(deliveryId: string) {
    setBusy(true);
    setError(null);
    try {
      await replayWebhookDelivery(deliveryId);
      const deliveryPage = await listWebhookDeliveries();
      setDeliveries(deliveryPage.items);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!user) {
    return (
      <Shell>
        <section className="center-panel">
          <div className="mark">
            <ShieldCheck size={28} />
          </div>
          <h1>sentinelflow</h1>
          <p className="muted">
            connect github, define dependency policies, and catch risky npm
            behavior before it lands.
          </p>
          <div className="actions">
            <a className="button primary" href="/auth/github/start">
              <Github size={16} />
              github sign in
            </a>
            <button className="button" onClick={loginDev} disabled={busy}>
              dev login
            </button>
          </div>
          {error && <p className="error">{error}</p>}
        </section>
      </Shell>
    );
  }

  return (
    <Shell user={user}>
      <div className="layout">
        <aside className="sidebar">
          <div className="section-label">repositories</div>
          <div className="repo-list">
            {repos.map((repo) => (
              <button
                key={repo.id}
                className={repo.id === activeRepo?.id ? "repo active" : "repo"}
                onClick={() => setActiveRepoId(repo.id)}
              >
                <span>{repo.fullName}</span>
                <Status value={repo.latestScanStatus ?? "idle"} />
              </button>
            ))}
          </div>
        </aside>

        <main className="content">
          {activeRepo && (
            <section className="topline">
              <div>
                <div className="section-label">active repo</div>
                <h2>{activeRepo.fullName}</h2>
              </div>
              <button
                className="button primary"
                onClick={runScan}
                disabled={busy}
              >
                <Play size={16} />
                scan
              </button>
            </section>
          )}

          {error && <p className="error">{error}</p>}

          <div className="grid">
            <section className="panel">
              <Header icon={<ShieldCheck size={17} />} title="policy" />
              {policy && (
                <div className="policy">
                  <Toggle
                    label="block lifecycle scripts"
                    checked={policy.blockLifecycleScripts}
                    onChange={(value) =>
                      void savePolicy({ blockLifecycleScripts: value })
                    }
                  />
                  <Toggle
                    label="block secret reads"
                    checked={policy.blockSecretReads}
                    onChange={(value) =>
                      void savePolicy({ blockSecretReads: value })
                    }
                  />
                  <Toggle
                    label="new risky package approval"
                    checked={policy.requireApprovalForNewRiskyPackages}
                    onChange={(value) =>
                      void savePolicy({
                        requireApprovalForNewRiskyPackages: value,
                      })
                    }
                  />
                  <label className="field">
                    <span>max blast radius</span>
                    <input
                      type="number"
                      min={0}
                      max={1000}
                      value={policy.maxBlastRadius}
                      onChange={(event) =>
                        void savePolicy({
                          maxBlastRadius: Number(event.currentTarget.value),
                        })
                      }
                    />
                  </label>
                </div>
              )}
            </section>

            <section className="panel">
              <Header icon={<Activity size={17} />} title="latest scan" />
              {scan ? (
                <div className="scan">
                  <Row label="status" value={<Status value={scan.status} />} />
                  <Row label="source" value={scan.source} />
                  <Row
                    label="commit"
                    value={scan.commitSha ?? "default branch"}
                  />
                  <Row label="findings" value={String(findingGroups.length)} />
                </div>
              ) : (
                <p className="muted">no scans yet</p>
              )}
            </section>
          </div>

          <section className="panel wide">
            <Header icon={<Activity size={17} />} title="findings" />
            <Table
              empty="no findings"
              headers={["severity", "package", "path", "reasons"]}
              rows={findingGroups.map((group) => [
                group.severity,
                formatPackage(group),
                group.packagePath,
                group.reasons.join(", "),
              ])}
            />
          </section>

          <section className="panel wide">
            <Header icon={<Bell size={17} />} title="webhooks" />
            <div className="endpoint-form">
              <input
                value={endpointUrl}
                onChange={(event) => setEndpointUrl(event.currentTarget.value)}
                placeholder="https://example.com/sentinelflow"
              />
              <button className="button" onClick={addEndpoint} disabled={busy}>
                add
              </button>
            </div>
            <Table
              empty="no webhook endpoints"
              headers={["url", "active", "created"]}
              rows={endpoints.map((endpoint) => [
                endpoint.url,
                endpoint.active ? "yes" : "no",
                formatTime(endpoint.createdAt),
              ])}
            />
          </section>

          <section className="panel wide">
            <Header icon={<RotateCcw size={17} />} title="deliveries" />
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>event</th>
                    <th>status</th>
                    <th>code</th>
                    <th>created</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {deliveries.length === 0 && (
                    <tr>
                      <td colSpan={5} className="empty">
                        no deliveries
                      </td>
                    </tr>
                  )}
                  {deliveries.map((delivery) => (
                    <tr key={delivery.id}>
                      <td>{delivery.eventType}</td>
                      <td>{delivery.status}</td>
                      <td>{delivery.statusCode ?? "none"}</td>
                      <td>{formatTime(delivery.createdAt)}</td>
                      <td className="right">
                        <button
                          className="icon-button"
                          title="replay delivery"
                          onClick={() => void replay(delivery.id)}
                          disabled={busy}
                        >
                          <RotateCcw size={15} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="panel wide">
            <Header icon={<Activity size={17} />} title="audit log" />
            <Table
              empty="no audit events"
              headers={["action", "repo", "created"]}
              rows={auditLogs.map((log) => [
                log.action,
                log.repoFullName ?? log.repoId ?? "none",
                formatTime(log.createdAt),
              ])}
            />
          </section>
        </main>
      </div>
    </Shell>
  );
}

function Shell({ children, user }: { children: React.ReactNode; user?: User }) {
  return (
    <div className="app">
      <header>
        <a className="brand" href="/">
          sentinel<span>_</span>flow
        </a>
        <nav>
          {user && <span className="muted">@{user.login}</span>}
          <a href="https://github.com/anasm266/dependency-risk-api">github</a>
        </nav>
      </header>
      {children}
    </div>
  );
}

function Header({ icon, title }: { icon: React.ReactNode; title: string }) {
  return (
    <div className="panel-header">
      {icon}
      <h3>{title}</h3>
    </div>
  );
}

function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="toggle">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.currentTarget.checked)}
      />
      <span>{label}</span>
    </label>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Status({ value }: { value: string }) {
  return <span className={`status ${value}`}>{value}</span>;
}

function formatPackage(group: FindingGroup) {
  return `${group.packageName}${group.packageVersion ? `@${group.packageVersion}` : ""}`;
}

function groupDashboardFindings(findings: Finding[]): FindingGroup[] {
  const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
  const groups = new Map<
    string,
    FindingGroup & { seenRuleIds: Set<string>; seenReasons: Set<string> }
  >();

  for (const finding of findings) {
    const packageName = cleanPackageName(finding.packageName);
    const packagePath = displayPackagePath(finding);
    const packageVersion = finding.packageVersion ?? null;
    const key = `${packagePath}\0${packageVersion ?? ""}`;
    const ruleId = displayRuleId(finding);
    const reason = reasonForRule(ruleId);
    const existing = groups.get(key);
    const group =
      existing ??
      ({
        packageName,
        packagePath,
        packageVersion,
        severity: finding.severity,
        ruleIds: [],
        reasons: [],
        evidenceCount: 0,
        seenRuleIds: new Set<string>(),
        seenReasons: new Set<string>(),
      } satisfies FindingGroup & {
        seenRuleIds: Set<string>;
        seenReasons: Set<string>;
      });

    if (severityRank[finding.severity] > severityRank[group.severity]) {
      group.severity = finding.severity;
    }
    group.evidenceCount += 1;
    if (!group.seenRuleIds.has(ruleId)) {
      group.ruleIds.push(ruleId);
      group.seenRuleIds.add(ruleId);
    }
    if (!group.seenReasons.has(reason)) {
      group.reasons.push(reason);
      group.seenReasons.add(reason);
    }
    if (
      isOptionalPlatformEvidence(finding) &&
      !group.seenReasons.has("optional platform package")
    ) {
      group.reasons.push("optional platform package");
      group.seenReasons.add("optional platform package");
    }
    groups.set(key, group);
  }

  return [...groups.values()].map(({ seenRuleIds, seenReasons, ...group }) => ({
    ...group,
  }));
}

function displayRuleId(finding: Finding) {
  if (
    finding.ruleId === "new_risky_dependency" ||
    finding.title.toLowerCase().includes("new risky dependency")
  ) {
    return "new_risky_dependency";
  }
  return finding.ruleId;
}

function reasonForRule(ruleId: string) {
  switch (ruleId) {
    case "lifecycle_script":
      return "lifecycle script";
    case "new_risky_dependency":
      return "new risky dependency";
    case "secret_read":
      return "secret read";
    case "network_egress":
      return "network egress";
    case "blast_radius":
      return "blast radius";
    default:
      return ruleId.replaceAll("_", " ");
  }
}

function displayPackagePath(finding: Finding) {
  const path =
    stringEvidence(finding.evidence["path"]) ??
    stringEvidence(finding.evidence["packagePath"]) ??
    stringEvidence(finding.evidence["lockfilePath"]);
  return stripRootNodeModules(path ?? finding.packageName);
}

function cleanPackageName(value: string) {
  const normalized = value.replaceAll("\\", "/");
  const segments = normalized.split("/").filter(Boolean);
  const lastNodeModules = segments.lastIndexOf("node_modules");
  if (lastNodeModules >= 0) {
    return packageNameFromSegments(segments.slice(lastNodeModules + 1));
  }
  const nestedNodeModules = normalized.lastIndexOf("/node_modules/");
  if (nestedNodeModules >= 0) {
    return cleanPackageName(normalized.slice(nestedNodeModules + 1));
  }
  return packageNameFromSegments(segments);
}

function packageNameFromSegments(segments: string[]) {
  const first = segments[0];
  if (!first) {
    return "unknown";
  }
  if (first.startsWith("@") && segments[1]) {
    return `${first}/${segments[1]}`;
  }
  return first;
}

function stripRootNodeModules(path: string) {
  return path.replaceAll("\\", "/").replace(/^node_modules\//, "");
}

function isOptionalPlatformEvidence(finding: Finding) {
  return (
    finding.evidence["optional"] === true &&
    (hasArrayEvidence(finding.evidence["os"]) ||
      hasArrayEvidence(finding.evidence["cpu"]) ||
      cleanPackageName(finding.packageName) === "fsevents")
  );
}

function hasArrayEvidence(value: unknown) {
  return Array.isArray(value) && value.length > 0;
}

function stringEvidence(value: unknown) {
  return typeof value === "string" && value ? value : null;
}

function Table({
  headers,
  rows,
  empty,
}: {
  headers: string[];
  rows: string[][];
  empty: string;
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {headers.map((header) => (
              <th key={header}>{header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={headers.length} className="empty">
                {empty}
              </td>
            </tr>
          )}
          {rows.map((row, index) => (
            <tr key={index}>
              {row.map((cell, cellIndex) => (
                <td key={cellIndex}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}
