export interface ApiConfig {
  nodeEnv: string;
  port: number;
  webOrigin: string;
  publicAppUrl: string;
  apiBaseUrl: string;
  sessionSecret: string;
  githubClientId: string;
  githubClientSecret: string;
  githubAppSlug: string;
  githubWebhookSecret: string;
  scanRepoAllowlist: Set<string>;
  metricsToken: string | null;
  runWorkerInApi: boolean;
  migrateOnStartup: boolean;
}

export function loadConfig(env = process.env): ApiConfig {
  return {
    nodeEnv: env["NODE_ENV"] ?? "development",
    port: Number.parseInt(env["PORT"] ?? "4000", 10),
    webOrigin: env["WEB_ORIGIN"] ?? "http://localhost:5173",
    publicAppUrl: env["PUBLIC_APP_URL"] ?? "http://localhost:5173",
    apiBaseUrl: env["API_BASE_URL"] ?? "http://localhost:4000",
    sessionSecret:
      env["SESSION_SECRET"] ?? "dev-session-secret-32-bytes-minimum",
    githubClientId: env["GITHUB_CLIENT_ID"] ?? "",
    githubClientSecret: env["GITHUB_CLIENT_SECRET"] ?? "",
    githubAppSlug: env["GITHUB_APP_SLUG"] ?? "sentinelflow",
    githubWebhookSecret: env["GITHUB_WEBHOOK_SECRET"] ?? "dev-webhook-secret",
    scanRepoAllowlist: new Set(
      (env["SCAN_REPO_ALLOWLIST"] ?? "anasm266/installsentry,anasm266/any-map")
        .split(",")
        .map((repo) => repo.trim())
        .filter(Boolean),
    ),
    metricsToken: env["METRICS_TOKEN"] ?? null,
    runWorkerInApi: env["RUN_WORKER_IN_API"] === "true",
    migrateOnStartup: env["MIGRATE_ON_STARTUP"] === "true",
  };
}
