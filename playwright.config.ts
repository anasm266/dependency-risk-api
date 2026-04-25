import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "on-first-retry",
  },
  webServer: [
    {
      command: "npm run dev:api",
      url: "http://127.0.0.1:4174/health",
      reuseExistingServer: false,
      env: {
        NODE_ENV: "test",
        PORT: "4174",
        WEB_ORIGIN: "http://127.0.0.1:4173",
        SESSION_SECRET: "playwright-session-secret-32-bytes",
        GITHUB_WEBHOOK_SECRET: "playwright-webhook-secret",
        SCAN_REPO_ALLOWLIST: "anasm266/installsentry",
      },
    },
    {
      command:
        "npm run dev -w apps/web -- --host 127.0.0.1 --port 4173 --strictPort",
      url: "http://127.0.0.1:4173",
      reuseExistingServer: false,
      env: {
        VITE_API_BASE_URL: "http://127.0.0.1:4174",
      },
    },
  ],
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "mobile",
      use: { ...devices["Pixel 5"] },
    },
  ],
});
