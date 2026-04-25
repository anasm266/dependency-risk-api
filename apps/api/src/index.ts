import { createStoreFromEnv, runMigrations } from "@sentinelflow/db";
import { loadWorkerConfig, processNextJob } from "@sentinelflow/worker";
import { loadConfig } from "./config.js";
import { buildApp } from "./server.js";

const config = loadConfig();

if (config.migrateOnStartup) {
  const databaseUrl = process.env["DATABASE_URL"];
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required when MIGRATE_ON_STARTUP=true");
  }
  await runMigrations(databaseUrl);
}

const store = await createStoreFromEnv();
const app = await buildApp({ store, config });
let workerStopped = false;

if (config.runWorkerInApi) {
  const workerConfig = loadWorkerConfig();
  void (async () => {
    while (!workerStopped) {
      const processed = await processNextJob({ store, config: workerConfig });
      if (!processed) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
  })().catch((error) => {
    app.log.error({ err: error }, "embedded worker crashed");
  });
}

try {
  await app.listen({ port: config.port, host: "0.0.0.0" });
} catch (error) {
  app.log.error(error);
  await store.close();
  process.exit(1);
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => {
    workerStopped = true;
    await app.close();
    await store.close();
    process.exit(0);
  });
}
