import { createStoreFromEnv } from "@sentinelflow/db";
import { loadWorkerConfig, processNextJob } from "./worker.js";

const store = await createStoreFromEnv();
const config = loadWorkerConfig();
let stopped = false;

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => {
    stopped = true;
    await store.close();
    process.exit(0);
  });
}

while (!stopped) {
  const processed = await processNextJob({ store, config });
  if (!processed) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}
