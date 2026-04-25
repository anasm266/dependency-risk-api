import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const root = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    environment: "node",
    include: ["packages/**/test/**/*.test.ts", "apps/**/test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
    },
  },
  resolve: {
    conditions: ["source"],
    alias: {
      "@sentinelflow/contracts": resolve(
        root,
        "packages/contracts/src/index.ts",
      ),
      "@sentinelflow/db": resolve(root, "packages/db/src/index.ts"),
    },
  },
});
