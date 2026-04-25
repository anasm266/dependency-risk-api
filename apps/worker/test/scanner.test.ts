import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ScannerUnsupportedError,
  scanPackageLock,
  runScanner,
} from "../src/scanner.js";

describe("scanner adapter", () => {
  it("rejects projects without package-lock.json", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sf-no-lock-"));
    await expect(
      runScanner({
        fixtureDir: dir,
        timeoutMs: 100,
        maxOutputBytes: 1000,
        command: "definitely-missing-command",
      }),
    ).rejects.toBeInstanceOf(ScannerUnsupportedError);
  });

  it("finds package-lock lifecycle script evidence", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sf-lock-"));
    await writeFile(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "bad-pkg": "1.0.0" } },
          "node_modules/bad-pkg": {
            version: "1.0.0",
            hasInstallScript: true,
          },
        },
      }),
    );

    const findings = await scanPackageLock(dir);
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "lifecycle_script",
        packageName: "bad-pkg",
      }),
    );
  });
});
