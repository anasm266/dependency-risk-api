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

  it("normalizes nested optional platform package evidence", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sf-lock-nested-"));
    await writeFile(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { devDependencies: { vitest: "1.0.0" } },
          "node_modules/vitest": {
            version: "1.0.0",
            dependencies: { fsevents: "2.3.3" },
          },
          "node_modules/vitest/node_modules/fsevents": {
            version: "2.3.3",
            hasInstallScript: true,
            optional: true,
            dev: true,
            os: ["darwin"],
          },
        },
      }),
    );

    const findings = await scanPackageLock(dir);
    const lifecycle = findings.find(
      (finding) => finding.ruleId === "lifecycle_script",
    );

    expect(lifecycle).toMatchObject({
      packageName: "fsevents",
      packagePath: "vitest/node_modules/fsevents",
      packageVersion: "2.3.3",
      isOptional: true,
      isDev: true,
      isPlatformSpecific: true,
      evidence: expect.objectContaining({
        path: "vitest/node_modules/fsevents",
        lockfilePath: "node_modules/vitest/node_modules/fsevents",
        optional: true,
        dev: true,
        os: ["darwin"],
      }),
    });
  });
});
