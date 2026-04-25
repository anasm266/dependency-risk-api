import { describe, expect, it } from "vitest";
import {
  decodeCursor,
  defaultPolicy,
  encodeCursor,
  evaluatePolicy,
  groupFindings,
  highestSeverity,
  pageItems,
  problem,
  signHmacSha256,
  verifyHmacSha256,
  weakEtag,
} from "../src/index.js";

describe("contracts helpers", () => {
  it("round-trips cursors and paginates deterministically", () => {
    const cursor = encodeCursor("repo-1");
    expect(decodeCursor(cursor)).toBe("repo-1");

    const page = pageItems([{ id: "a" }, { id: "b" }, { id: "c" }], 2);

    expect(page.items.map((item) => item.id)).toEqual(["a", "b"]);
    expect(decodeCursor(page.nextCursor ?? "")).toBe("b");
  });

  it("evaluates dependency policy findings", () => {
    const findings = evaluatePolicy(defaultPolicy, [
      {
        ruleId: "lifecycle_script",
        packageName: "left-pad",
        packageVersion: "1.0.0",
        evidence: { script: "postinstall" },
        isNewPackage: true,
      },
      {
        ruleId: "network_egress",
        packageName: "telemetry-pkg",
        packageVersion: "2.0.0",
        evidence: { host: "example.com" },
      },
      {
        ruleId: "blast_radius",
        packageName: "core-util",
        evidence: {},
        blastRadius: 120,
      },
    ]);

    expect(findings.map((finding) => finding.ruleId)).toContain(
      "lifecycle_script",
    );
    expect(findings.map((finding) => finding.ruleId)).toContain(
      "network_egress",
    );
    expect(highestSeverity(findings)).toBe("critical");
  });

  it("keeps normal lifecycle scripts high severity", () => {
    const findings = evaluatePolicy(defaultPolicy, [
      {
        ruleId: "lifecycle_script",
        packageName: "bad-pkg",
        packageVersion: "1.0.0",
        evidence: { path: "bad-pkg" },
      },
    ]);

    expect(findings[0]).toMatchObject({
      ruleId: "lifecycle_script",
      severity: "high",
    });
  });

  it("treats optional platform lifecycle scripts as medium severity", () => {
    const findings = evaluatePolicy(defaultPolicy, [
      {
        ruleId: "lifecycle_script",
        packageName: "fsevents",
        packagePath: "vitest/node_modules/fsevents",
        packageVersion: "2.3.3",
        evidence: {
          path: "vitest/node_modules/fsevents",
          optional: true,
          os: ["darwin"],
        },
        isOptional: true,
        isPlatformSpecific: true,
        isNewPackage: true,
      },
    ]);
    const lifecycle = findings.find(
      (finding) => finding.ruleId === "lifecycle_script",
    );

    expect(lifecycle?.severity).toBe("medium");
  });

  it("groups raw policy evidence into one dashboard finding row", () => {
    const findings = evaluatePolicy(defaultPolicy, [
      {
        ruleId: "lifecycle_script",
        packageName: "fsevents",
        packagePath: "vitest/node_modules/fsevents",
        packageVersion: "2.3.3",
        evidence: {
          path: "vitest/node_modules/fsevents",
          optional: true,
          os: ["darwin"],
        },
        isOptional: true,
        isPlatformSpecific: true,
        isNewPackage: true,
      },
    ]);

    const groups = groupFindings(findings);

    expect(groups).toHaveLength(1);
    expect(groups[0]).toMatchObject({
      packageName: "fsevents",
      packagePath: "vitest/node_modules/fsevents",
      packageVersion: "2.3.3",
      severity: "medium",
    });
    expect(groups[0]?.ruleIds).toEqual([
      "lifecycle_script",
      "new_risky_dependency",
    ]);
    expect(groups[0]?.reasons).toEqual([
      "lifecycle script",
      "optional platform package",
      "new risky dependency",
    ]);
  });

  it("uses timing-safe sha256 HMAC signatures", () => {
    const body = JSON.stringify({ event: "scan.completed" });
    const signature = signHmacSha256("secret", body);

    expect(verifyHmacSha256("secret", body, signature)).toBe(true);
    expect(verifyHmacSha256("secret", body, "sha256=bad")).toBe(false);
  });

  it("builds stable weak etags and problem-json objects", () => {
    expect(weakEtag({ ok: true })).toMatch(/^W\/"/);
    expect(problem(404, "Not Found", "missing")).toEqual({
      type: "about:blank",
      title: "Not Found",
      status: 404,
      detail: "missing",
    });
  });
});
