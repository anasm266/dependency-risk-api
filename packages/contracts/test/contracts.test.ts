import { describe, expect, it } from "vitest";
import {
  decodeCursor,
  defaultPolicy,
  encodeCursor,
  evaluatePolicy,
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
