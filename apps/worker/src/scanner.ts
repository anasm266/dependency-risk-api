import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";
import type { ScannerFindingInput } from "@sentinelflow/contracts";

export interface ScannerOptions {
  repoFullName?: string;
  commitSha?: string | null;
  fixtureDir?: string;
  githubToken?: string | undefined;
  timeoutMs: number;
  maxOutputBytes: number;
  command?: string | undefined;
}

export interface ScannerResult {
  findings: ScannerFindingInput[];
  rawSummary: {
    packagesSeen: number;
    lifecyclePackages: number;
    sarifResults: number;
  };
}

export class ScannerUnsupportedError extends Error {}

interface PackageLockEntry {
  version?: string;
  hasInstallScript?: boolean;
  dependencies?: Record<string, string>;
  optional?: boolean;
  dev?: boolean;
  os?: string[];
  cpu?: string[];
}

export async function runScanner(
  options: ScannerOptions,
): Promise<ScannerResult> {
  let cleanupDir: string | null = null;
  try {
    const projectDir =
      options.fixtureDir ??
      (await downloadRepositoryArchive(
        archiveInput(
          requireValue(options.repoFullName, "repoFullName"),
          options.commitSha ?? "HEAD",
          options.githubToken,
        ),
      ));
    if (!options.fixtureDir) {
      cleanupDir = projectDir;
    }

    await requirePackageLock(projectDir);
    const staticFindings = await scanPackageLock(projectDir);
    const sarifPath = join(projectDir, `.sentinelflow-${randomUUID()}.sarif`);

    const cliInput: Parameters<typeof runInstallSentryCli>[0] = {
      projectDir,
      sarifPath,
      timeoutMs: options.timeoutMs,
      maxOutputBytes: options.maxOutputBytes,
    };
    if (options.command) {
      cliInput.command = options.command;
    }
    const cliResult = await runInstallSentryCli(cliInput);

    const sarifFindings = cliResult.sarifResults.length
      ? cliResult.sarifResults
      : await parseSarifIfExists(sarifPath);

    return {
      findings: mergeFindings([...staticFindings, ...sarifFindings]),
      rawSummary: {
        packagesSeen: cliResult.packagesSeen,
        lifecyclePackages: staticFindings.filter(
          (finding) => finding.ruleId === "lifecycle_script",
        ).length,
        sarifResults: sarifFindings.length,
      },
    };
  } finally {
    if (cleanupDir) {
      await rm(cleanupDir, { recursive: true, force: true });
    }
  }
}

export async function scanPackageLock(
  projectDir: string,
): Promise<ScannerFindingInput[]> {
  const lockPath = join(projectDir, "package-lock.json");
  const raw = await readFile(lockPath, "utf8");
  const lock = JSON.parse(raw) as {
    packages?: Record<string, PackageLockEntry>;
  };
  const packages = Object.entries(lock.packages ?? {});
  const dependencyCounts = new Map<string, number>();
  for (const [, pkg] of packages) {
    for (const depName of Object.keys(pkg.dependencies ?? {})) {
      dependencyCounts.set(depName, (dependencyCounts.get(depName) ?? 0) + 1);
    }
  }

  const findings: ScannerFindingInput[] = [];
  for (const [path, pkg] of packages) {
    if (!path.startsWith("node_modules/")) {
      continue;
    }
    const packageName = packageNameFromLockPath(path);
    const packagePath = displayPackagePath(path);
    const packageEvidence = packageMetadataEvidence(path, pkg);
    if (pkg.hasInstallScript) {
      findings.push({
        ruleId: "lifecycle_script",
        packageName,
        packagePath,
        packageVersion: pkg.version ?? null,
        evidence: {
          ...packageEvidence,
          source: "package-lock.hasInstallScript",
        },
        isOptional: Boolean(pkg.optional),
        isDev: Boolean(pkg.dev),
        isPlatformSpecific: isPlatformSpecificPackage(packageName, pkg),
        isNewPackage: true,
      });
    }
    const blastRadius = dependencyCounts.get(packageName) ?? 0;
    if (blastRadius > 0) {
      findings.push({
        ruleId: "blast_radius",
        packageName,
        packagePath,
        packageVersion: pkg.version ?? null,
        evidence: { ...packageEvidence, dependentCount: blastRadius },
        blastRadius,
      });
    }
  }
  return findings;
}

async function runInstallSentryCli(input: {
  projectDir: string;
  sarifPath: string;
  timeoutMs: number;
  maxOutputBytes: number;
  command?: string;
}): Promise<{ packagesSeen: number; sarifResults: ScannerFindingInput[] }> {
  const command =
    input.command ?? (process.platform === "win32" ? "npx.cmd" : "npx");
  const args = input.command
    ? [
        "run",
        input.projectDir,
        "--sarif",
        input.sarifPath,
        "-o",
        join(input.projectDir, "report.html"),
      ]
    : [
        "--yes",
        "installsentry@latest",
        "run",
        input.projectDir,
        "--sarif",
        input.sarifPath,
        "-o",
        join(input.projectDir, "report.html"),
      ];

  const child = spawn(command, args, {
    cwd: input.projectDir,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });

  let output = "";
  const append = (chunk: Buffer) => {
    output += chunk.toString("utf8");
    if (Buffer.byteLength(output) > input.maxOutputBytes) {
      output = output.slice(-input.maxOutputBytes);
    }
  };
  child.stdout.on("data", append);
  child.stderr.on("data", append);

  const timeout = setTimeout(() => child.kill("SIGKILL"), input.timeoutMs);
  const exitCode = await new Promise<number | null>((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", resolve);
  });
  clearTimeout(timeout);

  if (exitCode !== 0) {
    const timedOut = output.includes("SIGKILL") || exitCode === null;
    if (timedOut) {
      throw new Error("InstallSentry scan timed out");
    }
    return {
      packagesSeen: extractPackageCount(output),
      sarifResults: await parseSarifIfExists(input.sarifPath),
    };
  }

  return {
    packagesSeen: extractPackageCount(output),
    sarifResults: await parseSarifIfExists(input.sarifPath),
  };
}

async function downloadRepositoryArchive(input: {
  repoFullName: string;
  commitSha: string;
  githubToken?: string;
}) {
  const tempRoot = await mkdtemp(join(tmpdir(), "sentinelflow-"));
  const archivePath = join(tempRoot, "repo.tgz");
  const projectDir = join(tempRoot, "repo");
  await mkdir(projectDir, { recursive: true });
  const response = await fetch(
    `https://api.github.com/repos/${input.repoFullName}/tarball/${input.commitSha}`,
    {
      headers: {
        accept: "application/vnd.github+json",
        ...(input.githubToken
          ? { authorization: `Bearer ${input.githubToken}` }
          : {}),
      },
    },
  );
  if (!response.ok || !response.body) {
    throw new Error(
      `failed to download repository archive: ${response.status}`,
    );
  }
  await writeFile(archivePath, Buffer.from(await response.arrayBuffer()));
  await tar.x({
    file: archivePath,
    cwd: projectDir,
    strip: 1,
  });
  return projectDir;
}

async function requirePackageLock(projectDir: string) {
  try {
    await stat(join(projectDir, "package-lock.json"));
  } catch {
    throw new ScannerUnsupportedError("package-lock.json is required");
  }
}

async function parseSarifIfExists(
  path: string,
): Promise<ScannerFindingInput[]> {
  try {
    const raw = await readFile(path, "utf8");
    const sarif = JSON.parse(raw) as {
      runs?: Array<{
        results?: Array<{
          ruleId?: string;
          level?: string;
          message?: { text?: string };
          properties?: Record<string, unknown>;
        }>;
      }>;
    };
    const results = sarif.runs?.flatMap((run) => run.results ?? []) ?? [];
    return results.map((result) => ({
      ruleId: normalizeSarifRule(result.ruleId ?? "scanner_finding"),
      packageName: String(result.properties?.["package"] ?? "unknown"),
      packageVersion: String(result.properties?.["version"] ?? "") || null,
      evidence: {
        message: result.message?.text ?? "",
        level: result.level ?? "warning",
        properties: result.properties ?? {},
      },
    }));
  } catch {
    return [];
  }
}

function normalizeSarifRule(ruleId: string): string {
  if (ruleId.includes("secret")) {
    return "secret_read";
  }
  if (ruleId.includes("network")) {
    return "network_egress";
  }
  if (ruleId.includes("lifecycle") || ruleId.includes("script")) {
    return "lifecycle_script";
  }
  return ruleId;
}

function mergeFindings(findings: ScannerFindingInput[]) {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = [
      finding.ruleId,
      finding.packageName,
      finding.packagePath ?? finding.evidence["path"] ?? "",
      finding.packageVersion ?? "",
      JSON.stringify(finding.evidence),
    ].join("\0");
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function packageMetadataEvidence(path: string, pkg: PackageLockEntry) {
  const evidence: Record<string, unknown> = {
    path: displayPackagePath(path),
    lockfilePath: path,
    optional: Boolean(pkg.optional),
    dev: Boolean(pkg.dev),
  };
  if (pkg.os?.length) {
    evidence["os"] = pkg.os;
  }
  if (pkg.cpu?.length) {
    evidence["cpu"] = pkg.cpu;
  }
  return evidence;
}

function displayPackagePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^node_modules\//, "");
}

function packageNameFromLockPath(path: string): string {
  const segments = path.replaceAll("\\", "/").split("/").filter(Boolean);
  const lastNodeModules = segments.lastIndexOf("node_modules");
  const packageSegments =
    lastNodeModules >= 0 ? segments.slice(lastNodeModules + 1) : segments;
  const first = packageSegments[0];
  if (!first) {
    return "unknown";
  }
  if (first.startsWith("@") && packageSegments[1]) {
    return `${first}/${packageSegments[1]}`;
  }
  return first;
}

function isPlatformSpecificPackage(
  packageName: string,
  pkg: PackageLockEntry,
): boolean {
  return Boolean(
    pkg.optional &&
    (packageName === "fsevents" || pkg.os?.length || pkg.cpu?.length),
  );
}

function extractPackageCount(output: string) {
  const match = output.match(/out of\s+(\d+)\s+total dependencies/i);
  return match ? Number(match[1]) : 0;
}

function requireValue(value: string | undefined, name: string) {
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function archiveInput(
  repoFullName: string,
  commitSha: string,
  githubToken: string | undefined,
): {
  repoFullName: string;
  commitSha: string;
  githubToken?: string;
} {
  const input: {
    repoFullName: string;
    commitSha: string;
    githubToken?: string;
  } = {
    repoFullName,
    commitSha,
  };
  if (githubToken) {
    input.githubToken = githubToken;
  }
  return input;
}
