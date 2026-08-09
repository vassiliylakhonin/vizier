import { execFile, spawn } from "node:child_process";
import process from "node:process";

import { Vizier } from "@vizier/sdk";

import {
  assertCleanWorktree,
  runGatedDeploy,
  type DeployMetadata,
} from "./index.js";

const VIZIER_BASE_URL = "https://vizier.vassiliy-lakhonin.workers.dev";
const KEYCHAIN_ACCOUNT = "VIZIER_API_KEY";
const KEYCHAIN_SERVICE = "com.vizier.gated-deploy";
const VERIFY_TIMEOUT_MS = 10_000;

function readCommand(command: string, args: readonly string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      command,
      [...args],
      { encoding: "utf8", maxBuffer: 64 * 1024 },
      (error, stdout) => {
        if (error === null) {
          resolve(stdout.trim());
          return;
        }
        reject(error);
      },
    );
  });
}

async function readKeychainSecret(): Promise<string> {
  const secret = await readCommand("/usr/bin/security", [
    "find-generic-password",
    "-a",
    KEYCHAIN_ACCOUNT,
    "-s",
    KEYCHAIN_SERVICE,
    "-w",
  ]);
  if (secret.length === 0) {
    throw new Error("Vizier credential is empty in macOS Keychain.");
  }
  return secret;
}

async function collectDeployMetadata(): Promise<DeployMetadata> {
  const [commit, worktree] = await Promise.all([
    readCommand("/usr/bin/git", ["rev-parse", "--verify", "HEAD"]),
    readCommand("/usr/bin/git", ["status", "--porcelain"]),
  ]);
  return { commit, dirty: worktree.length > 0 };
}

function executeWranglerDeploy(receiptId: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      "./node_modules/.bin/wrangler",
      [
        "deploy",
        "--strict",
        "--message",
        `Vizier ALLOW receipt ${receiptId}`,
      ],
      { stdio: "inherit", shell: false },
    );
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (signal !== null) {
        reject(new Error(`Wrangler terminated by signal ${signal}.`));
        return;
      }
      resolve(code ?? 1);
    });
  });
}

async function verifyWithTimeout(
  vizier: Vizier,
  request: Parameters<Vizier["verify"]>[0],
): Promise<Awaited<ReturnType<Vizier["verify"]>>> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), VERIFY_TIMEOUT_MS);
  try {
    return await vizier.verify(request, { signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function main(): Promise<number> {
  if (process.argv.length > 2) {
    throw new Error("vizier-gated-deploy does not accept command arguments.");
  }

  const metadata = await collectDeployMetadata();
  assertCleanWorktree(metadata);
  const apiKey = await readKeychainSecret();
  const vizier = new Vizier({ baseUrl: VIZIER_BASE_URL, apiKey });
  const result = await runGatedDeploy({
    metadata,
    verify: (request) => verifyWithTimeout(vizier, request),
    execute: executeWranglerDeploy,
  });

  console.log(
    JSON.stringify({
      event: "vizier.gated_deploy.completed",
      status: result.status,
      decision: result.decision,
      receipt_id: result.receiptId,
      reason_codes: result.reasonCodes,
      ...(result.status === "stopped" ? {} : { exit_code: result.exitCode }),
    }),
  );

  if (result.status === "stopped") {
    return 2;
  }
  return result.exitCode;
}

main()
  .then((exitCode) => {
    process.exitCode = exitCode;
  })
  .catch((error: unknown) => {
    console.error(
      JSON.stringify({
        event: "vizier.gated_deploy.failed",
        error: error instanceof Error ? error.message : "Unknown error",
      }),
    );
    process.exitCode = 1;
  });
