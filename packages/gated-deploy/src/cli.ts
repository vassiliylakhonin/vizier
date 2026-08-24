import { execFile, spawn } from "node:child_process";
import process from "node:process";

import { Vizier } from "@vizier/sdk";

import {
  assertCleanWorktree,
  runCovenantGatedDeploy,
  runGatedDeploy,
  type DeployMetadata,
} from "./index.js";

const VIZIER_BASE_URL = "https://vizier.vassiliy-lakhonin.workers.dev";
const KEYCHAIN_ACCOUNT = "VIZIER_API_KEY";
const KEYCHAIN_SERVICE = "com.vizier.gated-deploy";
const VERIFY_TIMEOUT_MS = 10_000;
const BOOTSTRAP_ENV = "VIZIER_V0_2_BOOTSTRAP";

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

async function withTimeout<T>(
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), VERIFY_TIMEOUT_MS);
  try {
    return await operation(controller.signal);
  } finally {
    clearTimeout(timeout);
  }
}

async function main(): Promise<number> {
  if (process.argv.length > 2) {
    throw new Error("vizier-gated-deploy does not accept command arguments.");
  }

  const metadata = await collectDeployMetadata();
  const apiKey = await readKeychainSecret();
  const vizier = new Vizier({ baseUrl: VIZIER_BASE_URL, apiKey });
  if (process.env[BOOTSTRAP_ENV] === "1") {
    assertCleanWorktree(metadata);
    const result = await runGatedDeploy({
      metadata,
      verify: (request) =>
        withTimeout((signal) => vizier.verify(request, { signal })),
      execute: executeWranglerDeploy,
    });
    console.log(
      JSON.stringify({
        event: "vizier.gated_deploy.bootstrap.completed",
        status: result.status,
        decision: result.decision,
        receipt_id: result.receiptId,
        reason_codes: result.reasonCodes,
        ...(result.status === "stopped" ? {} : { exit_code: result.exitCode }),
      }),
    );
    return result.status === "stopped" ? 2 : result.exitCode;
  }

  const result = await runCovenantGatedDeploy({
    metadata,
    gate: {
      activateCovenant: (request) =>
        withTimeout((signal) => vizier.activateCovenant(request, { signal })),
      authorizeCovenant: (request) =>
        withTimeout((signal) => vizier.authorizeCovenant(request, { signal })),
      recordOutcome: (request) =>
        withTimeout((signal) => vizier.recordOutcome(request, { signal })),
    },
    execute: executeWranglerDeploy,
  });

  console.log(
    JSON.stringify({
      event: "vizier.gated_deploy.completed",
      status: result.status,
      decision: result.decision,
      authorization_receipt_id: result.authorizationReceiptId,
      reason_codes: result.reasonCodes,
      ...(result.status === "stopped"
        ? {}
        : {
            exit_code: result.exitCode,
            ...(result.status === "outcome_unrecorded"
              ? {
                  deployment_status: result.deploymentStatus,
                  outcome_error: result.error,
                }
              : {
                  outcome_receipt_id: result.outcomeReceiptId,
                  outcome_compliance: result.outcomeCompliance,
                }),
          }),
    }),
  );

  if (result.status === "stopped") {
    return 2;
  }
  if (result.status === "outcome_unrecorded") {
    return 3;
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
