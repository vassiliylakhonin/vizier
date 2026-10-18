import { readFileSync, readdirSync } from "node:fs";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import type { D1Database } from "@cloudflare/workers-types";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Vizier, type VerificationResponse } from "@agenda-intelligence/vizier-sdk";
import {
  createWorkerVersionDeployer,
  prepareWorkerDeploymentReview,
  workerDeploymentAuthority,
  type WorkerVersionPlan,
} from "../packages/gated-deploy/src/worker-version";
import { mintDelegationGrant } from "../src/core/grants";
import { handleHttpRequest } from "../src/transport/http";
import type { TransportOptions } from "../src/transport/shared";

const scope = {
  account_id: "0123456789abcdef0123456789abcdef",
  worker_name: "pilot-existing-worker",
  principal_id: "platform-owner",
  agent_id: "release-agent",
};
const plan: WorkerVersionPlan = {
  operation: "deploy_worker_version", account_id: scope.account_id, worker_name: scope.worker_name,
  version_id: "023e105f-2a42-4f8b-a1c1-73f6a2a30c0f", percentage: 100,
};
const otherVersion = "123e105f-2a42-4f8b-a1c1-73f6a2a30c0f";
const deploymentId = "182bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e";
let db: DatabaseSync;
let options: TransportOptions;
let privateKey: string;
let client: Vizier;
let grant: string;
let transformVerification: ((body: VerificationResponse) => unknown) | undefined;
let beforeVerification: (() => void) | undefined;
let afterClaim: (() => void) | undefined;
let unavailablePath: string | undefined;
let cloudResult: () => Response | Promise<Response>;
let requests: string[];
const cloud = vi.fn<typeof fetch>();

function fakeD1(): D1Database {
  db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys=ON");
  const directory = new URL("../migrations/", import.meta.url);
  for (const file of readdirSync(directory).filter(name => name.endsWith(".sql")).sort()) {
    db.exec(readFileSync(new URL(file, directory), "utf8"));
  }
  function prepare(query: string, values: SQLInputValue[] = []) {
    return {
      bind(...args: SQLInputValue[]) { return prepare(query, args); },
      async first() { return db.prepare(query).get(...values) ?? null; },
      async all() { return { results: db.prepare(query).all(...values), success: true }; },
      async run() { return { success: true, meta: { changes: Number(db.prepare(query).run(...values).changes) } }; },
    };
  }
  return { prepare } as unknown as D1Database;
}

function cloudAcknowledgement(version = plan.version_id): Response {
  return Response.json({ success: true, errors: [], result: {
    id: deploymentId, strategy: "percentage", versions: [{ version_id: version, percentage: 100 }],
  } });
}

async function serviceFetch(input: Parameters<typeof fetch>[0], init?: RequestInit): Promise<Response> {
  const request = new Request(input, init);
  const path = new URL(request.url).pathname;
  requests.push(path);
  request.signal.throwIfAborted();
  if (path === unavailablePath) throw new Error("Synthetic unavailable service");
  if (path === "/v1/verify") beforeVerification?.();
  const response = await handleHttpRequest(request, options);
  if (path.endsWith("/consume") && response.ok) afterClaim?.();
  if (path === "/v1/verify" && transformVerification) {
    return Response.json(transformVerification(await response.json() as VerificationResponse));
  }
  return response;
}

async function signedGrant(overrides: Partial<Parameters<typeof mintDelegationGrant>[0]> = {}) {
  return mintDelegationGrant({
    signingKey: privateKey, issuer: scope.principal_id, subject: scope.agent_id,
    authority: workerDeploymentAuthority(scope), ttlSeconds: 600, ...overrides,
  });
}

async function approvalFor(input: unknown = plan, decision = "APPROVED") {
  const row = await client.submitHumanReview(prepareWorkerDeploymentReview(scope, input));
  const response = await handleHttpRequest(new Request(`https://vizier.test/v1/reviews/${row.id}/decision`, {
    method: "POST", headers: { Authorization: "Bearer reviewer", "Content-Type": "application/json" },
    body: JSON.stringify({ request_hash: row.request_hash, decision, reason: "Synthetic fixture operator decision" }),
  }), options);
  expect(response.status).toBe(200);
  return await response.json() as { id: string; token: string };
}

function deployer(overrides: Partial<Parameters<typeof createWorkerVersionDeployer>[0]> = {}) {
  return createWorkerVersionDeployer({ scope, vizier: client, cloudflareApiToken: "synthetic-cloud-token", cloudflareFetch: cloud, ...overrides });
}

beforeEach(async () => {
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  privateKey = JSON.stringify({ ...await crypto.subtle.exportKey("jwk", pair.privateKey), alg: "ES256", kid: "fixture-only", use: "sig" });
  const publicKey = { ...await crypto.subtle.exportKey("jwk", pair.publicKey), alg: "ES256", kid: "fixture-only", use: "sig" };
  const receiptPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const receiptSigningKey = JSON.stringify({
    ...await crypto.subtle.exportKey("jwk", receiptPair.privateKey), alg: "ES256", kid: "fixture-service-only", use: "sig",
  });
  options = {
    apiKey: "integration", reviewerApiKey: "reviewer", db: fakeD1(), receiptSigningKey,
    principalKeySource: JSON.stringify({ [scope.principal_id]: publicKey }), signedGrantModeSource: "required",
  };
  requests = [];
  transformVerification = undefined;
  beforeVerification = undefined;
  afterClaim = undefined;
  unavailablePath = undefined;
  client = new Vizier({ baseUrl: "https://vizier.test", apiKey: "integration", fetch: serviceFetch });
  grant = await signedGrant();
  cloudResult = () => cloudAcknowledgement();
  cloud.mockReset().mockImplementation(async () => cloudResult());
});

afterEach(() => { db.close(); vi.restoreAllMocks(); });

describe("Worker version deployment pilot — offline execution boundary", () => {
  it("creates exactly the approved deployment after signed scope and human approval", async () => {
    const approval = await approvalFor();
    const result = await deployer()({ plan, grant, approval });
    expect(result).toMatchObject({ status: "deployment_created", execution: "acknowledged", deploymentId, approvalId: approval.id });
    expect(cloud).toHaveBeenCalledTimes(1);
    const [url, init] = cloud.mock.calls[0]!;
    expect(url).toBe(`https://api.cloudflare.com/client/v4/accounts/${scope.account_id}/workers/scripts/${scope.worker_name}/deployments`);
    expect(init).toMatchObject({ method: "POST", redirect: "error", headers: { Authorization: "Bearer synthetic-cloud-token" } });
    expect(JSON.parse(init!.body as string)).toEqual({ strategy: "percentage", versions: [{ version_id: plan.version_id, percentage: 100 }] });
    expect(JSON.stringify(result)).not.toContain("synthetic-cloud-token");
    expect(db.prepare("SELECT status FROM human_reviews WHERE id=?").get(approval.id)!.status).toBe("CONSUMED");
  });

  it.each([
    ["different account", { account_id: "1123456789abcdef0123456789abcdef" }],
    ["different Worker", { worker_name: "unapproved-worker" }],
    ["create resource", { operation: "create_worker" }],
    ["spawn another agent", { operation: "spawn_agent" }],
    ["issue credential", { operation: "create_api_token" }],
    ["shell argument", { command: "execute arbitrary command" }],
    ["upstream URL", { url: "https://example.invalid" }],
    ["supplied authority", { authority: { allowed_actions: ["*"] } }],
    ["supplied credential", { cloudflareApiToken: "attacker" }],
    ["path traversal", { worker_name: "../other" }],
    ["partial rollout", { percentage: 50 }],
    ["invalid version", { version_id: "latest" }],
  ])("rejects %s before contacting authorization or Cloudflare", async (_label, changes) => {
    expect(await deployer()({ plan: { ...plan, ...changes }, grant, approval: { id: "unused", token: "unused" } }))
      .toMatchObject({ status: "stopped", reason: "PLAN_OUTSIDE_SCOPE_OR_INVALID", execution: "not_performed" });
    expect(requests).toEqual([]);
    expect(cloud).not.toHaveBeenCalled();
  });

  it("rejects a changed version despite valid owner scope", async () => {
    const approval = await approvalFor();
    expect(await deployer()({ plan: { ...plan, version_id: otherVersion }, grant, approval })).toMatchObject({ status: "stopped" });
    expect(cloud).not.toHaveBeenCalled();
    expect(db.prepare("SELECT status FROM human_reviews WHERE id=?").get(approval.id)!.status).toBe("APPROVED");
  });

  it("requires human approval even when owner delegation is valid", async () => {
    expect(await deployer()({ plan, grant, approval: { id: "", token: "" } })).toMatchObject({ reason: "AUTHORIZATION_REQUIRED" });
    expect(cloud).not.toHaveBeenCalled();
  });

  it("rejects a forged human approval before consuming it", async () => {
    const approval = await approvalFor();
    approval.token = approval.token.slice(0, -10) + "xxxxxxxxxx";
    expect(await deployer()({ plan, grant, approval })).toMatchObject({ status: "stopped" });
    expect(requests.some(path => path.endsWith("/consume"))).toBe(false);
    expect(cloud).not.toHaveBeenCalled();
  });

  it.each(["expired", "forged", "different agent", "widened authority", "missing"])("rejects a %s grant", async kind => {
    const approval = await approvalFor();
    const badGrant = kind === "expired" ? await signedGrant({ issuedAt: new Date(Date.now() - 120_000), ttlSeconds: 60 })
      : kind === "different agent" ? await signedGrant({ subject: "other-agent" })
        : kind === "widened authority" ? await signedGrant({ authority: { allowed_actions: ["deploy_worker_version", "create_worker"], constraints: {} } })
          : kind === "missing" ? "" : grant.slice(0, -10) + "xxxxxxxxxx";
    expect(await deployer()({ plan, grant: badGrant, approval })).toMatchObject({ status: "stopped" });
    expect(cloud).not.toHaveBeenCalled();
  });

  it("rejects a human rejection", async () => {
    expect(await deployer()({ plan, grant, approval: await approvalFor(plan, "REJECTED") })).toMatchObject({ status: "stopped" });
    expect(cloud).not.toHaveBeenCalled();
  });

  it("rejects expired human approval while delegation is still valid", async () => {
    const approval = await approvalFor();
    const later = Date.now() + 301_000;
    vi.spyOn(Date, "now").mockReturnValue(later);
    expect(await deployer()({ plan, grant, approval })).toMatchObject({ status: "stopped" });
    expect(cloud).not.toHaveBeenCalled();
  });

  it.each(["BLOCK", "REVIEW"] as const)("does not consume approval or execute on policy %s", async decision => {
    const approval = await approvalFor();
    transformVerification = response => ({ ...response, decision, risk_score: 0.5,
      reason_codes: ["FIXTURE_POLICY"], policy_results: [{ rule_id: "fixture", result: decision === "BLOCK" ? "FAIL" : "REVIEW", reason_code: "FIXTURE_POLICY", details: {} }],
      receipt: { ...response.receipt, decision, risk_score: 0.5, reason_codes: ["FIXTURE_POLICY"], policy_rule_ids: ["fixture"] },
    });
    expect(await deployer()({ plan, grant, approval })).toMatchObject({ reason: `POLICY_${decision}` });
    expect(requests.some(path => path.endsWith("/consume"))).toBe(false);
    expect(cloud).not.toHaveBeenCalled();
  });

  it.each(["wrong request hash", "unverified authority", "wrong issuer", "wrong subject", "malformed"])("rejects an ALLOW with %s", async kind => {
    const approval = await approvalFor();
    transformVerification = response => kind === "malformed" ? { decision: "ALLOW" }
      : { ...response, receipt: { ...response.receipt,
        ...(kind === "wrong request hash" ? { request_hash: "f".repeat(64) } : {}),
        ...(kind === "unverified authority" ? { authority_provenance: "unverified" } : {}),
        grant: { ...response.receipt.grant!, ...(kind === "wrong issuer" ? { issuer: "other-owner" } : {}),
          ...(kind === "wrong subject" ? { subject: "other-agent" } : {}) },
      } };
    expect(await deployer()({ plan, grant, approval })).toMatchObject({ status: "stopped" });
    expect(cloud).not.toHaveBeenCalled();
  });

  it.each(["/v1/verify", "/.well-known/jwks.json"])("fails closed when %s is unavailable", async path => {
    const approval = await approvalFor();
    unavailablePath = path;
    expect(await deployer()({ plan, grant, approval })).toMatchObject({ status: "stopped" });
    expect(cloud).not.toHaveBeenCalled();
  });

  it("fails closed when approval consumption is unavailable", async () => {
    const approval = await approvalFor();
    unavailablePath = `/v1/reviews/${approval.id}/consume`;
    expect(await deployer()({ plan, grant, approval })).toMatchObject({ status: "stopped" });
    expect(cloud).not.toHaveBeenCalled();
  });

  it("fails closed when the authorization deadline aborts the request", async () => {
    const approval = await approvalFor();
    const timeout = vi.spyOn(AbortSignal, "timeout").mockReturnValue(AbortSignal.abort());
    expect(await deployer()({ plan, grant, approval })).toMatchObject({ status: "stopped" });
    expect(timeout).toHaveBeenCalledWith(10_000);
    expect(cloud).not.toHaveBeenCalled();
  });

  it("does not execute twice for a replayed approval", async () => {
    const input = { plan, grant, approval: await approvalFor() };
    const execute = deployer();
    expect(await execute(input)).toMatchObject({ status: "deployment_created" });
    expect(await execute(input)).toMatchObject({ status: "stopped" });
    expect(cloud).toHaveBeenCalledTimes(1);
  });

  it("confirms the real ID-only Cloudflare acknowledgement through deployment history without a second POST", async () => {
    const captured = JSON.parse(readFileSync(new URL("./fixtures/cloudflare-deployment-create-2026-10-13.json", import.meta.url), "utf8"));
    const id = captured.result.id as string;
    cloud.mockImplementation(async (_url, init) => init?.method === "GET"
      ? Response.json({ success: true, errors: [], result: { deployments: [
        { id, strategy: "percentage", versions: [{ version_id: plan.version_id, percentage: 100 }] },
      ] } })
      : Response.json(captured));
    const result = await deployer()({ plan, grant, approval: await approvalFor() });
    expect(result).toMatchObject({ status: "deployment_created", deploymentId: id });
    expect(cloud.mock.calls.map(call => call[1]?.method)).toEqual(["POST", "GET"]);
    expect(cloud.mock.calls[1]![0]).toBe(cloud.mock.calls[0]![0]);
    expect(cloud.mock.calls[1]![1]!.body).toBeUndefined();
    expect(cloud.mock.calls[1]![1]!.redirect).toBe("error");
    expect(cloud.mock.calls[1]![1]!.signal).toBe(cloud.mock.calls[0]![1]!.signal);
  });

  it.each(["missing ID", "wrong ID", "wrong version", "wrong percentage", "duplicate ID", "HTTP failure", "non-JSON", "response loss"])("keeps an ID-only acknowledgement unresolved after history %s", async kind => {
    const id = deploymentId;
    cloud.mockImplementation(async (_url, init) => {
      if (init?.method === "POST") return Response.json({ success: true, errors: [], result: { id } });
      if (kind === "response loss") throw new Error("Synthetic history response loss");
      if (kind === "HTTP failure") return Response.json({ success: false }, { status: 503 });
      if (kind === "non-JSON") return new Response("invalid");
      const row = { id: kind === "wrong ID" ? "123e105f-2a42-4f8b-a1c1-73f6a2a30c0f" : id,
        strategy: "percentage", versions: [{ version_id: kind === "wrong version" ? otherVersion : plan.version_id,
          percentage: kind === "wrong percentage" ? 50 : 100 }] };
      return Response.json({ success: true, errors: [], result: { deployments:
        kind === "missing ID" ? [] : kind === "duplicate ID" ? [row, row] : [row] } });
    });
    const input = { plan, grant, approval: await approvalFor() };
    expect(await deployer()(input)).toMatchObject({ status: "reconcile_required", execution: "unknown", deploymentId: id });
    expect(await deployer()(input)).toMatchObject({ status: "stopped" });
    expect(cloud.mock.calls.map(call => call[1]?.method)).toEqual(["POST", "GET"]);
  });

  it("admits one of two concurrent claimants through separate executors", async () => {
    const input = { plan, grant, approval: await approvalFor() };
    const results = await Promise.all([deployer()(input), deployer()(input)]);
    expect(results.map(result => result.status).sort()).toEqual(["deployment_created", "stopped"]);
    expect(cloud).toHaveBeenCalledTimes(1);
  });

  it("snapshots the plan and operator scope before asynchronous verification", async () => {
    const mutableScope = { ...scope };
    const mutablePlan = { ...plan };
    const input = { plan: mutablePlan, grant, approval: await approvalFor() };
    const execute = deployer({ scope: mutableScope });
    beforeVerification = () => {
      mutablePlan.version_id = otherVersion;
      mutableScope.worker_name = "changed-after-construction";
      input.grant = "replaced";
      input.approval.token = "replaced";
    };
    expect(await execute(input)).toMatchObject({ status: "deployment_created" });
    expect(JSON.parse(cloud.mock.calls[0]![1]!.body as string).versions[0].version_id).toBe(plan.version_id);
  });

  it("rechecks grant expiry after consuming approval", async () => {
    const input = { plan, grant, approval: await approvalFor() };
    afterClaim = () => { vi.spyOn(Date, "now").mockReturnValue(Date.now() + 601_000); };
    expect(await deployer()(input)).toMatchObject({ reason: "GRANT_EXPIRED_BEFORE_EXECUTION" });
    expect(cloud).not.toHaveBeenCalled();
  });

  it("does not execute or automatically reclaim after a lost claim response", async () => {
    const input = { plan, grant, approval: await approvalFor() };
    afterClaim = () => { throw new Error("Synthetic claim response loss"); };
    expect(await deployer()(input)).toMatchObject({ reason: "AUTHORIZATION_FAILED_RECONCILE_APPROVAL" });
    afterClaim = undefined;
    expect(await deployer()(input)).toMatchObject({ status: "stopped" });
    expect(cloud).not.toHaveBeenCalled();
  });

  it.each(["lost response", "wrong version", "non-JSON", "HTTP failure", "error envelope"])("requires reconciliation after Cloudflare %s", async kind => {
    const input = { plan, grant, approval: await approvalFor() };
    cloudResult = () => {
      if (kind === "lost response") throw new Error("Synthetic Cloudflare response loss");
      if (kind === "wrong version") return cloudAcknowledgement(otherVersion);
      if (kind === "non-JSON") return new Response("invalid");
      if (kind === "HTTP failure") return new Response("unavailable", { status: 503 });
      return Response.json({ success: false, errors: [{ message: "not confirmed" }] });
    };
    expect(await deployer()(input)).toMatchObject({ status: "reconcile_required", execution: "unknown" });
    expect(await deployer()(input)).toMatchObject({ status: "stopped" });
    expect(cloud).toHaveBeenCalledTimes(1);
  });
});
