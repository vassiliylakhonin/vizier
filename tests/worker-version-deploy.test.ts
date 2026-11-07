import { SqliteExecutionJournal } from "../packages/gated-deploy/src/execution-journal";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { createWorkerDeploymentGateway } from "../packages/gated-deploy/src/worker-gateway";
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


async function gatewayApproval() {
  const { id, token } = await approvalFor();
  return { id, token };
}
const gatewayToken = "synthetic-client-capability-0123456789";
async function withGateway(
  run: (url: string) => Promise<void>,
  loadGrant: () => Promise<string> = async () => grant,
) {
  const server = createWorkerDeploymentGateway({
    scope, vizier: client, cloudflareApiToken: "synthetic-cloud-token",
    cloudflareFetch: cloud, clientToken: gatewayToken, loadGrant,
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing test server address");
  try { await run(`http://127.0.0.1:${address.port}/execute`); }
  finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
}
function gatewayCall(url: string, body: unknown, headers: Record<string, string> = {}) {
  return fetch(url, {
    method: "POST", headers: { Authorization: `Bearer ${gatewayToken}`, "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("operator-owned deployment gateway", () => {
  it("rejects concurrent requests while an execution is in flight", async () => {
    const approval = await gatewayApproval();
    let release!: () => void;
    let entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const blocked = new Promise<void>(resolve => { release = resolve; });
    await withGateway(async url => {
      const first = gatewayCall(url, { plan, approval });
      try {
        await started;
        expect((await gatewayCall(url, { plan, approval })).status).toBe(409);
      } finally { release(); }
      expect(await (await first).json()).toMatchObject({ status: "deployment_created" });
    }, async () => { entered(); await blocked; return grant; });
    expect(cloud).toHaveBeenCalledTimes(1);
  });

  it("fails closed at the HTTP boundary when Vizier is unavailable", async () => {
    const approval = await gatewayApproval();
    unavailablePath = "/v1/verify";
    await withGateway(async url => {
      expect(await (await gatewayCall(url, { plan, approval })).json()).toMatchObject({ status: "stopped", execution: "not_performed" });
    });
    expect(cloud).not.toHaveBeenCalled();
  });

  it("executes with operator credentials and refuses approval replay across gateway restarts", async () => {
    const approval = await gatewayApproval();
    await withGateway(async url => {
      const response = await gatewayCall(url, { plan, approval });
      expect(response.status).toBe(200);
      const body = await response.text();
      expect(JSON.parse(body)).toMatchObject({ status: "deployment_created" });
      for (const secret of [grant, approval.token, "synthetic-cloud-token", gatewayToken]) expect(body).not.toContain(secret);
    });
    await withGateway(async url => {
      expect(await (await gatewayCall(url, { plan, approval })).json()).toMatchObject({ status: "stopped" });
    });
    expect(cloud).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["grant", { grant: "agent-controlled" }],
    ["scope", { scope: { ...scope, worker_name: "other-worker" } }],
    ["upstream", { url: "https://attacker.invalid" }],
    ["credential", { cloudflareApiToken: "attacker" }],
  ])("rejects agent-supplied %s before authorization", async (_label, injection) => {
    await withGateway(async url => {
      expect((await gatewayCall(url, { plan, approval: { id: "unused", token: "unused" }, ...injection })).status).toBe(400);
    });
    expect(requests).toEqual([]);
    expect(cloud).not.toHaveBeenCalled();
  });

  it("rejects unauthenticated, browser, alternate-path and oversized calls", async () => {
    await withGateway(async url => {
      expect((await gatewayCall(url, {}, { Authorization: "Bearer wrong" })).status).toBe(401);
      expect((await gatewayCall(url, {}, { Origin: "https://attacker.invalid" })).status).toBe(404);
      expect((await gatewayCall(`${url}?target=other`, {})).status).toBe(404);
      expect((await gatewayCall(url, {}, { "Content-Type": "text/plain" })).status).toBe(415);
      expect((await gatewayCall(url, { padding: "x".repeat(33_000) })).status).toBe(413);
    });
    expect(requests).toEqual([]);
    expect(cloud).not.toHaveBeenCalled();
  });

  it("stops when the operator grant is unavailable, without consuming approval", async () => {
    const approval = await gatewayApproval();
    await withGateway(async url => {
      expect((await gatewayCall(url, { plan, approval })).status).toBe(503);
    }, async () => { throw new Error("synthetic secret must not escape"); });
    expect(cloud).not.toHaveBeenCalled();
    expect(db.prepare("SELECT status FROM human_reviews WHERE id=?").get(approval.id)!.status).toBe("APPROVED");
  });

  it("loads rotated grants on each call and rejects changed versions and expired grants", async () => {
    const approval = await gatewayApproval();
    const provider = vi.fn(async () => grant);
    await withGateway(async url => {
      expect(await (await gatewayCall(url, { plan: { ...plan, version_id: otherVersion }, approval })).json()).toMatchObject({ status: "stopped" });
      grant = await signedGrant({ issuedAt: new Date(Date.now() - 120_000), ttlSeconds: 1 });
      expect(await (await gatewayCall(url, { plan, approval })).json()).toMatchObject({ status: "stopped" });
    }, provider);
    expect(provider).toHaveBeenCalledTimes(2);
    expect(cloud).not.toHaveBeenCalled();
  });

  it("preserves uncertainty and never redeploys after a lost cloud response", async () => {
    const approval = await gatewayApproval();
    cloudResult = () => { throw new Error("Cloud committed, response lost"); };
    await withGateway(async url => {
      expect(await (await gatewayCall(url, { plan, approval })).json()).toMatchObject({ status: "reconcile_required", execution: "unknown" });
      expect(await (await gatewayCall(url, { plan, approval })).json()).toMatchObject({ status: "stopped" });
    });
    expect(cloud).toHaveBeenCalledTimes(1);
  });
});


// Explicitly opt in inside the disposable Linux container; never change host users.
it.runIf(process.env.VIZIER_ISOLATION_TEST === "1")("enforces the boundary against a separate unprivileged Linux process", async () => {
  expect(process.platform).toBe("linux");
  expect(process.getuid?.()).toBe(0);
  const directory = mkdtempSync(join(tmpdir(), "vizier-executor-"));
  chmodSync(directory, 0o700);
  const cloudToken = crypto.randomUUID();
  const secretPath = join(directory, "credential");
  const configPath = join(directory, "scope.json");
  writeFileSync(secretPath, cloudToken, { mode: 0o600 });
  writeFileSync(configPath, JSON.stringify(scope), { mode: 0o600 });
  let cloudPosts = 0;
  const upstream = createServer((request, response) => {
    if (request.headers.authorization !== `Bearer ${cloudToken}`) {
      response.writeHead(401); response.end(); return;
    }
    if (request.method !== "POST") { response.writeHead(405); response.end(); return; }
    cloudPosts++;
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ success: true, errors: [], result: {
      id: deploymentId, strategy: "percentage", versions: [{ version_id: plan.version_id, percentage: 100 }],
    } }));
  });
  const listen = async (server: ReturnType<typeof createServer>) => {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject); server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Missing address");
    return `http://127.0.0.1:${address.port}`;
  };
  const close = async (server: ReturnType<typeof createServer>) => {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  };
  const journalPath = join(directory, "executions.sqlite");
  const isolatedJournal = new SqliteExecutionJournal(journalPath);
  let gateway: ReturnType<typeof createWorkerDeploymentGateway> | undefined;
  try {
    const cloudUrl = await listen(upstream);
    gateway = createWorkerDeploymentGateway({
      scope, vizier: client, journal: isolatedJournal, cloudflareApiToken: cloudToken, clientToken: gatewayToken,
      loadGrant: async () => grant,
      cloudflareFetch: async (_url, init) => fetch(cloudUrl, init),
    });
    const gatewayUrl = await listen(gateway);
    const approval = await gatewayApproval();
    // The child receives only the bounded capability and exact approved request.
    const program = `
      const assert = require('node:assert/strict');
      const fs = require('node:fs');
      (async () => {
        assert.equal(process.getuid(), 65534);
        for (const path of [process.env.SECRET_PATH, process.env.CONFIG_PATH, process.env.JOURNAL_PATH, '/proc/' + process.env.EXECUTOR_PID + '/environ']) {
          assert.throws(() => fs.readFileSync(path), error => ['EACCES', 'EPERM'].includes(error.code));
        }
        assert.throws(() => fs.writeFileSync(process.env.CONFIG_PATH, '{}'), error => error.code === 'EACCES');
        assert.throws(() => process.kill(Number(process.env.EXECUTOR_PID), 0), error => error.code === 'EPERM');
        assert.equal(process.env.CLOUDFLARE_API_TOKEN, undefined);
        assert.equal(process.env.VIZIER_API_KEY, undefined);
        // Both raw API and an equivalent CLI-style request lack cloud authority.
        for (const authorization of ['', 'Bearer ' + process.env.CAPABILITY]) {
          const direct = await fetch(process.env.CLOUD_URL, {method:'POST', headers:{authorization}});
          assert.equal(direct.status, 401);
        }
        const call = body => fetch(process.env.GATEWAY_URL + '/execute', {
          method:'POST', headers:{authorization:'Bearer ' + process.env.CAPABILITY, 'content-type':'application/json'},
          body:JSON.stringify(body)
        });
        const input = JSON.parse(process.env.APPROVED_REQUEST);
        const changed = structuredClone(input);
        changed.plan.version_id = '123e105f-2a42-4f8b-a1c1-73f6a2a30c0f';
        assert.equal((await (await call(changed)).json()).status, 'stopped');
        assert.equal((await call({...input, cloudflareApiToken:'override'})).status, 400);
        assert.equal((await (await call(input)).json()).status, 'deployment_created');
        assert.equal((await (await call(input)).json()).status, 'stopped');
        console.log('ISOLATION_PASS');
      })().catch(error => { console.error(error); process.exitCode = 1; });
    `;
    const child = await promisify(execFile)(process.execPath, ["-e", program], {
      uid: 65534, gid: 65534, cwd: "/tmp", timeout: 20_000,
      env: {
        SECRET_PATH: secretPath, CONFIG_PATH: configPath, JOURNAL_PATH: journalPath, EXECUTOR_PID: String(process.pid),
        CLOUD_URL: cloudUrl, GATEWAY_URL: gatewayUrl, CAPABILITY: gatewayToken,
        APPROVED_REQUEST: JSON.stringify({ plan, approval }),
      },
    });
    expect(child.stdout.trim()).toBe("ISOLATION_PASS");
    expect(cloudPosts).toBe(1);
  } finally {
    if (gateway) await close(gateway);
    await close(upstream);
    isolatedJournal.close();
    rmSync(directory, { recursive: true, force: true });
  }
});


describe("durable deployment execution journal", () => {
  let directory: string;
  let path: string;
  let journal: SqliteExecutionJournal;
  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "vizier-journal-test-"));
    path = join(directory, "executions.sqlite");
    journal = new SqliteExecutionJournal(path);
  });
  afterEach(() => { journal.close(); rmSync(directory, { recursive: true, force: true }); });

  it("persists acknowledgement across reopen without persisting credentials or grants", async () => {
    const approval = await approvalFor();
    expect(await deployer({ journal })({ plan, grant, approval })).toMatchObject({ status: "deployment_created" });
    const reopened = new SqliteExecutionJournal(path, { readOnly: true });
    try {
      expect(reopened.get(approval.id)).toMatchObject({ state: "acknowledged", deployment_id: deploymentId });
    } finally { reopened.close(); }
    const bytes = readFileSync(path).toString();
    for (const secret of [grant, approval.token, "synthetic-cloud-token"]) expect(bytes).not.toContain(secret);
    expect(await deployer({ journal })({ plan, grant, approval })).toMatchObject({ status: "stopped" });
    expect(journal.get(approval.id)?.state).toBe("acknowledged");
    expect(cloud).toHaveBeenCalledTimes(1);
  });

  it.each(["prepare", "dispatch"] as const)("does not call cloud when %s cannot commit", async method => {
    const approval = await approvalFor();
    vi.spyOn(journal, method).mockImplementation(() => { throw new Error("Disk unavailable"); });
    expect(await deployer({ journal })({ plan, grant, approval })).toMatchObject({ status: "stopped", reason: "JOURNAL_UNAVAILABLE_RECONCILE_APPROVAL" });
    expect(cloud).not.toHaveBeenCalled();
    expect(journal.get(approval.id)?.state ?? null).toBe(method === "dispatch" ? "prepared" : null);
    expect(db.prepare("SELECT status FROM human_reviews WHERE id=?").get(approval.id)!.status).toBe("CONSUMED");
  });

  it("retains dispatch uncertainty when the final journal commit fails", async () => {
    const approval = await approvalFor();
    vi.spyOn(journal, "finish").mockImplementation(() => { throw new Error("Disk unavailable after cloud effect"); });
    expect(await deployer({ journal })({ plan, grant, approval })).toMatchObject({ status: "reconcile_required", execution: "unknown", deploymentId });
    expect(journal.get(approval.id)?.state).toBe("dispatching");
    expect(cloud).toHaveBeenCalledTimes(1);
  });

  it("persists unknown after a lost cloud response and refuses another dispatch", async () => {
    const approval = await approvalFor();
    cloudResult = () => { throw new Error("Response lost"); };
    expect(await deployer({ journal })({ plan, grant, approval })).toMatchObject({ status: "reconcile_required" });
    expect(journal.get(approval.id)).toMatchObject({ state: "unknown", deployment_id: null });
    expect(await deployer({ journal })({ plan, grant, approval })).toMatchObject({ status: "stopped" });
    expect(cloud).toHaveBeenCalledTimes(1);
  });

  it("records nothing for an unapproved operation", async () => {
    const approval = await approvalFor();
    await deployer({ journal })({ plan: { ...plan, version_id: otherVersion }, grant, approval });
    expect(journal.get(approval.id)).toBeNull();
    expect(cloud).not.toHaveBeenCalled();
  });
});
