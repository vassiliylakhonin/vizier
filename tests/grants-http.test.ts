import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { handleHttpRequest } from "../src/transport/http";

const run = promisify(execFile);
const TEST_API_KEY = "test-enforcement-key";

interface MintedPrincipal {
  readonly keyPath: string;
  readonly publicJwk: Record<string, unknown>;
}

let workdir: string;
let principal: MintedPrincipal;

beforeAll(async () => {
  workdir = await mkdtemp(join(tmpdir(), "vizier-grants-"));
  const keyPath = join(workdir, "principal.jwk.json");
  const { stdout } = await run("node", [
    "scripts/mint-grant.mjs",
    "keygen",
    "--kid",
    "acme-2026-09",
    "--out",
    keyPath,
  ]);
  const registered = JSON.parse(stdout) as Record<string, Record<string, unknown>>;
  principal = { keyPath, publicJwk: registered["<principal-id>"]! };
}, 30_000);

afterAll(async () => {
  await rm(workdir, { recursive: true, force: true });
});

/** Mint through the operator CLI, not the library, so drift between them fails here. */
async function mintViaCli(claims: Record<string, unknown>, ttl = 3_600): Promise<string> {
  const claimsPath = join(workdir, `grant-${crypto.randomUUID()}.json`);
  await writeFile(claimsPath, JSON.stringify(claims));
  const { stdout } = await run("node", [
    "scripts/mint-grant.mjs",
    "sign",
    "--key",
    principal.keyPath,
    "--grant",
    claimsPath,
    "--ttl",
    String(ttl),
  ]);
  return stdout.trim();
}

const AUTHORITY = {
  allowed_actions: ["purchase"],
  constraints: { max_amount: 10_000, currency: "USD" },
};

function body(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    agent: { id: "procurement-agent-01", owner: "acme-corp" },
    principal: { id: "acme-corp" },
    action: {
      type: "purchase",
      target: "supplier.example",
      parameters: { amount: 8_200, currency: "USD" },
    },
    authority: AUTHORITY,
    context: { request_id: "grant-http-01", timestamp: null, source: "rest" },
    ...overrides,
  };
}

async function verify(
  payload: unknown,
  principalKeySource?: string,
): Promise<Response> {
  return handleHttpRequest(
    new Request("https://vizier.example/v1/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${TEST_API_KEY}`,
      },
      body: JSON.stringify(payload),
    }),
    {
      apiKey: TEST_API_KEY,
      ...(principalKeySource === undefined ? {} : { principalKeySource }),
    },
  );
}

describe("delegation grants over HTTP", () => {
  it("accepts a grant minted by the operator CLI", async () => {
    const registry = JSON.stringify({ "acme-corp": principal.publicJwk });
    const grant = await mintViaCli({
      iss: "acme-corp",
      sub: "procurement-agent-01",
      authority: AUTHORITY,
    });

    const response = await verify(body({ grant }), registry);
    const payload = (await response.json()) as {
      decision: string;
      receipt: { authority_provenance: string; grant?: { issuer: string } };
    };

    expect(response.status).toBe(200);
    expect(payload.decision).toBe("ALLOW");
    expect(payload.receipt.authority_provenance).toBe("principal_signed");
    expect(payload.receipt.grant?.issuer).toBe("acme-corp");
  }, 30_000);

  it("blocks a CLI-minted grant carried beside a widened authority", async () => {
    const registry = JSON.stringify({ "acme-corp": principal.publicJwk });
    const grant = await mintViaCli({
      iss: "acme-corp",
      sub: "procurement-agent-01",
      authority: AUTHORITY,
    });

    const response = await verify(
      body({
        grant,
        authority: {
          allowed_actions: ["purchase"],
          constraints: { max_amount: 5_000_000, currency: "USD" },
        },
        action: {
          type: "purchase",
          target: "supplier.example",
          parameters: { amount: 4_000_000, currency: "USD" },
        },
      }),
      registry,
    );
    const payload = (await response.json()) as {
      decision: string;
      reason_codes: string[];
    };

    expect(payload.decision).toBe("BLOCK");
    expect(payload.reason_codes).toContain("GRANT_AUTHORITY_MISMATCH");
  }, 30_000);

  it("blocks a grant when the key registry is unparseable, and keeps serving requests without one", async () => {
    const grant = await mintViaCli({
      iss: "acme-corp",
      sub: "procurement-agent-01",
      authority: AUTHORITY,
    });

    const withGrant = (await (await verify(body({ grant }), "{not json")).json()) as {
      decision: string;
      reason_codes: string[];
    };
    expect(withGrant.decision).toBe("BLOCK");
    expect(withGrant.reason_codes).toContain("GRANT_PRINCIPAL_UNKNOWN");

    const withoutGrant = (await (await verify(body(), "{not json")).json()) as {
      decision: string;
    };
    expect(withoutGrant.decision).toBe("ALLOW");
  }, 30_000);

  it("rejects an oversized grant at the schema boundary", async () => {
    const response = await verify(body({ grant: "a".repeat(8_193) }));
    expect(response.status).toBe(422);
  });

  it("reports delegation configuration on the docs endpoint", async () => {
    const response = await handleHttpRequest(
      new Request("https://vizier.example/docs"),
      {
        apiKey: TEST_API_KEY,
        principalKeySource: JSON.stringify({ "acme-corp": principal.publicJwk }),
      },
    );
    const payload = (await response.json()) as {
      delegation: {
        registered_principals: number;
        principal_keys_valid: boolean;
        grant_field: string;
      };
    };

    expect(payload.delegation.registered_principals).toBe(1);
    expect(payload.delegation.principal_keys_valid).toBe(true);
    expect(payload.delegation.grant_field).toBe("grant");
  });
});
