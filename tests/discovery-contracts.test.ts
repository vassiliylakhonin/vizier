import { describe, expect, it, vi } from "vitest";

import { handleHttpRequest } from "../src/transport/http";
import { verificationResponseContractSchema } from "../src/transport/contracts";

const ORIGIN = "https://vizier.example";

function get(path: string): Promise<Response> {
  return handleHttpRequest(new Request(`${ORIGIN}${path}`));
}

function resolvePointer(document: unknown, reference: string): unknown {
  if (!reference.startsWith("#/")) {
    return undefined;
  }
  return reference
    .slice(2)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce<unknown>((value, part) => {
      if (typeof value !== "object" || value === null || !(part in value)) {
        return undefined;
      }
      return (value as Record<string, unknown>)[part];
    }, document);
}

function collectReferences(value: unknown, references: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectReferences(item, references);
    }
  } else if (typeof value === "object" && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      if (key === "$ref" && typeof item === "string") {
        references.push(item);
      } else {
        collectReferences(item, references);
      }
    }
  }
  return references;
}

describe("machine-readable discovery contracts", () => {
  it("publishes one OpenAPI 3.1 contract for every REST resource", async () => {
    const response = await get("/openapi.json");
    const document = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=300");
    expect(document).toMatchObject({
      openapi: "3.1.0",
      info: { version: "0.2.1" },
      servers: [{ url: ORIGIN }],
    });
    expect(Object.keys(document.paths as object).sort()).toEqual([
      "/v1/authorizations",
      "/v1/covenants",
      "/v1/outcomes",
      "/v1/verify",
    ]);

    const serialized = JSON.stringify(document);
    expect(serialized).not.toContain("#/$defs/");
    const references = collectReferences(document);
    expect(references.length).toBeGreaterThan(20);
    for (const reference of references) {
      expect(resolvePointer(document, reference), reference).toBeDefined();
    }
  });

  it("serves an identical well-known OpenAPI alias", async () => {
    const [canonical, alias] = await Promise.all([
      get("/openapi.json"),
      get("/.well-known/openapi.json"),
    ]);

    expect(alias.status).toBe(200);
    expect(await alias.json()).toEqual(await canonical.json());
  });

  it("publishes an AI catalog that routes to both A2A and OpenAPI", async () => {
    const response = await get("/.well-known/ai-catalog.json");
    const body = (await response.json()) as {
      specVersion: string;
      entries: Array<{ type: string; url: string; capabilities: string[] }>;
    };

    expect(response.status).toBe(200);
    expect(body.specVersion).toBe("1.0");
    expect(body.entries).toHaveLength(2);
    expect(body.entries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "application/a2a-agent-card+json",
          url: `${ORIGIN}/.well-known/agent-card.json`,
          capabilities: expect.arrayContaining(["activate-action-covenant"]),
        }),
        expect.objectContaining({
          type: "application/vnd.oai.openapi+json;version=3.1",
          url: `${ORIGIN}/openapi.json`,
        }),
      ]),
    );
  });

  it("keeps the documented verification response aligned with runtime output", async () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    const response = await handleHttpRequest(
      new Request(`${ORIGIN}/v1/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent: { id: "contract-test-agent", owner: "contract-test-principal" },
          principal: { id: "contract-test-principal" },
          action: {
            type: "deploy_worker",
            target: "worker:contract-test",
            parameters: {},
          },
          authority: {
            allowed_actions: ["deploy_worker"],
            constraints: { allowed_targets: ["worker:contract-test"] },
          },
          context: { request_id: "contract-test", timestamp: null, source: "rest" },
        }),
      }),
    );

    expect(response.status).toBe(200);
    expect(verificationResponseContractSchema.safeParse(await response.json()).success).toBe(
      true,
    );
  });

  it("links discovery contracts from the service index and field reference", async () => {
    const [root, docs] = await Promise.all([get("/"), get("/docs")]);

    await expect(root.json()).resolves.toMatchObject({
      version: "0.2.1",
      openapi: "/openapi.json",
      ai_catalog: "/.well-known/ai-catalog.json",
    });
    await expect(docs.json()).resolves.toMatchObject({
      api_version: "v0.2.1",
      machine_contracts: {
        openapi_3_1: "/openapi.json",
        ai_catalog: "/.well-known/ai-catalog.json",
      },
    });
  });
});
