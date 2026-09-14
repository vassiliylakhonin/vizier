import { readFileSync } from "node:fs";

import { describe, expect, it, vi } from "vitest";

import { handleHttpRequest } from "../src/transport/http";
import {
  createMcpServerManifest,
  MCP_SERVER_SCHEMA,
} from "../src/transport/catalog";
import { verificationResponseContractSchema } from "../src/transport/contracts";
import { SERVICE_VERSION } from "../src/version";

const ORIGIN = "https://vizier.example";
const PUBLISHED_ORIGIN = "https://vizier.vassiliy-lakhonin.workers.dev";

function readJson(relativePath: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(new URL(`../${relativePath}`, import.meta.url), "utf8"),
  ) as Record<string, unknown>;
}

function publishedServerJson(): unknown {
  return JSON.parse(
    readFileSync(new URL("../server.json", import.meta.url), "utf8"),
  );
}

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
      info: { version: SERVICE_VERSION },
      servers: [{ url: ORIGIN }],
    });
    expect(Object.keys(document.paths as object).sort()).toEqual([
      "/.well-known/agent-card.json",
      "/.well-known/agent.json",
      "/.well-known/agents.txt",
      "/.well-known/ai-catalog.json",
      "/.well-known/ard.json",
      "/.well-known/glama.json",
      "/.well-known/jwks.json",
      "/.well-known/llms.txt",
      "/.well-known/mcp.json",
      "/.well-known/oauth-protected-resource",
      "/a2a",
      "/health",
      "/mcp",
      "/playground/evaluate",
      "/v1/admin/keys",
      "/v1/admin/keys/{key_id}",
      "/v1/authorizations",
      "/v1/chat/completions",
      "/v1/circuit-breaker/reset",
      "/v1/covenants",
      "/v1/dlp/scan",
      "/v1/insights",
      "/v1/models",
      "/v1/outcomes",
      "/v1/quorum/approve",
      "/v1/quorum/proposals/{proposal_id}",
      "/v1/quorum/propose",
      "/v1/sanctions/entries",
      "/v1/sanctions/screen",
      "/v1/sanctions/screen-entity",
      "/v1/verify",
      "/v1/verify/evaluate",
    ]);

    const paths = document.paths as Record<string, Record<string, { security?: unknown[] }>>;
    expect(paths["/v1/verify/evaluate"]?.post?.security).toEqual([]);
    expect(paths["/playground/evaluate"]?.post?.security).toEqual([]);
    expect(paths["/v1/models"]?.get?.security).toEqual([]);
    expect(paths["/health"]?.get?.security).toEqual([]);
    expect(paths["/a2a"]?.post?.security).toEqual([]);
    expect(paths["/mcp"]?.post?.security).toEqual([]);
    expect(paths["/.well-known/agent-card.json"]?.get?.security).toEqual([]);
    expect(paths["/.well-known/agent.json"]?.get?.security).toEqual([]);
    expect(paths["/.well-known/mcp.json"]?.get?.security).toEqual([]);
    expect(paths["/.well-known/ai-catalog.json"]?.get?.security).toEqual([]);
    expect(paths["/.well-known/glama.json"]?.get?.security).toEqual([]);
    expect(paths["/.well-known/llms.txt"]?.get?.security).toEqual([]);
    expect(paths["/.well-known/agents.txt"]?.get?.security).toEqual([]);
    expect(paths["/.well-known/oauth-protected-resource"]?.get?.security).toEqual([]);

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

  it("publishes an AI catalog that routes to A2A, OpenAPI and MCP", async () => {
    const response = await get("/.well-known/ai-catalog.json");
    const body = (await response.json()) as {
      specVersion: string;
      entries: Array<{ identifier: string; type: string; url: string; capabilities: string[] }>;
    };

    expect(response.status).toBe(200);
    expect(body.specVersion).toBe("1.0");
    expect(body.entries).toHaveLength(4);
    expect(body.entries.every((e) => e.identifier.startsWith("urn:air:"))).toBe(true);
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
        expect.objectContaining({
          type: `application/json;profile=${MCP_SERVER_SCHEMA}`,
          url: `${ORIGIN}/.well-known/mcp.json`,
          capabilities: expect.arrayContaining(["mcp-streamable-http"]),
        }),
        expect.objectContaining({
          type: "application/json",
          url: `${ORIGIN}/.well-known/oauth-protected-resource`,
          capabilities: expect.arrayContaining(["oauth2", "rfc9728"]),
        }),
      ]),
    );
  });


  it("publishes the ARD manifest at /.well-known/ard.json", async () => {
    const response = await get("/.well-known/ard.json");
    const body = (await response.json()) as {
      specVersion: string;
      entries: Array<{ identifier: string }>;
    };
    expect(response.status).toBe(200);
    expect(body.specVersion).toBe("1.0");
    expect(body.entries.every((e) => e.identifier.startsWith("urn:air:"))).toBe(true);
  });

  it("serves /llms.txt and /agents.txt discovery files", async () => {
    const llmsRes = await get("/llms.txt");
    expect(llmsRes.status).toBe(200);
    expect(llmsRes.headers.get("content-type")).toContain("text/plain");
    const llmsText = await llmsRes.text();
    expect(llmsText).toContain("# Vizier");
    expect(llmsText).toContain("## Discovery & Standards");
    expect(llmsText).toContain("[ARD (Agent Resource Discovery)](");
    expect(llmsText).toContain("[Glama MCP Verification](");
    expect(llmsText).toContain("/.well-known/ard.json");

    const agentsRes = await get("/agents.txt");
    expect(agentsRes.status).toBe(200);
    expect(agentsRes.headers.get("content-type")).toContain("text/plain");
    const agentsText = await agentsRes.text();
    expect(agentsText).toContain("User-agent: *");
    expect(agentsText).toContain("LLMs-txt:");
  });

  it("serves the Glama MCP verification manifest at /.well-known/glama.json and /glama.json", async () => {
    const [wellKnown, root] = await Promise.all([
      get("/.well-known/glama.json"),
      get("/glama.json"),
    ]);

    expect(wellKnown.status).toBe(200);
    expect(wellKnown.headers.get("Cache-Control")).toBe("public, max-age=300");
    const wellKnownJson = await wellKnown.json();
    expect(wellKnownJson).toEqual({
      $schema: "https://glama.ai/mcp/schemas/server.json",
      maintainers: ["vassiliylakhonin"],
    });

    expect(root.status).toBe(200);
    expect(await root.json()).toEqual(wellKnownJson);
  });

  it("serves /.well-known/agent.json as an identical alias to agent-card.json", async () => {
    const [card, alias] = await Promise.all([
      get("/.well-known/agent-card.json"),
      get("/.well-known/agent.json"),
    ]);

    expect(alias.status).toBe(200);
    expect(await alias.json()).toEqual(await card.json());
  });

  it("serves RFC 9728 OAuth Protected Resource Metadata for MCP", async () => {
    const [standard, mcpScoped] = await Promise.all([
      get("/.well-known/oauth-protected-resource"),
      get("/.well-known/oauth-protected-resource/mcp"),
    ]);

    expect(standard.status).toBe(200);
    expect(standard.headers.get("Cache-Control")).toBe("public, max-age=300");
    const body = (await standard.json()) as Record<string, unknown>;
    expect(body).toMatchObject({
      resource: `${ORIGIN}/mcp`,
      authorization_servers: [ORIGIN],
      scopes_supported: ["vizier:verify", "vizier:covenants", "vizier:audit"],
      bearer_methods_supported: ["header"],
      resource_documentation: `${ORIGIN}/docs`,
    });

    expect(mcpScoped.status).toBe(200);
    expect(await mcpScoped.json()).toEqual(body);
  });

  // A registry listing is only useful while it points at the endpoint this
  // Worker actually serves, so the published server.json and the served
  // manifest are one document checked against each other.
  it("serves the same MCP manifest that server.json publishes", async () => {
    const response = await get("/.well-known/mcp.json");
    const served = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=300");
    expect(served.$schema).toBe(MCP_SERVER_SCHEMA);
    expect(served.name).toBe("io.github.vassiliylakhonin/vizier");
    expect(served.version).toBe(SERVICE_VERSION);
    expect(served.remotes).toEqual([
      expect.objectContaining({ type: "streamable-http", url: `${ORIGIN}/mcp` }),
    ]);
    expect(createMcpServerManifest(PUBLISHED_ORIGIN)).toEqual(
      publishedServerJson(),
    );
  });

  // The version had been copied into nine files. A release that updates some
  // and not the rest is silent at runtime, and one of the copies now lives in
  // the MCP Registry, which only changes on an explicit `mcp-publisher publish`.
  it.each([
    "package.json",
    "server.json",
    "packages/sdk/package.json",
    "packages/mcp-proxy/package.json",
    "packages/gated-deploy/package.json",
  ])("keeps %s on the one service version", (path) => {
    expect(readJson(path).version).toBe(SERVICE_VERSION);
  });

  it("reports the same version on every public surface", async () => {
    const [root, docs, openapi, card, manifest] = await Promise.all([
      get("/").then((response) => response.json()),
      get("/docs").then((response) => response.json()),
      get("/openapi.json").then((response) => response.json()),
      get("/.well-known/agent-card.json").then((response) => response.json()),
      get("/.well-known/mcp.json").then((response) => response.json()),
    ]);

    expect((root as { version: string }).version).toBe(SERVICE_VERSION);
    expect((docs as { api_version: string }).api_version).toBe(
      `v${SERVICE_VERSION}`,
    );
    expect((openapi as { info: { version: string } }).info.version).toBe(
      SERVICE_VERSION,
    );
    expect((card as { version: string }).version).toBe(SERVICE_VERSION);
    expect((manifest as { version: string }).version).toBe(SERVICE_VERSION);
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
      version: SERVICE_VERSION,
      openapi: "/openapi.json",
      ai_catalog: "/.well-known/ai-catalog.json",
    });
    await expect(docs.json()).resolves.toMatchObject({
      api_version: `v${SERVICE_VERSION}`,
      machine_contracts: {
        openapi_3_1: "/openapi.json",
        ai_catalog: "/.well-known/ai-catalog.json",
      },
    });
  });
});
