import { timingSafeEqual } from "node:crypto";
import { createServer, type ServerResponse } from "node:http";
import { z } from "zod";
import { createWorkerVersionDeployer, type WorkerVersionDeploymentOptions } from "./worker-version.js";

const requestSchema = z.strictObject({
  plan: z.unknown(),
  approval: z.strictObject({ id: z.string().min(1).max(256), token: z.string().min(1).max(16_384) }),
});
const MAX_BODY = 32_768;

export interface WorkerDeploymentGatewayOptions extends WorkerVersionDeploymentOptions {
  /** Separate agent capability; never reuse the Vizier or Cloudflare credential. */
  readonly clientToken: string;
  /** Operator-controlled provider, read on each call to support grant rotation. */
  readonly loadGrant: () => Promise<string>;
}

/**
 * Run under a separate OS identity/container. Only POST /execute is exposed;
 * neither configuration, review decisions nor a general Cloudflare proxy are.
 * Bind to loopback (CLI default) or an operator-protected private transport.
 */
export function createWorkerDeploymentGateway(options: WorkerDeploymentGatewayOptions) {
  const clientToken = z.string().min(32).max(256).regex(/^[A-Za-z0-9_-]+$/).parse(options.clientToken);
  if (clientToken === options.cloudflareApiToken) throw new Error("Use a distinct client capability");
  const expected = Buffer.from(`Bearer ${clientToken}`);
  const execute = createWorkerVersionDeployer(options);
  const loadGrant = options.loadGrant;
  let busy = false;
  const reply = (response: ServerResponse, status: number, body: unknown) => {
    response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", Connection: "close" });
    response.end(JSON.stringify(body));
  };
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 10_000, headersTimeout: 5_000 }, (request, response) => {
    const handle = async () => {
      const supplied = Buffer.from(request.headers.authorization ?? "");
      if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
        reply(response, 401, { error: "UNAUTHORIZED" }); return;
      }
      // No browser/CORS surface, query parameters, arbitrary paths or methods.
      if (request.headers.origin !== undefined || request.method !== "POST" || request.url !== "/execute") {
        reply(response, 404, { error: "UNSUPPORTED_REQUEST" }); return;
      }
      if (request.headers["content-type"]?.toLowerCase() !== "application/json" || request.headers["content-encoding"] !== undefined) {
        reply(response, 415, { error: "JSON_REQUIRED" }); return;
      }
      if (busy) { reply(response, 409, { error: "EXECUTOR_BUSY" }); return; }
      busy = true;
      try {
        const chunks: Buffer[] = [];
        let size = 0;
        for await (const chunk of request) {
          const bytes = Buffer.from(chunk);
          size += bytes.length;
          if (size > MAX_BODY) { reply(response, 413, { error: "BODY_TOO_LARGE" }); return; }
          chunks.push(bytes);
        }
        let input: z.infer<typeof requestSchema>;
        try { input = requestSchema.parse(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch { reply(response, 400, { error: "INVALID_REQUEST" }); return; }
        let grant: string;
        try {
          grant = z.string().min(1).max(8192).parse(await loadGrant());
        } catch {
          reply(response, 503, { status: "stopped", execution: "not_performed", reason: "OPERATOR_GRANT_UNAVAILABLE" }); return;
        }
        const result = await execute({ ...input, grant });
        reply(response, 200, result);
      } finally { busy = false; }
    };
    void handle().catch(() => {
      // Unexpected failures may occur after a side effect. Never imply safe retry.
      if (!response.headersSent && !response.destroyed) {
        reply(response, 500, { error: "RECONCILE_REQUIRED", execution: "unknown" });
      } else response.destroy();
    });
  });
  // Bound slow/incomplete bodies as well as authorization and cloud deadlines.
  server.setTimeout(45_000, socket => socket.destroy());
  return server;
}
