import { assertJsonComplexity, JsonComplexityError } from "../core/index";

export const MAX_BODY_BYTES = 100 * 1024 * 1024;

import type { D1Database } from "@cloudflare/workers-types";

export interface TransportOptions {
  readonly apiKey?: string;
  readonly agentCardSigningKey?: string;
  readonly receiptSigningKey?: string;
  readonly db?: D1Database;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly ctx?: any;
}

export class TransportRequestError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}

export function jsonResponse(
  value: unknown,
  status = 200,
  extraHeaders?: Readonly<Record<string, string>>,
): Response {
  const headers = new Headers(extraHeaders);
  if (!headers.has("Cache-Control")) {
    headers.set("Cache-Control", "no-store");
  }
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(JSON.stringify(value), { status, headers });
}

export async function readLimitedJson(request: Request): Promise<unknown> {
  const contentType = request.headers.get("Content-Type")?.split(";", 1)[0]?.trim();
  if (contentType !== "application/json") {
    throw new TransportRequestError(
      415,
      "UNSUPPORTED_MEDIA_TYPE",
      "Content-Type must be application/json.",
    );
  }

  const declaredLength = request.headers.get("Content-Length");
  if (declaredLength !== null && Number(declaredLength) > MAX_BODY_BYTES) {
    throw new TransportRequestError(
      413,
      "PAYLOAD_TOO_LARGE",
      "Request body is too large.",
    );
  }
  if (request.body === null) {
    throw new TransportRequestError(
      400,
      "INVALID_JSON",
      "Request body must contain JSON.",
    );
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      totalBytes += value.byteLength;
      if (totalBytes > MAX_BODY_BYTES) {
        await reader.cancel("body size limit exceeded");
        throw new TransportRequestError(
          413,
          "PAYLOAD_TOO_LARGE",
          "Request body is too large.",
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body);
    const value = JSON.parse(text) as unknown;
    assertJsonComplexity(value);
    return value;
  } catch (error) {
    if (error instanceof TransportRequestError) {
      throw error;
    }
    if (error instanceof JsonComplexityError) {
      throw new TransportRequestError(
        413,
        "JSON_TOO_COMPLEX",
        "Request JSON exceeds the structural complexity limit.",
      );
    }
    throw new TransportRequestError(
      400,
      "INVALID_JSON",
      "Request body contains invalid JSON.",
    );
  }
}
