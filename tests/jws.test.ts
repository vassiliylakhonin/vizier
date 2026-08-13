import { webcrypto } from "node:crypto";

import { describe, expect, it } from "vitest";

import { createAgentCard } from "../src/transport/a2a";
import { handleHttpRequest } from "../src/transport/http";
import {
  canonicalizeJson,
  createJwks,
  publicJwkFromPrivate,
  signAgentCard,
} from "../src/transport/jws";

async function createTestSigningKey(): Promise<string> {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const privateJwk = await webcrypto.subtle.exportKey("jwk", keyPair.privateKey);
  return JSON.stringify({
    ...privateJwk,
    alg: "ES256",
    kid: "vizier-test-key",
    use: "sig",
  });
}

function decodeBase64url(value: string): Uint8Array<ArrayBuffer> {
  const decoded = Buffer.from(value, "base64url");
  const bytes = new Uint8Array(decoded.length);
  bytes.set(decoded);
  return bytes;
}

describe("Agent Card JWS", () => {
  it("canonicalizes nested JSON deterministically", () => {
    expect(canonicalizeJson({ z: 1, a: { y: false, x: [3, 2, 1] } })).toBe(
      '{"a":{"x":[3,2,1],"y":false},"z":1}',
    );
  });

  it("publishes only the public part of the signing key", async () => {
    const signingKey = await createTestSigningKey();
    const jwks = createJwks(signingKey);

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({
      alg: "ES256",
      crv: "P-256",
      kid: "vizier-test-key",
      kty: "EC",
      use: "sig",
    });
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });

  it("creates an A2A v1 ES256 signature with a same-origin jku", async () => {
    const signingKey = await createTestSigningKey();
    const card = createAgentCard("https://vizier.example");
    const signedCard = await signAgentCard(card, signingKey);
    const signatures = signedCard.signatures as Array<{
      protected: string;
      signature: string;
    }>;
    const [signature] = signatures;

    expect(signatures).toHaveLength(1);
    expect(signature).toBeDefined();
    const encodedHeader = signature?.protected;
    const encodedSignature = signature?.signature;
    expect(encodedHeader).toBeDefined();
    expect(encodedSignature).toBeDefined();

    const protectedHeader = JSON.parse(
      new TextDecoder().decode(decodeBase64url(encodedHeader ?? "")),
    ) as Record<string, unknown>;
    expect(protectedHeader).toEqual({
      alg: "ES256",
      jku: "https://vizier.example/.well-known/jwks.json",
      kid: "vizier-test-key",
      typ: "JOSE",
    });

    const unsignedCard = { ...signedCard };
    delete unsignedCard.signatures;
    const encodedPayload = Buffer.from(canonicalizeJson(unsignedCard)).toString(
      "base64url",
    );
    const signingInput = new TextEncoder().encode(
      `${encodedHeader}.${encodedPayload}`,
    );

    const verifyKey = await webcrypto.subtle.importKey(
      "jwk",
      publicJwkFromPrivate(signingKey),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    await expect(
      webcrypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        verifyKey,
        decodeBase64url(encodedSignature ?? ""),
        signingInput,
      ),
    ).resolves.toBe(true);
  });

  it("serves a signed card and matching public JWKS", async () => {
    const signingKey = await createTestSigningKey();
    const options = { agentCardSigningKey: signingKey };
    const cardResponse = await handleHttpRequest(
      new Request("https://vizier.example/.well-known/agent-card.json"),
      options,
    );
    const jwksResponse = await handleHttpRequest(
      new Request("https://vizier.example/.well-known/jwks.json"),
      options,
    );
    const card = (await cardResponse.json()) as Record<string, unknown>;
    const jwks = (await jwksResponse.json()) as {
      keys: Array<Record<string, unknown>>;
    };

    expect(card.signatures).toEqual([
      {
        protected: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
        signature: expect.stringMatching(/^[A-Za-z0-9_-]+$/),
      },
    ]);
    expect(card).not.toHaveProperty("signature");
    expect(jwks.keys[0]?.kid).toBe("vizier-test-key");
    expect(cardResponse.headers.get("Cache-Control")).toBe(
      "public, max-age=300",
    );
  });

  it("rejects malformed configured keys instead of serving an unsigned card", async () => {
    const response = await handleHttpRequest(
      new Request("https://vizier.example/.well-known/agent-card.json"),
      { agentCardSigningKey: "not-json" },
    );

    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "INTERNAL_ERROR" },
    });
  });
});
