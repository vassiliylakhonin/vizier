import { describe, expect, it } from "vitest";

import {
  MAX_GRANT_LIFETIME_SECONDS,
  PrincipalKeyRegistryError,
  mintDelegationGrant,
  parsePrincipalKeyRegistry,
  verificationRequestSchema,
  verifyAction,
  type PrincipalKeyRegistry,
  type VerificationRequest,
} from "../src/core/index";
import { base64urlEncode, canonicalizeJson } from "../src/crypto/jws";

const AUTHORITY = {
  allowed_actions: ["purchase"],
  constraints: { max_amount: 10_000, currency: "USD" },
};

const WIDENED_AUTHORITY = {
  allowed_actions: ["purchase"],
  constraints: { max_amount: 5_000_000, currency: "USD" },
};

interface Signer {
  readonly privateKey: string;
  readonly publicJwk: Record<string, unknown>;
  readonly kid: string;
}

async function createSigner(kid: string): Promise<Signer> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const privateJwk = (await crypto.subtle.exportKey(
    "jwk",
    pair.privateKey,
  )) as Record<string, unknown>;
  const publicJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Record<
    string,
    unknown
  >;
  const common = { alg: "ES256", crv: "P-256", kid, kty: "EC", use: "sig" };
  return {
    kid,
    privateKey: JSON.stringify({ ...common, d: privateJwk.d, x: privateJwk.x, y: privateJwk.y }),
    publicJwk: { ...common, x: publicJwk.x, y: publicJwk.y },
  };
}

function registryOf(
  ...entries: readonly (readonly [string, Signer])[]
): PrincipalKeyRegistry {
  const source: Record<string, unknown> = {};
  for (const [principal, signer] of entries) {
    source[principal] = signer.publicJwk;
  }
  return parsePrincipalKeyRegistry(JSON.stringify(source));
}

function request(
  overrides: {
    readonly grant?: string;
    readonly authority?: unknown;
    readonly principalId?: string | null;
    readonly agentId?: string;
    readonly amount?: number;
  } = {},
): VerificationRequest {
  return verificationRequestSchema.parse({
    agent: { id: overrides.agentId ?? "procurement-agent-01", owner: "acme-corp" },
    principal:
      overrides.principalId === null ? null : { id: overrides.principalId ?? "acme-corp" },
    action: {
      type: "purchase",
      target: "supplier.example",
      parameters: { amount: overrides.amount ?? 8_200, currency: "USD" },
    },
    authority: overrides.authority ?? AUTHORITY,
    context: { request_id: "req-1", timestamp: null, source: "rest" },
    ...(overrides.grant === undefined ? {} : { grant: overrides.grant }),
  });
}

async function grantFor(
  signer: Signer,
  overrides: Partial<Parameters<typeof mintDelegationGrant>[0]> = {},
): Promise<string> {
  return mintDelegationGrant({
    signingKey: signer.privateKey,
    issuer: "acme-corp",
    subject: "procurement-agent-01",
    authority: AUTHORITY,
    ttlSeconds: 3_600,
    ...overrides,
  });
}

describe("delegation grants", () => {
  it("turns a caller-asserted authority into a principal-signed one", async () => {
    const signer = await createSigner("acme-2026-09");
    const grant = await grantFor(signer);

    const response = await verifyAction(request({ grant }), {
      trustedAuthority: true,
      principalKeys: registryOf(["acme-corp", signer]),
    });

    expect(response.decision).toBe("ALLOW");
    expect(response.receipt.authority_provenance).toBe("principal_signed");
    expect(response.receipt.grant).toMatchObject({
      issuer: "acme-corp",
      subject: "procurement-agent-01",
      key_id: "acme-2026-09",
    });
    expect(
      response.policy_results.find((item) => item.rule_id === "authority.grant.verified")
        ?.result,
    ).toBe("PASS");
  });

  it("leaves a request without a grant exactly as it was", async () => {
    const response = await verifyAction(request(), { trustedAuthority: true });

    expect(response.decision).toBe("ALLOW");
    expect(response.receipt.authority_provenance).toBe("trusted_integration");
    expect(response.receipt.grant).toBeUndefined();
    expect(
      response.policy_results.some((item) => item.rule_id === "authority.grant.verified"),
    ).toBe(false);
  });

  it("records that an unauthenticated caller's authority is unverified", async () => {
    const response = await verifyAction(request(), { trustedAuthority: false });

    expect(response.receipt.authority_provenance).toBe("unverified");
    expect(response.decision).not.toBe("ALLOW");
  });

  describe("binding the grant to the request", () => {
    it("blocks a real grant carried beside a widened authority", async () => {
      const signer = await createSigner("acme-2026-09");
      const grant = await grantFor(signer);

      // The grant is genuine and unexpired. Only the authority travelling
      // beside it in the request body has been enlarged.
      const response = await verifyAction(
        request({ grant, authority: WIDENED_AUTHORITY, amount: 4_000_000 }),
        { trustedAuthority: true, principalKeys: registryOf(["acme-corp", signer]) },
      );

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_AUTHORITY_MISMATCH");
      expect(response.receipt.authority_provenance).not.toBe("principal_signed");
    });

    it("blocks a grant issued to a different agent", async () => {
      const signer = await createSigner("acme-2026-09");
      const grant = await grantFor(signer, { subject: "some-other-agent" });

      const response = await verifyAction(request({ grant }), {
        trustedAuthority: true,
        principalKeys: registryOf(["acme-corp", signer]),
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_SUBJECT_MISMATCH");
    });

    it("blocks a grant issued by a different principal", async () => {
      const signer = await createSigner("other-2026-09");
      const grant = await grantFor(signer, { issuer: "other-corp" });

      const response = await verifyAction(request({ grant }), {
        trustedAuthority: true,
        principalKeys: registryOf(["other-corp", signer]),
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_ISSUER_MISMATCH");
    });

    it("blocks a grant when the request names no principal at all", async () => {
      const signer = await createSigner("acme-2026-09");
      const grant = await grantFor(signer);

      const response = await verifyAction(request({ grant, principalId: null }), {
        trustedAuthority: true,
        principalKeys: registryOf(["acme-corp", signer]),
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_ISSUER_MISMATCH");
    });

    it("blocks a grant addressed to a different audience", async () => {
      const signer = await createSigner("acme-2026-09");
      const grant = await grantFor(signer, { audience: "someone-else" });

      const response = await verifyAction(request({ grant }), {
        trustedAuthority: true,
        principalKeys: registryOf(["acme-corp", signer]),
        audience: "vizier",
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_AUDIENCE_MISMATCH");
    });
  });

  describe("signature and key resolution", () => {
    it("blocks a grant whose payload was edited after signing", async () => {
      const signer = await createSigner("acme-2026-09");
      const grant = await grantFor(signer);
      const [header, , signature] = grant.split(".");
      const forgedPayload = base64urlEncode(
        new TextEncoder().encode(
          canonicalizeJson({
            iss: "acme-corp",
            sub: "procurement-agent-01",
            jti: "grant_forged",
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3_600,
            authority: WIDENED_AUTHORITY,
          }),
        ),
      );
      const tampered = `${String(header)}.${forgedPayload}.${String(signature)}`;

      const response = await verifyAction(
        request({ grant: tampered, authority: WIDENED_AUTHORITY }),
        { trustedAuthority: true, principalKeys: registryOf(["acme-corp", signer]) },
      );

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_SIGNATURE_INVALID");
    });

    it("blocks a grant signed by an impostor reusing the registered key id", async () => {
      const real = await createSigner("acme-2026-09");
      const impostor = await createSigner("acme-2026-09");
      const grant = await grantFor(impostor);

      const response = await verifyAction(request({ grant }), {
        trustedAuthority: true,
        principalKeys: registryOf(["acme-corp", real]),
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_SIGNATURE_INVALID");
    });

    it("blocks a grant from a principal with no registered key", async () => {
      const signer = await createSigner("acme-2026-09");
      const grant = await grantFor(signer);

      const response = await verifyAction(request({ grant }), {
        trustedAuthority: true,
        principalKeys: registryOf(["someone-else", signer]),
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_PRINCIPAL_UNKNOWN");
    });

    it("blocks a grant naming a key id the principal has not registered", async () => {
      const registered = await createSigner("acme-2026-09");
      const rotated = await createSigner("acme-2027-01");
      const grant = await grantFor(rotated);

      const response = await verifyAction(request({ grant }), {
        trustedAuthority: true,
        principalKeys: registryOf(["acme-corp", registered]),
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_KEY_UNKNOWN");
    });

    it("blocks every grant when no principal keys are configured at all", async () => {
      const signer = await createSigner("acme-2026-09");
      const grant = await grantFor(signer);

      const response = await verifyAction(request({ grant }), {
        trustedAuthority: true,
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_PRINCIPAL_UNKNOWN");
    });
  });

  describe("validity window", () => {
    it("blocks an expired grant", async () => {
      const signer = await createSigner("acme-2026-09");
      const issuedAt = new Date(Date.now() - 7_200_000);
      const grant = await grantFor(signer, { issuedAt, ttlSeconds: 3_600 });

      const response = await verifyAction(request({ grant }), {
        trustedAuthority: true,
        principalKeys: registryOf(["acme-corp", signer]),
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_EXPIRED");
    });

    it("blocks a grant that is not yet valid", async () => {
      const signer = await createSigner("acme-2026-09");
      const grant = await grantFor(signer, {
        notBefore: new Date(Date.now() + 86_400_000),
        ttlSeconds: 172_800,
      });

      const response = await verifyAction(request({ grant }), {
        trustedAuthority: true,
        principalKeys: registryOf(["acme-corp", signer]),
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_NOT_YET_VALID");
    });

    it("refuses to mint a grant that outlives the maximum lifetime", async () => {
      const signer = await createSigner("acme-2026-09");
      await expect(
        grantFor(signer, { ttlSeconds: MAX_GRANT_LIFETIME_SECONDS + 1 }),
      ).rejects.toThrow(/ttlSeconds/);
    });
  });

  describe("malformed input", () => {
    it.each([
      ["not a JWS", "obviously-not-a-token"],
      ["two segments only", "aaa.bbb"],
      ["empty segments", "..."],
    ])("blocks a grant that is %s", async (_label, token) => {
      const signer = await createSigner("acme-2026-09");
      const response = await verifyAction(request({ grant: token }), {
        trustedAuthority: true,
        principalKeys: registryOf(["acme-corp", signer]),
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_MALFORMED");
    });

    it("blocks an unsigned grant that claims alg none", async () => {
      const signer = await createSigner("acme-2026-09");
      const encode = (value: unknown): string =>
        base64urlEncode(new TextEncoder().encode(canonicalizeJson(value)));
      const token = [
        encode({ alg: "none", kid: "acme-2026-09", typ: "vizier-delegation+jws" }),
        encode({
          iss: "acme-corp",
          sub: "procurement-agent-01",
          jti: "grant_none",
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3_600,
          authority: AUTHORITY,
        }),
        "AA",
      ].join(".");

      const response = await verifyAction(request({ grant: token }), {
        trustedAuthority: true,
        principalKeys: registryOf(["acme-corp", signer]),
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_MALFORMED");
    });

    it("blocks a well-formed JWS minted for something other than delegation", async () => {
      const signer = await createSigner("acme-2026-09");
      const { signCompactJws } = await import("../src/crypto/jws");
      const token = await signCompactJws(
        {
          iss: "acme-corp",
          sub: "procurement-agent-01",
          jti: "grant_wrong_typ",
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3_600,
          authority: AUTHORITY,
        },
        signer.privateKey,
        "vizier-receipt+jws",
      );

      const response = await verifyAction(request({ grant: token }), {
        trustedAuthority: true,
        principalKeys: registryOf(["acme-corp", signer]),
      });

      expect(response.decision).toBe("BLOCK");
      expect(response.reason_codes).toContain("GRANT_MALFORMED");
    });
  });

  describe("principal key registry", () => {
    it("accepts an array of keys so a principal can rotate", async () => {
      const outgoing = await createSigner("acme-2026-06");
      const incoming = await createSigner("acme-2026-09");
      const registry = parsePrincipalKeyRegistry(
        JSON.stringify({ "acme-corp": [outgoing.publicJwk, incoming.publicJwk] }),
      );

      for (const signer of [outgoing, incoming]) {
        const response = await verifyAction(request({ grant: await grantFor(signer) }), {
          trustedAuthority: true,
          principalKeys: registry,
        });
        expect(response.decision).toBe("ALLOW");
      }
    });

    it("refuses a private key registered by mistake", async () => {
      const signer = await createSigner("acme-2026-09");
      expect(() =>
        parsePrincipalKeyRegistry(
          JSON.stringify({ "acme-corp": JSON.parse(signer.privateKey) }),
        ),
      ).toThrow(PrincipalKeyRegistryError);
    });

    it.each([
      ["invalid JSON", "{not json"],
      ["a JSON array", "[]"],
      ["an empty key list", '{"acme-corp":[]}'],
      ["a non-JWK value", '{"acme-corp":"a-key"}'],
    ])("refuses a registry that is %s", (_label, source) => {
      expect(() => parsePrincipalKeyRegistry(source)).toThrow(PrincipalKeyRegistryError);
    });

    it("refuses duplicate key ids for one principal", async () => {
      const first = await createSigner("acme-2026-09");
      const second = await createSigner("acme-2026-09");
      expect(() =>
        parsePrincipalKeyRegistry(
          JSON.stringify({ "acme-corp": [first.publicJwk, second.publicJwk] }),
        ),
      ).toThrow(PrincipalKeyRegistryError);
    });

    it("treats an absent registry as empty rather than failing", () => {
      expect(parsePrincipalKeyRegistry(undefined).size).toBe(0);
      expect(parsePrincipalKeyRegistry("   ").size).toBe(0);
    });
  });

  it("never reports principal_signed provenance for a grant it could not verify", async () => {
    const real = await createSigner("acme-2026-09");
    const impostor = await createSigner("acme-2026-09");
    const registry = registryOf(["acme-corp", real]);

    const hostileGrants = [
      "garbage",
      await grantFor(impostor),
      await grantFor(real, { subject: "another-agent" }),
      await grantFor(real, { issuer: "another-corp" }),
      await grantFor(real, {
        issuedAt: new Date(Date.now() - 7_200_000),
        ttlSeconds: 60,
      }),
    ];

    for (const grant of hostileGrants) {
      const response = await verifyAction(request({ grant }), {
        trustedAuthority: true,
        principalKeys: registry,
      });
      expect(response.decision).toBe("BLOCK");
      expect(response.receipt.authority_provenance).not.toBe("principal_signed");
      expect(response.receipt.grant).toBeUndefined();
    }
  });
});
