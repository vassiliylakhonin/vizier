import { z } from "zod";

import {
  decodeCompactJws,
  isEcPublicJwk,
  signCompactJws,
  verifyJwsSignature,
  type EcPublicJwk,
} from "../crypto/jws";
import { JsonComplexityError, assertJsonComplexity } from "./json-complexity";
import { canonicalize } from "./receipts";
import {
  MAX_GRANT_TOKEN_CHARS,
  authoritySchema,
  identifierSchema,
} from "./schemas";

/**
 * A delegation grant is a compact JWS signed by the principal — not by Vizier.
 *
 * Without one, the authority in a verification request is whatever the calling
 * application says it is, and the receipt attests only that Vizier evaluated
 * that claim. With one, the receipt attests that the named principal actually
 * delegated that authority to that agent, and Vizier checked the signature
 * against a key registered for the principal out of band.
 */
export const DELEGATION_GRANT_TYP = "vizier-delegation+jws";

/** Grants must expire. A grant that outlives this is refused outright. */
export const MAX_GRANT_LIFETIME_SECONDS = 365 * 24 * 60 * 60;

/** Tolerance for clock drift between the principal's signer and this service. */
export const CLOCK_SKEW_SECONDS = 60;

const numericDateSchema = z.number().int().nonnegative().max(4_102_444_800);

export const delegationGrantPayloadSchema = z.strictObject({
  iss: identifierSchema,
  sub: identifierSchema,
  aud: identifierSchema.optional(),
  jti: identifierSchema,
  iat: numericDateSchema,
  nbf: numericDateSchema.optional(),
  exp: numericDateSchema,
  authority: authoritySchema,
});

export type DelegationGrantPayload = z.infer<typeof delegationGrantPayloadSchema>;

export type GrantFailureCode =
  | "GRANT_MALFORMED"
  | "GRANT_PRINCIPAL_UNKNOWN"
  | "GRANT_KEY_UNKNOWN"
  | "GRANT_SIGNATURE_INVALID"
  | "GRANT_NOT_YET_VALID"
  | "GRANT_EXPIRED"
  | "GRANT_LIFETIME_EXCESSIVE"
  | "GRANT_ISSUER_MISMATCH"
  | "GRANT_SUBJECT_MISMATCH"
  | "GRANT_AUDIENCE_MISMATCH"
  | "GRANT_AUTHORITY_MISMATCH";

export interface VerifiedGrant {
  readonly jti: string;
  readonly issuer: string;
  readonly subject: string;
  readonly key_id: string;
  readonly issued_at: string;
  readonly expires_at: string;
}

export type GrantVerification =
  | { readonly ok: true; readonly grant: VerifiedGrant }
  | {
      readonly ok: false;
      readonly code: GrantFailureCode;
      readonly details: Readonly<Record<string, unknown>>;
    };

/** Public keys Vizier will accept delegation grants from, keyed by principal. */
export type PrincipalKeyRegistry = ReadonlyMap<string, readonly EcPublicJwk[]>;

export class PrincipalKeyRegistryError extends Error {}

/**
 * Parse the registered principal keys.
 *
 * Trust in a principal's key is established out of band, by an operator
 * registering it — never by fetching it at decision time. The authorization
 * kernel makes no outbound request, so a decision cannot be changed, delayed,
 * or observed by anyone who controls a network path.
 */
export function parsePrincipalKeyRegistry(
  source: string | undefined,
): PrincipalKeyRegistry {
  if (source === undefined || source.trim().length === 0) {
    return new Map();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(source) as unknown;
  } catch {
    throw new PrincipalKeyRegistryError(
      "Principal key registry must be valid JSON.",
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new PrincipalKeyRegistryError(
      "Principal key registry must be a JSON object keyed by principal id.",
    );
  }

  const registry = new Map<string, readonly EcPublicJwk[]>();
  for (const [principalId, value] of Object.entries(parsed)) {
    if (identifierSchema.safeParse(principalId).success === false) {
      throw new PrincipalKeyRegistryError(
        "Principal key registry contains an invalid principal id.",
      );
    }
    const candidates = Array.isArray(value) ? value : [value];
    if (candidates.length === 0) {
      throw new PrincipalKeyRegistryError(
        `Principal "${principalId}" has no registered key.`,
      );
    }
    const keys: EcPublicJwk[] = [];
    for (const candidate of candidates) {
      if (!isEcPublicJwk(candidate)) {
        throw new PrincipalKeyRegistryError(
          `Principal "${principalId}" has a key that is not an ES256 EC P-256 public JWK with kid.`,
        );
      }
      keys.push(candidate);
    }
    if (new Set(keys.map((key) => key.kid)).size !== keys.length) {
      throw new PrincipalKeyRegistryError(
        `Principal "${principalId}" has duplicate key ids.`,
      );
    }
    registry.set(principalId, Object.freeze(keys));
  }
  return registry;
}

export interface GrantVerificationInput {
  readonly token: string;
  readonly registry: PrincipalKeyRegistry;
  /** Must equal the request's `principal.id`. */
  readonly principalId: string | null;
  /** Must equal the request's `agent.id`. */
  readonly agentId: string;
  /** Must equal the request's `authority` block, byte for byte once canonical. */
  readonly authority: unknown;
  readonly audience?: string;
  readonly now?: Date;
}

function failure(
  code: GrantFailureCode,
  details: Readonly<Record<string, unknown>> = {},
): GrantVerification {
  return Object.freeze({ ok: false as const, code, details: Object.freeze(details) });
}

/**
 * Verify a delegation grant and bind it to the action being authorized.
 *
 * The order is deliberate: the signature is checked before any claim inside the
 * grant is compared with anything. Claims read before that point are used only
 * to find the key that will verify them.
 */
export async function verifyDelegationGrant(
  input: GrantVerificationInput,
): Promise<GrantVerification> {
  if (input.token.length > MAX_GRANT_TOKEN_CHARS) {
    return failure("GRANT_MALFORMED", { reason: "token_too_long" });
  }

  const parts = decodeCompactJws(input.token);
  if (parts === null) {
    return failure("GRANT_MALFORMED", { reason: "not_a_compact_jws" });
  }

  // The decoded payload has not passed through the request body's complexity
  // check — it arrived as an opaque string — so bound it before touching it.
  try {
    assertJsonComplexity(parts.payload);
  } catch (error) {
    if (error instanceof JsonComplexityError) {
      return failure("GRANT_MALFORMED", { reason: "payload_too_complex" });
    }
    throw error;
  }

  const { alg, kid, typ } = parts.header;
  if (alg !== "ES256" || typ !== DELEGATION_GRANT_TYP) {
    return failure("GRANT_MALFORMED", { reason: "unsupported_header" });
  }
  if (typeof kid !== "string" || kid.length === 0) {
    return failure("GRANT_MALFORMED", { reason: "missing_kid" });
  }

  const payload = delegationGrantPayloadSchema.safeParse(parts.payload);
  if (!payload.success) {
    return failure("GRANT_MALFORMED", { reason: "payload_schema" });
  }
  const claims = payload.data;

  const registeredKeys = input.registry.get(claims.iss);
  if (registeredKeys === undefined) {
    return failure("GRANT_PRINCIPAL_UNKNOWN", { issuer: claims.iss });
  }
  const key = registeredKeys.find((candidate) => candidate.kid === kid);
  if (key === undefined) {
    return failure("GRANT_KEY_UNKNOWN", { issuer: claims.iss, key_id: kid });
  }

  if (!(await verifyJwsSignature(parts, key))) {
    return failure("GRANT_SIGNATURE_INVALID", { issuer: claims.iss, key_id: kid });
  }

  // Everything below this line is a verified claim.
  const nowSeconds = Math.floor((input.now ?? new Date()).getTime() / 1000);

  if (claims.exp <= claims.iat) {
    return failure("GRANT_MALFORMED", { reason: "expiry_not_after_issuance" });
  }
  if (claims.exp - claims.iat > MAX_GRANT_LIFETIME_SECONDS) {
    return failure("GRANT_LIFETIME_EXCESSIVE", {
      lifetime_seconds: claims.exp - claims.iat,
      max_lifetime_seconds: MAX_GRANT_LIFETIME_SECONDS,
    });
  }
  const notBefore = claims.nbf ?? claims.iat;
  if (nowSeconds + CLOCK_SKEW_SECONDS < notBefore) {
    return failure("GRANT_NOT_YET_VALID", { not_before: notBefore });
  }
  if (nowSeconds - CLOCK_SKEW_SECONDS >= claims.exp) {
    return failure("GRANT_EXPIRED", { expires_at: claims.exp });
  }

  if (input.audience !== undefined && claims.aud !== undefined && claims.aud !== input.audience) {
    return failure("GRANT_AUDIENCE_MISMATCH", { audience: claims.aud });
  }
  if (input.principalId === null || claims.iss !== input.principalId) {
    return failure("GRANT_ISSUER_MISMATCH", {
      grant_issuer: claims.iss,
      request_principal: input.principalId,
    });
  }
  if (claims.sub !== input.agentId) {
    return failure("GRANT_SUBJECT_MISMATCH", {
      grant_subject: claims.sub,
      request_agent: input.agentId,
    });
  }

  // The whole point: the authority Vizier evaluates must be the authority the
  // principal signed, not a widened copy travelling beside it.
  let requestAuthority: string;
  try {
    requestAuthority = canonicalize(input.authority);
  } catch {
    return failure("GRANT_AUTHORITY_MISMATCH", { reason: "request_authority_uncanonicalizable" });
  }
  if (canonicalize(claims.authority) !== requestAuthority) {
    return failure("GRANT_AUTHORITY_MISMATCH", { reason: "authority_differs_from_grant" });
  }

  return Object.freeze({
    ok: true as const,
    grant: Object.freeze({
      jti: claims.jti,
      issuer: claims.iss,
      subject: claims.sub,
      key_id: kid,
      issued_at: new Date(claims.iat * 1000).toISOString(),
      expires_at: new Date(claims.exp * 1000).toISOString(),
    }),
  });
}

// --- Minting -----------------------------------------------------------------
//
// Kept beside verification so the two cannot drift. Nothing here runs in the
// Worker request path: a grant is minted by the principal, on the principal's
// own machine, with a key this service never sees the private half of.

export interface MintDelegationGrantInput {
  /** The principal's ES256 private JWK, serialised. Never leaves the signer. */
  readonly signingKey: string;
  /** Principal id — must match `principal.id` in the requests it authorises. */
  readonly issuer: string;
  /** Agent id — must match `agent.id` in those requests. */
  readonly subject: string;
  /** The exact authority being delegated. */
  readonly authority: z.infer<typeof authoritySchema>;
  readonly ttlSeconds: number;
  readonly audience?: string;
  readonly jti?: string;
  readonly issuedAt?: Date;
  readonly notBefore?: Date;
}

export async function mintDelegationGrant(
  input: MintDelegationGrantInput,
): Promise<string> {
  if (!Number.isInteger(input.ttlSeconds) || input.ttlSeconds <= 0) {
    throw new Error("Grant ttlSeconds must be a positive whole number.");
  }
  if (input.ttlSeconds > MAX_GRANT_LIFETIME_SECONDS) {
    throw new Error(
      `Grant ttlSeconds must not exceed ${String(MAX_GRANT_LIFETIME_SECONDS)}.`,
    );
  }
  const issuedAt = Math.floor((input.issuedAt ?? new Date()).getTime() / 1000);
  const payload = {
    iss: input.issuer,
    sub: input.subject,
    jti: input.jti ?? `grant_${crypto.randomUUID()}`,
    iat: issuedAt,
    exp: issuedAt + input.ttlSeconds,
    authority: input.authority,
    ...(input.audience === undefined ? {} : { aud: input.audience }),
    ...(input.notBefore === undefined
      ? {}
      : { nbf: Math.floor(input.notBefore.getTime() / 1000) }),
  };
  const validated = delegationGrantPayloadSchema.safeParse(payload);
  if (!validated.success) {
    throw new Error("Grant claims failed schema validation before signing.");
  }
  return signCompactJws(validated.data, input.signingKey, DELEGATION_GRANT_TYP);
}
