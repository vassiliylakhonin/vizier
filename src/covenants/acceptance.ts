import { z } from "zod";

import { decodeCompactJws, signCompactJws, verifyJwsSignature } from "../crypto/jws";
import type { PrincipalKeyRegistry } from "../core/grants";
import { identifierSchema } from "../core/schemas";

/**
 * Principal-signed acceptance of one covenant draft.
 *
 * Without this, "the principal accepted the draft" is an assertion by the
 * authenticated integration. With it, the principal signs the exact draft hash
 * with a key registered out of band (`VIZIER_PRINCIPAL_KEYS`, the same registry
 * delegation grants use), and Vizier verifies the signature before activating.
 * A signature proves that the key holder accepted that draft hash. It does not
 * prove the human read the draft: that depends on what the signing client shows.
 */
export const COVENANT_ACCEPTANCE_TYP = "vizier-covenant-acceptance+jws";

export const covenantAcceptancePayloadSchema = z.strictObject({
  iss: identifierSchema,
  draft_hash: z.string().regex(/^[a-f0-9]{64}$/),
  accepted_at: z.iso.datetime({ offset: true }),
});

export type CovenantAcceptancePayload = z.infer<typeof covenantAcceptancePayloadSchema>;

export type AcceptanceFailureCode =
  | "ACCEPTANCE_SIGNATURE_MALFORMED"
  | "ACCEPTANCE_KEY_UNKNOWN"
  | "ACCEPTANCE_SIGNATURE_INVALID"
  | "ACCEPTANCE_SIGNATURE_MISMATCH";

export type AcceptanceVerification =
  | { readonly ok: true; readonly keyId: string }
  | { readonly ok: false; readonly code: AcceptanceFailureCode; readonly message: string };

function fail(code: AcceptanceFailureCode, message: string): AcceptanceVerification {
  return { ok: false, code, message };
}

export async function verifyCovenantAcceptance(input: {
  readonly token: string;
  readonly registry: PrincipalKeyRegistry;
  readonly principalId: string;
  readonly draftHash: string;
  readonly acceptedAt: string;
}): Promise<AcceptanceVerification> {
  const parts = decodeCompactJws(input.token);
  if (parts === null || parts.header.alg !== "ES256" || parts.header.typ !== COVENANT_ACCEPTANCE_TYP) {
    return fail("ACCEPTANCE_SIGNATURE_MALFORMED", "The acceptance signature is not a Vizier covenant acceptance JWS.");
  }
  const kid = parts.header.kid;
  const payload = covenantAcceptancePayloadSchema.safeParse(parts.payload);
  if (typeof kid !== "string" || kid.length === 0 || !payload.success) {
    return fail("ACCEPTANCE_SIGNATURE_MALFORMED", "The acceptance signature claims are malformed.");
  }
  const key = input.registry.get(payload.data.iss)?.find((candidate) => candidate.kid === kid);
  if (key === undefined) {
    return fail("ACCEPTANCE_KEY_UNKNOWN", "No registered principal key matches the acceptance signature.");
  }
  if (!(await verifyJwsSignature(parts, key))) {
    return fail("ACCEPTANCE_SIGNATURE_INVALID", "The acceptance signature does not verify.");
  }
  // Everything below is a verified claim and must match what is being activated.
  if (
    payload.data.iss !== input.principalId ||
    payload.data.draft_hash !== input.draftHash ||
    payload.data.accepted_at !== input.acceptedAt
  ) {
    return fail(
      "ACCEPTANCE_SIGNATURE_MISMATCH",
      "The signed acceptance is for a different principal, draft or acceptance time.",
    );
  }
  return { ok: true, keyId: kid };
}

/** Run on the principal's own machine; the service never sees the private key. */
export async function mintCovenantAcceptance(input: {
  readonly signingKey: string;
  readonly principalId: string;
  readonly draftHash: string;
  readonly acceptedAt?: Date;
}): Promise<{ readonly accepted_at: string; readonly token: string }> {
  const acceptedAt = (input.acceptedAt ?? new Date()).toISOString();
  const payload = covenantAcceptancePayloadSchema.parse({
    iss: input.principalId,
    draft_hash: input.draftHash,
    accepted_at: acceptedAt,
  });
  return {
    accepted_at: acceptedAt,
    token: await signCompactJws(payload, input.signingKey, COVENANT_ACCEPTANCE_TYP),
  };
}
