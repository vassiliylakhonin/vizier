import {
  base64urlEncode,
  canonicalizeJson,
  privateJwkFromString,
  publicJwkFromPrivate,
} from "../crypto/jws";

export {
  base64urlEncode,
  canonicalizeJson,
  createJwks,
  publicJwkFromPrivate,
} from "../crypto/jws";

const TEXT_ENCODER = new TextEncoder();

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function jwksUrlFromCard(card: Readonly<Record<string, unknown>>): string {
  const interfaces = card.supportedInterfaces;
  if (!Array.isArray(interfaces)) {
    throw new Error("Agent Card must declare a supported interface.");
  }
  const interfaceUrl = interfaces.find(
    (entry) => isRecord(entry) && isNonEmptyString(entry.url),
  );
  if (!isRecord(interfaceUrl) || !isNonEmptyString(interfaceUrl.url)) {
    throw new Error("Agent Card must declare a supported interface URL.");
  }
  const url = new URL(interfaceUrl.url);
  if (url.protocol !== "https:") {
    throw new Error("Agent Card interface URL must use HTTPS.");
  }
  return new URL("/.well-known/jwks.json", url).toString();
}

export async function signAgentCard(
  card: Readonly<Record<string, unknown>>,
  signingKey: string,
): Promise<Readonly<Record<string, unknown>>> {
  const privateJwk = privateJwkFromString(signingKey);
  const publicJwk = publicJwkFromPrivate(signingKey);
  const unsignedCard = { ...card };
  delete unsignedCard.signatures;
  // Remove the pre-v1 compatibility field if an older caller supplied it.
  delete unsignedCard.signature;

  const protectedHeader = {
    alg: "ES256",
    jku: jwksUrlFromCard(unsignedCard),
    kid: publicJwk.kid,
    typ: "JOSE",
  };
  const encodedHeader = base64urlEncode(
    TEXT_ENCODER.encode(JSON.stringify(protectedHeader)),
  );
  const encodedPayload = base64urlEncode(
    TEXT_ENCODER.encode(canonicalizeJson(unsignedCard)),
  );
  const signingInput = TEXT_ENCODER.encode(`${encodedHeader}.${encodedPayload}`);

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    cryptoKey,
    signingInput,
  );

  return {
    ...unsignedCard,
    signatures: [
      {
        protected: encodedHeader,
        signature: base64urlEncode(new Uint8Array(signature)),
      },
    ],
  };
}

export async function maybeSignAgentCard(
  card: Readonly<Record<string, unknown>>,
  signingKey?: string,
): Promise<Readonly<Record<string, unknown>>> {
  if (signingKey === undefined || signingKey.length === 0) {
    return card;
  }
  return signAgentCard(card, signingKey);
}
