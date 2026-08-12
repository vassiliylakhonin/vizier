const TEXT_ENCODER = new TextEncoder();

interface EcPrivateJwk {
  readonly alg: "ES256";
  readonly crv: "P-256";
  readonly d: string;
  readonly kid: string;
  readonly kty: "EC";
  readonly use: "sig";
  readonly x: string;
  readonly y: string;
}

interface EcPublicJwk {
  readonly alg: "ES256";
  readonly crv: "P-256";
  readonly kid: string;
  readonly kty: "EC";
  readonly use: "sig";
  readonly x: string;
  readonly y: string;
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isEcPrivateJwk(value: unknown): value is EcPrivateJwk {
  return (
    isRecord(value) &&
    value.kty === "EC" &&
    value.crv === "P-256" &&
    value.alg === "ES256" &&
    value.use === "sig" &&
    isNonEmptyString(value.kid) &&
    isNonEmptyString(value.x) &&
    isNonEmptyString(value.y) &&
    isNonEmptyString(value.d)
  );
}

function readPrivateJwk(input: string): EcPrivateJwk {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input) as unknown;
  } catch {
    throw new Error("Agent Card signing key must be valid JSON.");
  }
  if (!isEcPrivateJwk(parsed)) {
    throw new Error(
      "Agent Card signing key must be an ES256 EC P-256 private JWK with kid.",
    );
  }
  return parsed;
}

export function canonicalizeJson(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("RFC 8785 forbids non-finite numbers.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
  }
  if (isRecord(value)) {
    const entries = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`,
      );
    return `{${entries.join(",")}}`;
  }
  throw new TypeError(`RFC 8785 cannot serialize ${typeof value}.`);
}

export function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 8_192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8_192));
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function publicJwkFromPrivate(signingKey: string): EcPublicJwk {
  const privateJwk = readPrivateJwk(signingKey);
  return {
    alg: "ES256",
    crv: "P-256",
    kid: privateJwk.kid,
    kty: "EC",
    use: "sig",
    x: privateJwk.x,
    y: privateJwk.y,
  };
}

export function createJwks(signingKey?: string): {
  readonly keys: readonly EcPublicJwk[];
} {
  if (signingKey === undefined || signingKey.length === 0) {
    return { keys: [] };
  }
  return { keys: [publicJwkFromPrivate(signingKey)] };
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
  const privateJwk = readPrivateJwk(signingKey);
  const unsignedCard = { ...card };
  delete unsignedCard.signature;

  const protectedHeader = {
    alg: "ES256",
    b64: false,
    crit: ["b64"],
    jku: jwksUrlFromCard(unsignedCard),
    kid: privateJwk.kid,
  };
  const encodedHeader = base64urlEncode(
    TEXT_ENCODER.encode(JSON.stringify(protectedHeader)),
  );
  const payload = TEXT_ENCODER.encode(canonicalizeJson(unsignedCard));
  const header = TEXT_ENCODER.encode(`${encodedHeader}.`);
  const signingInput = new Uint8Array(header.length + payload.length);
  signingInput.set(header);
  signingInput.set(payload, header.length);

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
    signature: `${encodedHeader}..${base64urlEncode(new Uint8Array(signature))}`,
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
