const TEXT_ENCODER = new TextEncoder();

export interface EcPrivateJwk {
  readonly alg: "ES256";
  readonly crv: "P-256";
  readonly d: string;
  readonly kid: string;
  readonly kty: "EC";
  readonly use: "sig";
  readonly x: string;
  readonly y: string;
}

export interface EcPublicJwk {
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

export function privateJwkFromString(input: string): EcPrivateJwk {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input) as unknown;
  } catch {
    throw new Error("Signing key must be valid JSON.");
  }
  if (!isEcPrivateJwk(parsed)) {
    throw new Error(
      "Signing key must be an ES256 EC P-256 private JWK with kid.",
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
      .map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`);
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

function base64urlDecode(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error("Invalid base64url value.");
  }
  const standard = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = standard.padEnd(Math.ceil(standard.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function publicJwkFromPrivate(signingKey: string): EcPublicJwk {
  const privateJwk = privateJwkFromString(signingKey);
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

export function createJwks(
  ...signingKeys: readonly (string | undefined)[]
): { readonly keys: readonly EcPublicJwk[] } {
  const keys = signingKeys
    .filter((value): value is string => value !== undefined && value.length > 0)
    .map((value) => publicJwkFromPrivate(value));
  if (new Set(keys.map((key) => key.kid)).size !== keys.length) {
    throw new Error("Signing keys must have distinct kid values.");
  }
  return { keys: Object.freeze(keys) };
}

export async function signCompactJws(
  payload: Readonly<Record<string, unknown>>,
  signingKey: string,
  type: string,
): Promise<string> {
  const privateJwk = privateJwkFromString(signingKey);
  const protectedHeader = {
    alg: "ES256",
    kid: privateJwk.kid,
    typ: type,
  };
  const encodedHeader = base64urlEncode(
    TEXT_ENCODER.encode(JSON.stringify(protectedHeader)),
  );
  const encodedPayload = base64urlEncode(
    TEXT_ENCODER.encode(canonicalizeJson(payload)),
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
  return `${encodedHeader}.${encodedPayload}.${base64urlEncode(new Uint8Array(signature))}`;
}

export async function verifyCompactJws(
  token: string,
  payload: Readonly<Record<string, unknown>>,
  signingKey: string,
  expectedType: string,
): Promise<boolean> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return false;
    }
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    if (
      encodedHeader === undefined ||
      encodedPayload === undefined ||
      encodedSignature === undefined
    ) {
      return false;
    }
    const header = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
        base64urlDecode(encodedHeader),
      ),
    ) as unknown;
    const publicJwk = publicJwkFromPrivate(signingKey);
    if (
      !isRecord(header) ||
      header.alg !== "ES256" ||
      header.kid !== publicJwk.kid ||
      header.typ !== expectedType
    ) {
      return false;
    }
    const expectedPayload = base64urlEncode(
      TEXT_ENCODER.encode(canonicalizeJson(payload)),
    );
    if (encodedPayload !== expectedPayload) {
      return false;
    }
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      publicJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      cryptoKey,
      base64urlDecode(encodedSignature),
      TEXT_ENCODER.encode(`${encodedHeader}.${encodedPayload}`),
    );
  } catch {
    return false;
  }
}
