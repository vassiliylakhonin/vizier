// Mint the principal's half of a Vizier authorization.
//
//   node scripts/mint-grant.mjs keygen --kid acme-2026-09
//   node scripts/mint-grant.mjs sign --key principal.jwk.json --grant grant.json
//
// A delegation grant is what makes a Vizier receipt worth keeping: without one
// the receipt attests that Vizier evaluated an authority the calling
// application asserted, and with one it attests that the principal actually
// delegated that authority to that agent.
//
// `keygen` writes a private JWK the principal keeps and prints the public JWK
// to register as VIZIER_PRINCIPAL_KEYS. The private key never leaves the
// machine that runs this script, and the service never holds it.

import { readFile, writeFile } from "node:fs/promises";
import { argv, exit, stderr, stdout } from "node:process";

const MAX_LIFETIME_SECONDS = 365 * 24 * 60 * 60;
const TYP = "vizier-delegation+jws";

function fail(message) {
  stderr.write(`mint-grant: ${message}\n`);
  exit(1);
}

function flag(name, fallback) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1) {
    return fallback;
  }
  const value = argv[index + 1];
  return value === undefined || value.startsWith("--") ? fallback : value;
}

function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

// RFC 8785. Must match src/crypto/jws.ts, or a grant this script signs will
// verify against a payload the service canonicalises differently.
function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("RFC 8785 forbids non-finite numbers.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`);
    return `{${entries.join(",")}}`;
  }
  throw new TypeError(`RFC 8785 cannot serialize ${typeof value}.`);
}

async function keygen() {
  const kid = flag("kid");
  if (!kid) {
    fail("keygen needs --kid, for example --kid acme-2026-09");
  }
  const out = flag("out", "principal.jwk.json");
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const priv = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const common = { alg: "ES256", crv: "P-256", kid, kty: "EC", use: "sig" };
  const privateJwk = { ...common, d: priv.d, x: priv.x, y: priv.y };
  const publicJwk = { ...common, x: pub.x, y: pub.y };

  await writeFile(out, `${JSON.stringify(privateJwk, null, 2)}\n`, { mode: 0o600 });
  stderr.write(`Private key written to ${out} (mode 600). Keep it off the server.\n`);
  stderr.write("Register the public half as VIZIER_PRINCIPAL_KEYS:\n");
  stdout.write(`${JSON.stringify({ "<principal-id>": publicJwk }, null, 2)}\n`);
}

async function sign() {
  const keyPath = flag("key");
  const grantPath = flag("grant");
  if (!keyPath || !grantPath) {
    fail("sign needs --key <private jwk> and --grant <claims json>");
  }
  const signingKey = JSON.parse(await readFile(keyPath, "utf8"));
  if (signingKey.kty !== "EC" || signingKey.crv !== "P-256" || !signingKey.d) {
    fail("--key must be an EC P-256 private JWK");
  }
  const claims = JSON.parse(await readFile(grantPath, "utf8"));
  for (const field of ["iss", "sub", "authority"]) {
    if (claims[field] === undefined) {
      fail(`--grant is missing "${field}"`);
    }
  }

  const ttl = Number(flag("ttl", claims.ttl_seconds ?? 3600));
  if (!Number.isInteger(ttl) || ttl <= 0 || ttl > MAX_LIFETIME_SECONDS) {
    fail(`--ttl must be a whole number of seconds between 1 and ${MAX_LIFETIME_SECONDS}`);
  }
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = {
    iss: claims.iss,
    sub: claims.sub,
    jti: claims.jti ?? `grant_${crypto.randomUUID()}`,
    iat: issuedAt,
    exp: issuedAt + ttl,
    authority: claims.authority,
    ...(claims.aud === undefined ? {} : { aud: claims.aud }),
  };

  const header = { alg: "ES256", kid: signingKey.kid, typ: TYP };
  const signingInput = `${base64url(new TextEncoder().encode(JSON.stringify(header)))}.${base64url(
    new TextEncoder().encode(canonicalize(payload)),
  )}`;
  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    signingKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    cryptoKey,
    new TextEncoder().encode(signingInput),
  );

  stderr.write(
    `Grant ${payload.jti} for agent ${payload.sub}, valid until ${new Date(
      payload.exp * 1000,
    ).toISOString()}.\n`,
  );
  stdout.write(`${signingInput}.${base64url(new Uint8Array(signature))}\n`);
}

const command = argv[2];
if (command === "keygen") {
  await keygen();
} else if (command === "sign") {
  await sign();
} else {
  stderr.write(
    "usage:\n" +
      "  node scripts/mint-grant.mjs keygen --kid <key-id> [--out principal.jwk.json]\n" +
      "  node scripts/mint-grant.mjs sign --key <private jwk> --grant <claims json> [--ttl 3600]\n",
  );
  exit(command === undefined ? 1 : 1);
}
