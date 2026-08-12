export type EnforcementAuthorization =
  | "authenticated"
  | "evaluation"
  | "denied";

export interface AuthorizationOptions {
  readonly allowMissingCredentialForEvaluation?: boolean;
}

function bearerToken(request: Request): string | null {
  const value = request.headers.get("Authorization");
  if (value === null || !value.startsWith("Bearer ")) {
    return null;
  }
  const token = value.slice("Bearer ".length);
  return token.length > 0 ? token : null;
}

async function digest(value: string): Promise<Uint8Array> {
  const bytes = new TextEncoder().encode(value);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function supportsTimingSafeEqual(
  subtle: SubtleCrypto,
): subtle is SubtleCrypto & {
  timingSafeEqual(
    left: ArrayBuffer | ArrayBufferView,
    right: ArrayBuffer | ArrayBufferView,
  ): boolean;
} {
  return "timingSafeEqual" in subtle;
}

async function secretsEqual(left: string, right: string): Promise<boolean> {
  const [leftDigest, rightDigest] = await Promise.all([digest(left), digest(right)]);
  if (supportsTimingSafeEqual(crypto.subtle)) {
    return crypto.subtle.timingSafeEqual(leftDigest, rightDigest);
  }
  let difference = 0;
  for (let index = 0; index < leftDigest.length; index += 1) {
    difference |= leftDigest[index]! ^ rightDigest[index]!;
  }
  return difference === 0;
}

export async function authorizeEnforcement(
  request: Request,
  apiKey: string | undefined,
  options: AuthorizationOptions = {},
): Promise<EnforcementAuthorization> {
  if (apiKey === undefined || apiKey.length === 0) {
    return "evaluation";
  }
  const hasAuthorizationHeader = request.headers.has("Authorization");
  const token = bearerToken(request);
  if (token === null) {
    return options.allowMissingCredentialForEvaluation === true &&
      !hasAuthorizationHeader
      ? "evaluation"
      : "denied";
  }
  return (await secretsEqual(token, apiKey)) ? "authenticated" : "denied";
}
