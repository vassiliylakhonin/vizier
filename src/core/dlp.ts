import type { VerificationRequest } from "./schemas";

export type DlpCategory =
  | "api_key"
  | "private_key"
  | "jwt"
  | "payment_card"
  | "ssn"
  | "high_entropy";

export interface DlpFinding {
  readonly category: DlpCategory;
  readonly detector: string;
  readonly path: string;
  readonly snippet_masked: string;
}

export interface DlpEvaluationResult {
  readonly clean: boolean;
  readonly findings: readonly DlpFinding[];
  readonly total_leaks_prevented: number;
}

export interface DlpOptions {
  readonly enabled?: boolean;
  readonly allowedCategories?: readonly string[];
}

/**
 * Masks a secret string to preserve privacy while providing audit visibility.
 * e.g. "sk-proj-1234567890abcdef1234" -> "sk-p******1234"
 */
export function maskSecret(secret: string): string {
  const trimmed = secret.trim();
  if (trimmed.length <= 8) {
    return "******";
  }
  const prefix = trimmed.slice(0, 4);
  const suffix = trimmed.slice(-4);
  return `${prefix}******${suffix}`;
}

/**
 * Calculates Shannon entropy of a string in bits per character.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Validates a credit card number using the standard Luhn algorithm (Mod 10).
 */
export function isValidLuhn(cardNumber: string): boolean {
  const digits = cardNumber.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

interface DetectorPattern {
  readonly name: string;
  readonly category: DlpCategory;
  readonly regex: RegExp;
  readonly validator?: (match: string) => boolean;
}

const DETECTORS: readonly DetectorPattern[] = [
  // Private Keys
  {
    name: "private_key_pem",
    category: "private_key",
    regex: /-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----/g,
  },
  // OpenAI API Keys
  {
    name: "openai_api_key",
    category: "api_key",
    regex: /\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b/g,
  },
  // Anthropic API Keys
  {
    name: "anthropic_api_key",
    category: "api_key",
    regex: /\b(?:sk-ant-[A-Za-z0-9_-]{32,})\b/g,
  },
  // AWS Access Key ID
  {
    name: "aws_access_key",
    category: "api_key",
    regex: /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
  },
  // GitHub Personal Access Tokens
  {
    name: "github_token",
    category: "api_key",
    regex: /\b(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b/g,
  },
  // Stripe API Keys
  {
    name: "stripe_api_key",
    category: "api_key",
    regex: /\b(?:sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})\b/g,
  },
  // Slack Tokens
  {
    name: "slack_token",
    category: "api_key",
    regex: /\b(?:xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}|xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,})\b/g,
  },
  // Google Cloud API Keys
  {
    name: "google_api_key",
    category: "api_key",
    regex: /\b(?:AIza[0-9A-Za-z\-_]{35})\b/g,
  },
  // JWT Tokens (Header.Payload.Signature)
  {
    name: "jwt_token",
    category: "jwt",
    regex: /\b(?:eyJ[A-Za-z0-9-_=]{10,}\.eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_.+/=]{10,})\b/g,
  },
  // US Social Security Number (SSN)
  {
    name: "us_ssn",
    category: "ssn",
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  // Payment Cards (with Luhn Validation)
  {
    name: "payment_card_luhn",
    category: "payment_card",
    regex: /\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{13,19}\b/g,
    validator: isValidLuhn,
  },
];

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HASH_REGEX = /^[0-9a-f]{64}$/i;

/**
 * Scans a single string for DLP violations.
 */
export function scanDlpText(
  text: string,
  path: string = "text",
  allowedCategories: ReadonlySet<string> = new Set(),
): DlpFinding[] {
  if (!text || typeof text !== "string") return [];
  const findings: DlpFinding[] = [];
  const visitedSnippets = new Set<string>();

  // 1. Run pattern & algorithmic detectors
  for (const detector of DETECTORS) {
    if (allowedCategories.has(detector.category)) continue;

    // Reset regex state
    detector.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = detector.regex.exec(text)) !== null) {
      const rawMatch = match[0];
      if (detector.validator && !detector.validator(rawMatch)) {
        continue;
      }
      if (!visitedSnippets.has(rawMatch)) {
        visitedSnippets.add(rawMatch);
        findings.push({
          category: detector.category,
          detector: detector.name,
          path,
          snippet_masked: maskSecret(rawMatch),
        });
      }
    }
  }

  // 2. Run Shannon entropy anomaly detector on continuous tokens
  if (!allowedCategories.has("high_entropy")) {
    const tokens = text.split(/[\s,;:'"()[\]{}<>]+/);
    for (const token of tokens) {
      const trimmed = token.trim();
      // Only evaluate standalone strings >= 24 chars that aren't UUIDs or standard SHA256 hashes
      if (
        trimmed.length >= 24 &&
        trimmed.length <= 128 &&
        !UUID_REGEX.test(trimmed) &&
        !HASH_REGEX.test(trimmed) &&
        !visitedSnippets.has(trimmed) &&
        !trimmed.startsWith("http://") &&
        !trimmed.startsWith("https://")
      ) {
        const entropy = calculateShannonEntropy(trimmed);
        // Base64/Hex high entropy threshold: > 4.6 bits/char
        if (entropy >= 4.6) {
          visitedSnippets.add(trimmed);
          findings.push({
            category: "high_entropy",
            detector: "shannon_entropy_anomaly",
            path,
            snippet_masked: maskSecret(trimmed),
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Recursively scans an object/parameters map for DLP violations.
 */
export function scanDlpParameters(
  parameters: Record<string, unknown>,
  allowedCategories: ReadonlySet<string> = new Set(),
  basePath: string = "action.parameters",
): DlpFinding[] {
  const findings: DlpFinding[] = [];
  function walk(val: unknown, currentPath: string) {
    if (typeof val === "string") {
      findings.push(...scanDlpText(val, currentPath, allowedCategories));
    } else if (Array.isArray(val)) {
      for (let i = 0; i < val.length; i++) {
        walk(val[i], `${currentPath}[${i}]`);
      }
    } else if (typeof val === "object" && val !== null) {
      for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
        walk(v, `${currentPath}.${k}`);
      }
    }
  }
  walk(parameters, basePath);
  return findings;
}

/**
 * Recursively scans all fields and parameters in a VerificationRequest for DLP violations.
 */
export function evaluateDlp(
  request: VerificationRequest,
  options: DlpOptions = {},
): DlpEvaluationResult {
  const isEnabled =
    options.enabled ??
    (request.authority.constraints.dlp_screening !== false);

  if (!isEnabled) {
    return {
      clean: true,
      findings: [],
      total_leaks_prevented: 0,
    };
  }

  const allowedCategories = new Set(
    (options.allowedCategories ??
      request.authority.constraints.allowed_dlp_categories ??
      []).map((c) => c.toLowerCase())
  );

  const findings: DlpFinding[] = [];

  // 1. Scan target
  if (typeof request.action.target === "string") {
    findings.push(...scanDlpText(request.action.target, "action.target", allowedCategories));
  }

  // 2. Scan parameters recursively
  findings.push(...scanDlpParameters(request.action.parameters, allowedCategories, "action.parameters"));

  return {
    clean: findings.length === 0,
    findings: Object.freeze(findings),
    total_leaks_prevented: findings.length,
  };
}
