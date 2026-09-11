import type { KVNamespace } from "@cloudflare/workers-types";
import type { VerificationRequest } from "./schemas";
import type {
  EntityOwnershipGraph,
  Sanctions50EvaluationResult,
  Shareholder,
} from "./sanctions-50-rule";
import { evaluateSanctions50Rule } from "./sanctions-50-rule";

export interface SanctionsMatch {
  readonly matched_value: string;
  readonly candidate_type: "domain" | "crypto_address" | "entity_name" | "iban" | "target";
  readonly list: string;
  readonly entity_name: string;
  readonly source: "built_in" | "kv" | "constraint";
  readonly details?: Readonly<Record<string, unknown>>;
}

export interface SanctionsEvaluationResult {
  readonly clean: boolean;
  readonly match?: SanctionsMatch;
  readonly rule50_result?: Sanctions50EvaluationResult;
}

export interface CandidateEntity {
  readonly value: string;
  readonly type: "domain" | "crypto_address" | "entity_name" | "iban" | "target";
  readonly raw: string;
}

export function normalizeDomain(value: string): string {
  let cleaned = value.trim().toLowerCase();
  // Strip protocol
  cleaned = cleaned.replace(/^[a-z]+:\/\//i, "");
  // Strip path and query
  cleaned = cleaned.split("/")[0] ?? cleaned;
  // Strip port
  cleaned = cleaned.split(":")[0] ?? cleaned;
  // Strip leading www.
  if (cleaned.startsWith("www.")) {
    cleaned = cleaned.slice(4);
  }
  // Strip trailing dot
  return cleaned.replace(/\.+$/, "");
}

export function normalizeCryptoAddress(value: string): string {
  return value.trim().toLowerCase();
}

export function normalizeIban(value: string): string {
  return value.trim().toUpperCase().replace(/[\s.-]/g, "");
}

const COMMON_CORP_SUFFIXES = new Set([
  "llc", "inc", "ltd", "corp", "corporation", "limited", "company", "co",
  "gmbh", "ag", "sa", "sarl", "bv", "nv", "pjsc", "jsc", "ooo", "zao"
]);

export function normalizeEntityName(value: string): string {
  const cleaned = value
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, " ")
    .replace(/\s+/g, " ");

  const words = cleaned.split(" ").filter(Boolean);
  while (words.length > 1 && COMMON_CORP_SUFFIXES.has(words[words.length - 1]!)) {
    words.pop();
  }
  return words.join(" ");
}

const CRYPTO_REGEX = /^(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,65}|T[A-Za-z1-9]{33})$/;
const IBAN_REGEX = /^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/;
const DOMAIN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

export interface SanctionsRecord {
  readonly entity_name: string;
  readonly list: string;
  readonly category: "crypto_address" | "domain" | "entity_name" | "iban";
  readonly details?: Record<string, unknown>;
}

export const BUILT_IN_SANCTIONS: ReadonlyMap<string, SanctionsRecord> = new Map([
  // OFAC SDN Tagged Crypto Addresses (Tornado Cash, Lazarus, Garantex, SUEX)
  ["0xd90e2f925da726b50c4ed8d0fb90ad053324f31b", { entity_name: "Tornado Cash (Router)", list: "OFAC_SDN", category: "crypto_address" }],
  ["0x8589427373d6d84e98730d7795d8f6f8731fda16", { entity_name: "Tornado Cash (0.1 ETH)", list: "OFAC_SDN", category: "crypto_address" }],
  ["0x722122df12d4e14e13ac3b6895a86e84145b6967", { entity_name: "Tornado Cash (1 ETH)", list: "OFAC_SDN", category: "crypto_address" }],
  ["0x098b716b8aaf21512996dc57eb0615e2383e2f96", { entity_name: "Lazarus Group (Ronin Exploiter)", list: "OFAC_SDN", category: "crypto_address" }],
  ["0xa0e1c89ef1a489c9c7de96311ed5ce5d32c20e4b", { entity_name: "Lazarus Group", list: "OFAC_SDN", category: "crypto_address" }],
  ["0x2f389ce8bd80164436100f8071e0d0579df27f09", { entity_name: "SUEX OTC", list: "OFAC_SDN", category: "crypto_address" }],
  ["12xq9fdpcwhk3a2in2oxfv7qv57uj2v59r", { entity_name: "SUEX OTC (BTC)", list: "OFAC_SDN", category: "crypto_address" }],

  // High-Risk Sanctioned / Fraud Domains
  ["tornadocash.eth", { entity_name: "Tornado Cash", list: "OFAC_SDN", category: "domain" }],
  ["tornadocash.io", { entity_name: "Tornado Cash", list: "OFAC_SDN", category: "domain" }],
  ["suex.io", { entity_name: "SUEX OTC", list: "OFAC_SDN", category: "domain" }],
  ["garantex.org", { entity_name: "Garantex Exchange", list: "OFAC_SDN", category: "domain" }],
  ["garantex.io", { entity_name: "Garantex Exchange", list: "OFAC_SDN", category: "domain" }],
  ["hydramarket.onion", { entity_name: "Hydra Market", list: "OFAC_SDN", category: "domain" }],

  // High-Risk Sanctioned Entity Names (Canonical Lowercase)
  ["tornado cash", { entity_name: "Tornado Cash", list: "OFAC_SDN", category: "entity_name" }],
  ["suex otc", { entity_name: "SUEX OTC", list: "OFAC_SDN", category: "entity_name" }],
  ["garantex europe", { entity_name: "Garantex Europe Technology OU", list: "OFAC_SDN", category: "entity_name" }],
  ["garantex", { entity_name: "Garantex Europe", list: "OFAC_SDN", category: "entity_name" }],
  ["hydra market", { entity_name: "Hydra Market", list: "OFAC_SDN", category: "entity_name" }],
  ["chatex", { entity_name: "Chatex", list: "OFAC_SDN", category: "entity_name" }],
  ["lazarus group", { entity_name: "Lazarus Group", list: "OFAC_SDN", category: "entity_name" }],
  ["wagner group", { entity_name: "Wagner Group", list: "EU_SANCTIONS", category: "entity_name" }],

  // High-Risk Maritime & Dark-Fleet Blocked Entities (OFAC SDN / EU / UK)
  ["national iranian tanker company", { entity_name: "National Iranian Tanker Company (NITC)", list: "OFAC_SDN", category: "entity_name" }],
  ["nitc", { entity_name: "National Iranian Tanker Company (NITC)", list: "OFAC_SDN", category: "entity_name" }],
  ["islamic republic of iran shipping lines", { entity_name: "Islamic Republic of Iran Shipping Lines (IRISL)", list: "OFAC_SDN", category: "entity_name" }],
  ["irisl", { entity_name: "Islamic Republic of Iran Shipping Lines (IRISL)", list: "OFAC_SDN", category: "entity_name" }],
  ["sovcomflot", { entity_name: "PAO Sovcomflot", list: "OFAC_SDN", category: "entity_name" }],
  ["scf", { entity_name: "PAO Sovcomflot", list: "OFAC_SDN", category: "entity_name" }],
]);

export function extractSanctionsCandidates(request: VerificationRequest): CandidateEntity[] {
  const candidates: CandidateEntity[] = [];
  const visited = new Set<string>();

  function addCandidate(rawVal: unknown, hintType?: CandidateEntity["type"]) {
    if (typeof rawVal !== "string" || rawVal.trim().length === 0) return;
    const trimmed = rawVal.trim();
    if (visited.has(trimmed)) return;
    visited.add(trimmed);

    // Auto-detect type
    if (CRYPTO_REGEX.test(trimmed) || hintType === "crypto_address") {
      candidates.push({ value: normalizeCryptoAddress(trimmed), type: "crypto_address", raw: trimmed });
    } else if (IBAN_REGEX.test(normalizeIban(trimmed)) || hintType === "iban") {
      candidates.push({ value: normalizeIban(trimmed), type: "iban", raw: trimmed });
    } else if (DOMAIN_REGEX.test(normalizeDomain(trimmed)) || hintType === "domain") {
      candidates.push({ value: normalizeDomain(trimmed), type: "domain", raw: trimmed });
    } else {
      candidates.push({ value: normalizeEntityName(trimmed), type: "entity_name", raw: trimmed });
    }
  }

  // 1. Target
  addCandidate(request.action.target, "target");

  // 2. Search parameters for counterparty indicators
  const params = request.action.parameters;
  const isCandidateKey = (k: string) => {
    const lk = k.toLowerCase();
    return (
      lk.includes("counterparty") ||
      lk.includes("vendor") ||
      lk.includes("recipient") ||
      lk.includes("payee") ||
      lk.includes("company") ||
      lk.includes("supplier") ||
      lk.includes("wallet") ||
      lk.includes("crypto") ||
      lk.includes("address") ||
      lk.includes("iban") ||
      lk.includes("account") ||
      lk.includes("domain") ||
      lk.includes("url") ||
      lk.includes("beneficiary") ||
      lk.includes("target") ||
      lk.includes("to")
    );
  };

  const inspectValue = (val: unknown, keyName?: string) => {
    if (typeof val === "string") {
      const trimmed = val.trim();
      if (
        (keyName && isCandidateKey(keyName)) ||
        CRYPTO_REGEX.test(trimmed) ||
        DOMAIN_REGEX.test(normalizeDomain(trimmed)) ||
        IBAN_REGEX.test(normalizeIban(trimmed))
      ) {
        addCandidate(trimmed);
      }
    } else if (Array.isArray(val)) {
      for (const item of val) {
        inspectValue(item, keyName);
      }
    } else if (typeof val === "object" && val !== null) {
      for (const [subKey, subVal] of Object.entries(val as Record<string, unknown>)) {
        inspectValue(subVal, subKey);
      }
    }
  };

  for (const [key, val] of Object.entries(params)) {
    inspectValue(val, key);
  }

  return candidates;
}

export async function evaluateSanctions(
  request: VerificationRequest,
  kv?: KVNamespace,
): Promise<SanctionsEvaluationResult> {
  const candidates = extractSanctionsCandidates(request);
  const customBlocked = new Set(
    (request.authority.constraints.blocked_entities ?? []).map((item) => item.trim().toLowerCase())
  );

  for (const candidate of candidates) {
    // Check Tier 3: Custom blocked entities in constraints
    if (
      customBlocked.has(candidate.value) ||
      customBlocked.has(candidate.raw.toLowerCase())
    ) {
      return {
        clean: false,
        match: {
          matched_value: candidate.raw,
          candidate_type: candidate.type,
          list: "CUSTOM_CONSTRAINT_BLOCKED",
          entity_name: candidate.raw,
          source: "constraint",
        },
      };
    }

    // Check Tier 1: Built-in High-Risk & OFAC SDN registry
    const builtIn = BUILT_IN_SANCTIONS.get(candidate.value);
    if (builtIn !== undefined) {
      return {
        clean: false,
        match: {
          matched_value: candidate.raw,
          candidate_type: candidate.type,
          list: builtIn.list,
          entity_name: builtIn.entity_name,
          source: "built_in",
          details: builtIn.details,
        },
      };
    }

    // Check Tier 2: Cloudflare KV dynamic denylist
    if (kv !== undefined) {
      try {
        const kvKey = `sanctions:${candidate.type}:${candidate.value}`;
        const rawKv = await kv.get(kvKey);
        if (rawKv !== null) {
          const parsed = JSON.parse(rawKv) as SanctionsRecord;
          return {
            clean: false,
            match: {
              matched_value: candidate.raw,
              candidate_type: candidate.type,
              list: parsed.list,
              entity_name: parsed.entity_name,
              source: "kv",
              details: parsed.details,
            },
          };
        }
      } catch (err) {
        console.error(
          JSON.stringify({
            event: "vizier.sanctions.kv_error",
            candidate: candidate.value,
            error: err instanceof Error ? err.message : "Unknown error",
          })
        );
      }
    }
  }

  // Check Tier 4: OFAC 50% Rule if ownership structure or shareholders provided
  const params = request.action.parameters ?? {};
  let ownershipGraph: EntityOwnershipGraph | null = null;

  if (params.ownership_graph && typeof params.ownership_graph === "object") {
    ownershipGraph = params.ownership_graph as unknown as EntityOwnershipGraph;
  } else if (Array.isArray(params.shareholders)) {
    const rawTarget = (params.counterparty || params.entity_name || params.company || params.vendor || params.payee || "counterparty");
    ownershipGraph = {
      entity_name: typeof rawTarget === "string" ? rawTarget : "counterparty",
      shareholders: params.shareholders as unknown as Shareholder[],
    };
  } else if (params.counterparty && typeof params.counterparty === "object") {
    const cp = params.counterparty as Record<string, unknown>;
    if (Array.isArray(cp.shareholders)) {
      ownershipGraph = {
        entity_name: (cp.name || cp.entity_name || "counterparty") as string,
        shareholders: cp.shareholders as unknown as Shareholder[],
      };
    }
  }

  if (ownershipGraph && ownershipGraph.shareholders && ownershipGraph.shareholders.length > 0) {
    const rule50Result = await evaluateSanctions50Rule(ownershipGraph, kv, customBlocked);
    if (!rule50Result.clean) {
      return {
        clean: false,
        match: {
          matched_value: rule50Result.entity_name,
          candidate_type: "entity_name",
          list: rule50Result.reason_codes[0] ?? "SANCTIONS_50_RULE_VIOLATION",
          entity_name: rule50Result.entity_name,
          source: rule50Result.direct_match ? rule50Result.direct_match.source : "built_in",
          details: {
            aggregate_blocked_percentage: rule50Result.aggregate_blocked_percentage,
            threshold_percentage: rule50Result.threshold_percentage,
            blocked_shareholders: rule50Result.blocked_shareholders,
            explanation: rule50Result.explanation,
          },
        },
        rule50_result: rule50Result,
      };
    }
  }

  return { clean: true };
}

export async function addCustomSanctionsEntry(
  kv: KVNamespace,
  entry: {
    raw_value: string;
    entity_name: string;
    list?: string;
    type?: "crypto_address" | "domain" | "entity_name" | "iban";
    details?: Record<string, unknown>;
  },
): Promise<{ key: string; normalized: string }> {
  let normalized: string;
  let candidateType: "crypto_address" | "domain" | "entity_name" | "iban";

  if (entry.type) {
    candidateType = entry.type;
    if (candidateType === "crypto_address") normalized = normalizeCryptoAddress(entry.raw_value);
    else if (candidateType === "iban") normalized = normalizeIban(entry.raw_value);
    else if (candidateType === "domain") normalized = normalizeDomain(entry.raw_value);
    else normalized = normalizeEntityName(entry.raw_value);
  } else {
    // Auto-detect
    if (CRYPTO_REGEX.test(entry.raw_value)) {
      candidateType = "crypto_address";
      normalized = normalizeCryptoAddress(entry.raw_value);
    } else if (DOMAIN_REGEX.test(normalizeDomain(entry.raw_value))) {
      candidateType = "domain";
      normalized = normalizeDomain(entry.raw_value);
    } else if (IBAN_REGEX.test(normalizeIban(entry.raw_value))) {
      candidateType = "iban";
      normalized = normalizeIban(entry.raw_value);
    } else {
      candidateType = "entity_name";
      normalized = normalizeEntityName(entry.raw_value);
    }
  }

  const kvKey = `sanctions:${candidateType}:${normalized}`;
  const record: SanctionsRecord = {
    entity_name: entry.entity_name,
    list: entry.list ?? "CUSTOM_DENYLIST",
    category: candidateType,
    details: entry.details,
  };

  await kv.put(kvKey, JSON.stringify(record));
  return { key: kvKey, normalized };
}
