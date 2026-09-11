import type { KVNamespace } from "@cloudflare/workers-types";
import {
  BUILT_IN_SANCTIONS,
  normalizeEntityName,
  type SanctionsMatch,
  type SanctionsRecord,
} from "./sanctions";

export interface Shareholder {
  readonly name: string;
  readonly percentage: number; // 0.0 to 100.0
  readonly lei?: string;
  readonly country?: string;
  readonly shareholders?: readonly Shareholder[];
}

export interface EntityOwnershipGraph {
  readonly entity_name: string;
  readonly country?: string;
  readonly lei?: string;
  readonly registration_number?: string;
  readonly shareholders: readonly Shareholder[];
  readonly threshold_percentage?: number; // defaults to 50.0
}

export interface BlockedShareholderDetail {
  readonly name: string;
  readonly direct_percentage: number;
  readonly effective_percentage: number;
  readonly list: string;
  readonly match_source: "built_in" | "kv" | "constraint";
  readonly path: readonly string[];
  readonly deemed_blocked_entity?: boolean;
}

export interface Sanctions50EvaluationResult {
  readonly clean: boolean;
  readonly violation: boolean;
  readonly entity_name: string;
  readonly direct_match?: SanctionsMatch;
  readonly aggregate_blocked_percentage: number;
  readonly threshold_percentage: number;
  readonly blocked_shareholders: readonly BlockedShareholderDetail[];
  readonly reason_codes: readonly string[];
  readonly explanation: string;
}

export async function lookupDirectSanctions(
  rawName: string,
  kv?: KVNamespace,
  customBlocked?: ReadonlySet<string>,
): Promise<SanctionsMatch | null> {
  const normalized = normalizeEntityName(rawName);

  // 1. Custom blocked constraint
  if (customBlocked && (customBlocked.has(normalized) || customBlocked.has(rawName.trim().toLowerCase()))) {
    return {
      matched_value: rawName,
      candidate_type: "entity_name",
      list: "CUSTOM_CONSTRAINT_BLOCKED",
      entity_name: rawName,
      source: "constraint",
    };
  }

  // 2. Built-in SDN list
  const builtIn = BUILT_IN_SANCTIONS.get(normalized);
  if (builtIn !== undefined) {
    return {
      matched_value: rawName,
      candidate_type: "entity_name",
      list: builtIn.list,
      entity_name: builtIn.entity_name,
      source: "built_in",
      details: builtIn.details,
    };
  }

  // 3. KV denylist
  if (kv !== undefined) {
    try {
      const kvKey = `sanctions:entity_name:${normalized}`;
      const rawKv = await kv.get(kvKey);
      if (rawKv !== null) {
        const parsed = JSON.parse(rawKv) as SanctionsRecord;
        return {
          matched_value: rawName,
          candidate_type: "entity_name",
          list: parsed.list,
          entity_name: parsed.entity_name,
          source: "kv",
          details: parsed.details,
        };
      }
    } catch {
      // ignore kv read errors
    }
  }

  return null;
}

export async function evaluateSanctions50Rule(
  graph: EntityOwnershipGraph,
  kv?: KVNamespace,
  customBlocked?: ReadonlySet<string>,
): Promise<Sanctions50EvaluationResult> {
  const threshold = graph.threshold_percentage ?? 50.0;
  const entityName = graph.entity_name.trim();

  // Step 1: Check if the target entity itself is directly sanctioned
  const directMatch = await lookupDirectSanctions(entityName, kv, customBlocked);
  if (directMatch !== null) {
    return {
      clean: false,
      violation: true,
      entity_name: entityName,
      direct_match: directMatch,
      aggregate_blocked_percentage: 100.0,
      threshold_percentage: threshold,
      blocked_shareholders: [
        {
          name: entityName,
          direct_percentage: 100.0,
          effective_percentage: 100.0,
          list: directMatch.list,
          match_source: directMatch.source,
          path: [entityName],
        },
      ],
      reason_codes: ["SANCTIONED_ENTITY_MATCH"],
      explanation: `Target entity '${entityName}' is directly blocked on list '${directMatch.list}' (${directMatch.source}).`,
    };
  }

  // Step 2: Evaluate recursive ownership structure
  const blockedShareholders: BlockedShareholderDetail[] = [];
  const visited = new Set<string>([normalizeEntityName(entityName)]);

  let aggregateDirectBlocked = 0;

  for (const sh of graph.shareholders) {
    const shName = sh.name.trim();
    const normalizedSh = normalizeEntityName(shName);
    const directPct = Math.max(0, Math.min(100, sh.percentage));

    if (visited.has(normalizedSh)) {
      continue; // cycle prevention
    }

    // Check direct status of shareholder
    const shMatch = await lookupDirectSanctions(shName, kv, customBlocked);
    if (shMatch !== null) {
      aggregateDirectBlocked += directPct;
      blockedShareholders.push({
        name: shName,
        direct_percentage: directPct,
        effective_percentage: directPct,
        list: shMatch.list,
        match_source: shMatch.source,
        path: [entityName, shName],
      });
      continue;
    }

    // If shareholder has nested shareholders (subsidiary/holding structure)
    if (sh.shareholders && sh.shareholders.length > 0) {
      visited.add(normalizedSh);
      const subGraphResult = await evaluateSanctions50Rule(
        {
          entity_name: shName,
          shareholders: sh.shareholders,
          threshold_percentage: threshold,
        },
        kv,
        customBlocked,
      );

      // OFAC Rule: If parent is blocked (aggregate >= 50% or directly blocked),
      // then parent is considered blocked entity.
      if (subGraphResult.violation || subGraphResult.aggregate_blocked_percentage >= threshold) {
        aggregateDirectBlocked += directPct;
        blockedShareholders.push({
          name: shName,
          direct_percentage: directPct,
          effective_percentage: directPct,
          list: "OFAC_50_PERCENT_DEEMED",
          match_source: "built_in",
          path: [entityName, shName],
          deemed_blocked_entity: true,
        });
      } else if (subGraphResult.aggregate_blocked_percentage > 0) {
        // Proportional indirect share for transparency
        for (const subBlocked of subGraphResult.blocked_shareholders) {
          blockedShareholders.push({
            name: subBlocked.name,
            direct_percentage: subBlocked.direct_percentage,
            effective_percentage: Math.round((directPct * subBlocked.effective_percentage / 100.0) * 100) / 100,
            list: subBlocked.list,
            match_source: subBlocked.match_source,
            path: [entityName, shName, ...subBlocked.path.slice(1)],
          });
        }
      }
      visited.delete(normalizedSh);
    }
  }

  const roundedAggregate = Math.round(aggregateDirectBlocked * 100) / 100;
  const isViolation = roundedAggregate >= threshold;

  if (isViolation) {
    const listNames = Array.from(new Set(blockedShareholders.map((b) => b.name))).join(", ");
    return {
      clean: false,
      violation: true,
      entity_name: entityName,
      aggregate_blocked_percentage: roundedAggregate,
      threshold_percentage: threshold,
      blocked_shareholders: blockedShareholders,
      reason_codes: ["SANCTIONS_50_RULE_VIOLATION"],
      explanation: `Entity '${entityName}' is blocked under OFAC 50% Rule: aggregate blocked ownership is ${roundedAggregate.toFixed(2)}% (threshold: ${threshold.toFixed(2)}%). Blocked shareholders: ${listNames}.`,
    };
  }

  return {
    clean: true,
    violation: false,
    entity_name: entityName,
    aggregate_blocked_percentage: roundedAggregate,
    threshold_percentage: threshold,
    blocked_shareholders: blockedShareholders,
    reason_codes: [],
    explanation: `Entity '${entityName}' cleared OFAC 50% Rule: aggregate blocked ownership is ${roundedAggregate.toFixed(2)}% (below threshold of ${threshold.toFixed(2)}%).`,
  };
}
