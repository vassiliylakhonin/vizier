import type { VerificationRequest } from "./schemas";

/**
 * Deterministic numeric-consistency preflight for agent-produced text.
 *
 * The check extracts labeled numeric mentions ("Target price: $101",
 * "| Целевая цена (USD) | 93 |", "потенциал роста в 13%"), groups them by
 * metric, and reports two kinds of internal inconsistency:
 *
 * 1. metric_conflict — the same metric carries two different current values
 *    in one document (e.g. target price $101 in the header vs $93 in a table).
 * 2. derived_value_mismatch — a stated upside/downside percentage does not
 *    match the value recomputed from the document's own target and current
 *    prices within the rounding tolerance implied by how the percentage was
 *    written (0 decimals => ±0.5 pp, 1 decimal => ±0.05 pp).
 *
 * Explicit revisions ("raised from $93 to $101", "повышена с $93 до $101")
 * mark the "from" value as superseded: it is historical, not a current value,
 * so it never conflicts with the new value. A conflicting current value that
 * equals a superseded one is called out in the finding detail as a likely
 * stale copy.
 *
 * This is a heuristic consistency check over labeled numbers, not a fact
 * check: it cannot tell which of two conflicting values is correct, and it
 * only compares metrics it can label. English and Russian labels are
 * recognized for the derived upside check; exact-label conflict detection
 * works for labels in any language.
 */

export type NumericUnit = "percent" | "currency" | "plain";

export interface NumericMention {
  /** Grouping key: canonical alias when recognized, else normalized label. */
  readonly label: string;
  /** The label as written in the source line. */
  readonly label_text: string;
  readonly value: number;
  readonly unit: NumericUnit;
  /** Currency code when a symbol, code or label unit names one. */
  readonly currency: string | null;
  /** 1-based line number inside the analyzed text. */
  readonly line: number;
  /** Trimmed source line the mention came from. */
  readonly context: string;
  /** Fractional digits as written; drives rounding tolerance. */
  readonly fraction_digits: number;
  /** True for the "from" side of an explicit revision ("raised from X to Y"). */
  readonly superseded: boolean;
}

export type NumericConsistencyFindingKind =
  | "metric_conflict"
  | "derived_value_mismatch";

export interface NumericConsistencyFinding {
  readonly kind: NumericConsistencyFindingKind;
  readonly label: string;
  /** Where the text was found, e.g. "text" or "action.parameters.body". */
  readonly path: string;
  readonly detail: string;
  readonly mentions: readonly NumericMention[];
  /** Recomputed value for derived_value_mismatch (percentage points). */
  readonly expected?: number;
  /** Nearest stated value for derived_value_mismatch. */
  readonly stated?: number;
  /** Rounding tolerance applied to the stated value, in its units. */
  readonly tolerance?: number;
}

export interface NumericConsistencyResult {
  readonly consistent: boolean;
  readonly findings: readonly NumericConsistencyFinding[];
  readonly mentions: readonly NumericMention[];
}

export interface NumericConsistencyEvaluationResult {
  readonly consistent: boolean;
  readonly findings: readonly NumericConsistencyFinding[];
}

export interface NumericConsistencyOptions {
  readonly enabled?: boolean;
}

const CURRENCY_SYMBOLS: Readonly<Record<string, string>> = Object.freeze({
  $: "USD",
  "€": "EUR",
  "£": "GBP",
});

const CURRENCY_WORDS = new Set([
  "USD",
  "EUR",
  "GBP",
  "KZT",
  "RUB",
  "RUR",
  "USDC",
  "USDT",
  "KGS",
  "UZS",
  "CNY",
  "JPY",
  "CHF",
]);

const NUMBER_BODY = String.raw`(?:\d{1,3}(?:[ \u00A0]\d{3})+|\d+)(?:[.,]\d+)?`;
const NUMBER_TOKEN = new RegExp(
  String.raw`(?<![\p{L}\p{N}_.])([+-]?)([$€£])?(${NUMBER_BODY})(%)?(?![\p{L}\p{N}%])`,
  "gu",
);

/** "from X to Y" / "с X до Y" revisions; the X span is superseded history. */
const REVISION = new RegExp(
  String.raw`(?<![\p{L}])(?:с|from)(?![\p{L}])\s*([+-]?[$€£]?${NUMBER_BODY}%?)\s*(?<![\p{L}])(?:до|to)(?![\p{L}])\s*([+-]?[$€£]?${NUMBER_BODY}%?)`,
  "giu",
);

const FILLER_WORDS = new Set([
  "в",
  "во",
  "на",
  "по",
  "с",
  "со",
  "и",
  "of",
  "the",
  "a",
  "an",
  "from",
  "at",
  "to",
  "до",
  "and",
  "is",
  "was",
  "равна",
  "равен",
  "составила",
  "составил",
]);

/**
 * Recognized metric families for the derived-value check. A normalized label
 * containing any key canonicalizes to the family, which also unifies
 * inflections and phrasing variants for conflict grouping.
 */
const METRIC_ALIASES: ReadonlyArray<{
  readonly canonical: string;
  readonly keys: readonly string[];
}> = Object.freeze([
  Object.freeze({
    canonical: "target price",
    keys: Object.freeze([
      "target price",
      "price target",
      "целевая цена",
      "целевой цены",
      "цель по цене",
    ]),
  }),
  Object.freeze({
    canonical: "current price",
    keys: Object.freeze([
      "current price",
      "текущая цена",
      "текущей цены",
      "спотовая цена",
    ]),
  }),
  Object.freeze({
    canonical: "upside",
    keys: Object.freeze([
      "upside",
      "growth potential",
      "потенциал роста",
      "потенциалом роста",
      "потенциала роста",
    ]),
  }),
]);

interface ParsedToken {
  readonly value: number;
  readonly fractionDigits: number;
}

/** Parses "1 457", "89,5", "1,457.50", "-5" with decimal-separator heuristics. */
export function parseNumericToken(raw: string): ParsedToken | null {
  let s = raw.trim().replace(/^[$€£]+/, "").replace(/%$/, "").trim();
  s = s.replace(/[ \u00A0]/g, "");
  if (s === "" || s === "+" || s === "-") return null;
  let fractionDigits = 0;
  const hasComma = s.includes(",");
  const hasDot = s.includes(".");
  if (hasComma && hasDot) {
    if (s.lastIndexOf(",") > s.lastIndexOf(".")) {
      fractionDigits = s.length - s.lastIndexOf(",") - 1;
      s = s.replace(/\./g, "").replace(",", ".");
    } else {
      fractionDigits = s.length - s.lastIndexOf(".") - 1;
      s = s.replace(/,/g, "");
    }
  } else if (hasComma) {
    const parts = s.split(",");
    const thousands =
      parts.length > 1 &&
      parts.slice(1).every((p) => p.length === 3) &&
      parts[0]!.length <= 3;
    if (thousands) {
      s = parts.join("");
    } else {
      fractionDigits = parts[parts.length - 1]!.length;
      s = parts.join(".");
    }
  } else if (hasDot) {
    const parts = s.split(".");
    if (parts.length > 2 && parts.slice(1).every((p) => p.length === 3)) {
      s = parts.join("");
    } else {
      fractionDigits = parts[parts.length - 1]!.length;
    }
  }
  const value = Number(s);
  if (!Number.isFinite(value)) return null;
  return { value, fractionDigits };
}

function normalizeLabel(raw: string): string {
  let s = raw.toLowerCase().replace(/ё/g, "е");
  s = s.replace(
    /\((?:usd|eur|gbp|kzt|rub|rur|usdc|usdt|kgs|uzs|cny|jpy|chf|%|\$|€|£|долл\.?|тенге)\)/giu,
    " ",
  );
  s = s.replace(/[$€£%]/g, " ");
  s = s.replace(/[#*>•·_~:;.!,?()"'[\]{}«»„“””—–-]/gu, " ");
  const words = s.split(/\s+/).filter((w) => w.length > 0);
  while (words.length > 0 && FILLER_WORDS.has(words[words.length - 1]!)) {
    words.pop();
  }
  while (words.length > 0 && FILLER_WORDS.has(words[0]!)) {
    words.shift();
  }
  return words.slice(-8).join(" ");
}

function canonicalLabel(normalized: string): string | null {
  for (const { canonical, keys } of METRIC_ALIASES) {
    for (const key of keys) {
      if (normalized === key || normalized.includes(key)) return canonical;
    }
  }
  return null;
}

/** Rounding tolerance implied by how a value was written: ±half a last digit. */
export function statedTolerance(fractionDigits: number): number {
  return 0.5 * Math.pow(10, -fractionDigits);
}

interface RawTokenMatch {
  readonly start: number;
  readonly end: number;
  readonly sign: string;
  readonly symbol: string | undefined;
  readonly digits: string;
  readonly percent: boolean;
}

function findNumberTokens(line: string): RawTokenMatch[] {
  const tokens: RawTokenMatch[] = [];
  NUMBER_TOKEN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = NUMBER_TOKEN.exec(line)) !== null) {
    tokens.push({
      start: m.index,
      end: m.index + m[0].length,
      sign: m[1] ?? "",
      symbol: m[2],
      digits: m[3]!,
      percent: m[4] !== undefined,
    });
  }
  return tokens;
}

/** Spans of the "from" side of explicit revisions on one line. */
function findSupersededSpans(
  line: string,
): Array<{ start: number; end: number }> {
  const spans: Array<{ start: number; end: number }> = [];
  REVISION.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = REVISION.exec(line)) !== null) {
    const full = m[0];
    const fromToken = m[1]!;
    const offset = full.indexOf(fromToken);
    spans.push({
      start: m.index + offset,
      end: m.index + offset + fromToken.length,
    });
  }
  return spans;
}

function labelForToken(line: string, start: number): string {
  if (line.includes("|")) {
    // Markdown-style table row: the label lives in a text cell left of the value.
    const cells = line.split("|");
    let pos = 0;
    let labelCell = "";
    for (const cell of cells) {
      const cellStart = pos;
      const cellEnd = pos + cell.length;
      if (start >= cellStart && start <= cellEnd) {
        break;
      }
      const trimmed = cell.trim();
      if (trimmed !== "" && !/\d/.test(trimmed) && /[\p{L}]/u.test(trimmed)) {
        labelCell = trimmed;
      }
      pos = cellEnd + 1;
    }
    if (labelCell !== "") return labelCell;
  }
  return line.slice(0, start);
}

function currencyFromLabel(rawLabel: string): string | null {
  const paren = rawLabel.match(
    /\((USD|EUR|GBP|KZT|RUB|RUR|USDC|USDT|KGS|UZS|CNY|JPY|CHF)\)/i,
  );
  if (paren) return paren[1]!.toUpperCase();
  for (const word of rawLabel.split(/[\s,;:()[\]]+/)) {
    if (CURRENCY_WORDS.has(word.toUpperCase())) return word.toUpperCase();
  }
  return null;
}

function extractMentions(text: string): NumericMention[] {
  const mentions: NumericMention[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const supersededSpans = findSupersededSpans(line);
    for (const token of findNumberTokens(line)) {
      const rawNumeric = `${token.sign}${token.digits}${token.percent ? "%" : ""}`;
      const parsed = parseNumericToken(rawNumeric);
      if (parsed === null) continue;
      // Bare 4-digit years are dates, not metrics.
      if (
        !token.percent &&
        token.symbol === undefined &&
        /^\d{4}$/.test(token.digits) &&
        parsed.value >= 1900 &&
        parsed.value <= 2100
      ) {
        continue;
      }
      const rawLabel = labelForToken(line, token.start);
      const normalized = normalizeLabel(rawLabel);
      if (normalized === "") continue;
      let unit: NumericUnit = token.percent
        ? "percent"
        : token.symbol !== undefined
          ? "currency"
          : "plain";
      let currency: string | null =
        token.symbol !== undefined
          ? (CURRENCY_SYMBOLS[token.symbol] ?? null)
          : null;
      // A label that names the unit applies it to a bare number
      // ("Целевая цена (USD) | 93", "Потенциал роста (%) | -5").
      if (unit === "plain" && /%/.test(rawLabel)) {
        unit = "percent";
      }
      if (unit === "plain" || unit === "currency") {
        const labelCurrency = currencyFromLabel(rawLabel);
        if (labelCurrency !== null) {
          unit = "currency";
          currency = currency ?? labelCurrency;
        }
      }
      const superseded = supersededSpans.some(
        (span) => token.start >= span.start && token.start < span.end,
      );
      mentions.push({
        label: canonicalLabel(normalized) ?? normalized,
        label_text: rawLabel.trim().replace(/[:;.\s]+$/, ""),
        value: parsed.value,
        unit,
        currency,
        line: i + 1,
        context: line.trim(),
        fraction_digits: parsed.fractionDigits,
        superseded,
      });
    }
  }
  return mentions;
}

function currenciesConflict(a: NumericMention, b: NumericMention): boolean {
  return (
    a.currency !== null && b.currency !== null && a.currency !== b.currency
  );
}

function distinctValues(mentions: readonly NumericMention[]): number[] {
  const values: number[] = [];
  for (const m of mentions) {
    if (!values.some((v) => Math.abs(v - m.value) < 1e-9)) {
      values.push(m.value);
    }
  }
  return values;
}

function findConflicts(
  mentions: readonly NumericMention[],
  path: string,
): NumericConsistencyFinding[] {
  const findings: NumericConsistencyFinding[] = [];
  const byLabel = new Map<string, NumericMention[]>();
  for (const m of mentions) {
    const group = byLabel.get(m.label) ?? [];
    group.push(m);
    byLabel.set(m.label, group);
  }
  for (const [label, group] of byLabel) {
    const current = group.filter((m) => !m.superseded);
    if (current.length < 2) continue;
    const conflicting = new Set<number>();
    for (let a = 0; a < current.length; a++) {
      for (let b = a + 1; b < current.length; b++) {
        const ma = current[a]!;
        const mb = current[b]!;
        if (ma.unit !== mb.unit) continue;
        if (currenciesConflict(ma, mb)) continue;
        if (Math.abs(ma.value - mb.value) >= 1e-9) {
          conflicting.add(a);
          conflicting.add(b);
        }
      }
    }
    if (conflicting.size === 0) continue;
    const involved = [...conflicting]
      .sort((a, b) => a - b)
      .map((i) => current[i]!);
    const values = distinctValues(involved);
    const superseded = group.filter((m) => m.superseded);
    const staleNotes = values.flatMap((v) => {
      const stale = superseded.find((s) => Math.abs(s.value - v) < 1e-9);
      const at = involved.find((m) => Math.abs(m.value - v) < 1e-9);
      return stale !== undefined && at !== undefined
        ? [
            `Value ${v} on line ${at.line} matches the superseded previous value on line ${stale.line} (likely a stale copy).`,
          ]
        : [];
    });
    const display = involved[0]!.label_text || label;
    findings.push({
      kind: "metric_conflict",
      label,
      path,
      detail:
        `Metric "${display}" has ${values.length} different current values: ` +
        values
          .map((v) => {
            const m = involved.find((x) => Math.abs(x.value - v) < 1e-9)!;
            const suffix =
              m.unit === "percent"
                ? "%"
                : m.currency !== null
                  ? ` ${m.currency}`
                  : "";
            return `${v}${suffix} (line ${m.line})`;
          })
          .join(", ") +
        "." +
        (staleNotes.length > 0 ? ` ${staleNotes.join(" ")}` : ""),
      mentions: Object.freeze(involved),
    });
  }
  return findings;
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

function findDerivedMismatches(
  mentions: readonly NumericMention[],
  path: string,
): NumericConsistencyFinding[] {
  const findings: NumericConsistencyFinding[] = [];
  const current = mentions.filter((m) => !m.superseded);
  const targets = current.filter(
    (m) => m.label === "target price" && m.unit === "currency",
  );
  const currents = current.filter(
    (m) => m.label === "current price" && m.unit === "currency",
  );
  const upsides = current.filter(
    (m) => m.label === "upside" && m.unit === "percent",
  );
  if (targets.length === 0 || currents.length === 0 || upsides.length === 0) {
    return findings;
  }
  for (const tv of distinctValues(targets)) {
    const t = targets.find((m) => Math.abs(m.value - tv) < 1e-9)!;
    for (const cv of distinctValues(currents)) {
      const c = currents.find((m) => Math.abs(m.value - cv) < 1e-9)!;
      if (currenciesConflict(t, c) || c.value === 0) continue;
      const expected = (t.value / c.value - 1) * 100;
      const explained = upsides.some(
        (u) =>
          Math.abs(u.value - expected) <=
          statedTolerance(u.fraction_digits) + 1e-9,
      );
      if (explained) continue;
      const nearest = upsides.reduce((best, u) =>
        Math.abs(u.value - expected) < Math.abs(best.value - expected)
          ? u
          : best,
      );
      const tolerance = statedTolerance(nearest.fraction_digits);
      findings.push({
        kind: "derived_value_mismatch",
        label: "upside",
        path,
        detail:
          `Derived upside from target price ${t.value} ${t.currency ?? ""} and current price ${c.value} ${c.currency ?? ""} is ${round2(expected)}%, ` +
          `but the nearest stated upside is ${nearest.value}% on line ${nearest.line} ` +
          `(difference ${round2(Math.abs(nearest.value - expected))} pp, rounding tolerance ±${tolerance} pp).`.replace(
            /\s+/g,
            " ",
          ),
        mentions: Object.freeze([t, c, nearest]),
        expected: round2(expected),
        stated: nearest.value,
        tolerance,
      });
    }
  }
  return findings;
}

/**
 * Analyzes one text for internal numeric consistency. Pure and synchronous.
 */
export function analyzeNumericConsistency(
  text: string,
  path: string = "text",
): NumericConsistencyResult {
  if (typeof text !== "string" || text.length === 0) {
    return {
      consistent: true,
      findings: Object.freeze([]),
      mentions: Object.freeze([]),
    };
  }
  const mentions = extractMentions(text);
  const findings = [
    ...findConflicts(mentions, path),
    ...findDerivedMismatches(mentions, path),
  ];
  return Object.freeze({
    consistent: findings.length === 0,
    findings: Object.freeze(findings),
    mentions: Object.freeze(mentions),
  });
}

/**
 * Recursively analyzes every string in a parameters map.
 */
export function scanNumericConsistencyParameters(
  parameters: Record<string, unknown>,
  basePath: string = "action.parameters",
): NumericConsistencyFinding[] {
  const findings: NumericConsistencyFinding[] = [];
  function walk(val: unknown, currentPath: string): void {
    if (typeof val === "string") {
      findings.push(...analyzeNumericConsistency(val, currentPath).findings);
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
 * Opt-in preflight over a verification request. Unlike DLP screening it is
 * off unless the authority constraints set `numeric_consistency: true`:
 * inconsistent numbers call for human judgment (REVIEW), so a request that
 * never asked for the check must not start returning REVIEW on its own.
 */
export function evaluateNumericConsistency(
  request: VerificationRequest,
  options: NumericConsistencyOptions = {},
): NumericConsistencyEvaluationResult {
  const enabled =
    options.enabled ??
    request.authority.constraints.numeric_consistency === true;
  if (!enabled) {
    return { consistent: true, findings: Object.freeze([]) };
  }
  const findings: NumericConsistencyFinding[] = [];
  if (typeof request.action.target === "string") {
    findings.push(
      ...analyzeNumericConsistency(request.action.target, "action.target")
        .findings,
    );
  }
  findings.push(
    ...scanNumericConsistencyParameters(
      request.action.parameters,
      "action.parameters",
    ),
  );
  return Object.freeze({
    consistent: findings.length === 0,
    findings: Object.freeze(findings),
  });
}
