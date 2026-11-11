import { describe, expect, it } from "vitest";
import {
  analyzeNumericConsistency,
  evaluateNumericConsistency,
  parseNumericToken,
  statedTolerance,
} from "../src/core/numeric-consistency";
import { canonicalize, sha256 } from "../src/core/receipts";
import { handleHttpRequest } from "../src/transport/http";
import type { VerificationRequest } from "../src/core/schemas";

const TEST_API_KEY = "test-enforcement-key";

/**
 * The Freedom Finance report on Kaspi.kz (11 Nov 2026) that motivated this
 * check, transcribed from the user's screenshot: header and body moved to
 * target $101 / +13%, the metrics table still shows the old target $93 with
 * a -5% potential that matches neither price pair.
 */
const KASPI_REPORT = [
  "Отчет Freedom Finance по Kaspi.kz, 11 ноября 2026",
  "Рекомендация: Держать (Hold)",
  "Потенциал роста: 13%",
  "Целевая цена: $101",
  "Текущая цена: $89,5",
  "",
  "| Метрика | Значение |",
  "| --- | --- |",
  "| Текущая цена (USD) | 89,5 |",
  "| Целевая цена (USD) | 93 |",
  "| Потенциал роста (%) | -5 |",
  "",
  "В итоге целевая цена одной АДР повышена с $93 до $101 с потенциалом роста в 13%. Рекомендация: Держать.",
  "Доходы растут, но чистая прибыль ожидаемо стабильна.",
].join("\n");

interface VerificationResponseBody {
  readonly decision: "ALLOW" | "REVIEW" | "BLOCK";
  readonly reason_codes: string[];
  readonly policy_results?: Array<{
    readonly rule_id: string;
    readonly result: string;
    readonly reason_code?: string | null;
  }>;
}

function createRequest(
  parameters: Record<string, unknown>,
  constraints: Record<string, unknown> = { numeric_consistency: true },
): VerificationRequest {
  return {
    agent: { id: "test-agent", owner: "acme" },
    principal: { id: "acme" },
    action: {
      type: "publish_report",
      target: "research-portal",
      parameters,
    },
    authority: {
      allowed_actions: ["publish_report"],
      constraints,
    },
    context: {
      request_id: "req-num-01",
      timestamp: "2026-11-11T12:00:00Z",
      source: "rest",
    },
  } as unknown as VerificationRequest;
}

async function postVerify(body: unknown, apiKey: string = TEST_API_KEY): Promise<Response> {
  return handleHttpRequest(
    new Request("https://vizier.example/v1/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
    }),
    { apiKey },
  );
}

describe("Numeric consistency preflight", () => {
  describe("parseNumericToken", () => {
    it("parses decimal comma (Russian style)", () => {
      expect(parseNumericToken("89,5")).toEqual({ value: 89.5, fractionDigits: 1 });
    });
    it("parses plain integers and signs", () => {
      expect(parseNumericToken("-5")).toEqual({ value: -5, fractionDigits: 0 });
      expect(parseNumericToken("+13")).toEqual({ value: 13, fractionDigits: 0 });
    });
    it("parses space and comma thousands", () => {
      expect(parseNumericToken("1 457")).toEqual({ value: 1457, fractionDigits: 0 });
      expect(parseNumericToken("1,457")).toEqual({ value: 1457, fractionDigits: 0 });
    });
    it("parses mixed separators by the rightmost one", () => {
      expect(parseNumericToken("1,457.50")).toEqual({ value: 1457.5, fractionDigits: 2 });
      expect(parseNumericToken("1.457,50")).toEqual({ value: 1457.5, fractionDigits: 2 });
    });
    it("parses repeated-dot thousands", () => {
      expect(parseNumericToken("1.234.567")).toEqual({ value: 1234567, fractionDigits: 0 });
    });
    it("rejects non-numbers", () => {
      expect(parseNumericToken("+")).toBeNull();
      expect(parseNumericToken("abc")).toBeNull();
    });
  });

  describe("statedTolerance", () => {
    it("is half a unit of the last written digit", () => {
      expect(statedTolerance(0)).toBe(0.5);
      expect(statedTolerance(1)).toBe(0.05);
      expect(statedTolerance(2)).toBe(0.005);
    });
  });

  describe("analyzeNumericConsistency", () => {
    it("flags the Kaspi/Freedom report: target conflict, upside conflict, table upside mismatch", () => {
      const result = analyzeNumericConsistency(KASPI_REPORT);
      expect(result.consistent).toBe(false);
      expect(result.findings).toHaveLength(3);

      const targetConflict = result.findings.find(
        (f) => f.kind === "metric_conflict" && f.label === "target price",
      );
      expect(targetConflict).toBeDefined();
      expect(targetConflict!.detail).toContain("101 USD");
      expect(targetConflict!.detail).toContain("93 USD");
      // The stale table value equals the superseded "raised from $93" value.
      expect(targetConflict!.detail).toContain("superseded previous value");

      const upsideConflict = result.findings.find(
        (f) => f.kind === "metric_conflict" && f.label === "upside",
      );
      expect(upsideConflict).toBeDefined();
      expect(upsideConflict!.detail).toContain("13%");
      expect(upsideConflict!.detail).toContain("-5%");

      const derived = result.findings.find((f) => f.kind === "derived_value_mismatch");
      expect(derived).toBeDefined();
      // (93 / 89.5 - 1) * 100 = +3.91%, stated -5% in the table.
      expect(derived!.expected).toBe(3.91);
      expect(derived!.stated).toBe(-5);
      expect(derived!.tolerance).toBe(0.5);
    });

    it("accepts the header pair: $101 vs $89.5 rounds to the stated +13%", () => {
      // 101/89.5 - 1 = 12.85%; stated 13% is within ±0.5 pp, so the only
      // derived finding in the Kaspi report is the stale-table one.
      const result = analyzeNumericConsistency(KASPI_REPORT);
      const derivedFindings = result.findings.filter(
        (f) => f.kind === "derived_value_mismatch",
      );
      expect(derivedFindings).toHaveLength(1);
      expect(derivedFindings[0]!.expected).toBe(3.91);
    });

    it("passes a consistent report", () => {
      const text = [
        "Target price: $100",
        "Current price: $80",
        "Upside: 25%",
        "The target price of $100 implies an upside of 25% over the current price of $80.",
      ].join("\n");
      const result = analyzeNumericConsistency(text);
      expect(result.consistent).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it("treats a rounded stated upside as consistent", () => {
      const text = [
        "Target price: $100",
        "Current price: $96",
        "Upside: 4%",
      ].join("\n");
      // 100/96 - 1 = 4.167%; stated 4% is within ±0.5 pp.
      expect(analyzeNumericConsistency(text).consistent).toBe(true);
    });

    it("flags a stated upside that matches neither rounding", () => {
      const text = [
        "Target price: $100",
        "Current price: $80",
        "Upside: 10%",
      ].join("\n");
      const result = analyzeNumericConsistency(text);
      expect(result.consistent).toBe(false);
      const derived = result.findings.find((f) => f.kind === "derived_value_mismatch");
      expect(derived).toBeDefined();
      expect(derived!.expected).toBe(25);
      expect(derived!.stated).toBe(10);
    });

    it("does not conflict a superseded 'from' value with its replacement", () => {
      const result = analyzeNumericConsistency(
        "Целевая цена одной АДР повышена с $93 до $101.",
      );
      expect(result.consistent).toBe(true);
      const superseded = result.mentions.filter((m) => m.superseded);
      expect(superseded).toHaveLength(1);
      expect(superseded[0]!.value).toBe(93);
    });

    it("does not conflict English 'raised from X to Y' either", () => {
      const result = analyzeNumericConsistency(
        "The target price was raised from $93 to $101 with an upside of 13%.",
      );
      expect(result.consistent).toBe(true);
      expect(result.mentions.find((m) => m.value === 93)!.superseded).toBe(true);
    });

    it("flags a plain repeated metric with two current values", () => {
      const result = analyzeNumericConsistency("Target price: $100\nTarget price: $110");
      expect(result.consistent).toBe(false);
      expect(result.findings[0]!.kind).toBe("metric_conflict");
      expect(result.findings[0]!.detail).not.toContain("superseded");
    });

    it("ignores bare years", () => {
      const result = analyzeNumericConsistency("Report dated 11 November 2026");
      expect(result.mentions.find((m) => m.value === 2026)).toBeUndefined();
      expect(result.consistent).toBe(true);
    });

    it("keeps different currencies of the same label out of conflicts", () => {
      const result = analyzeNumericConsistency(
        "Target price: $101\nTarget price: 45000 KZT",
      );
      const conflict = result.findings.find(
        (f) => f.kind === "metric_conflict" && f.label === "target price",
      );
      expect(conflict).toBeUndefined();
    });
  });

  describe("evaluateNumericConsistency", () => {
    it("is off unless the constraints opt in", () => {
      const req = createRequest({ body: KASPI_REPORT }, {});
      const result = evaluateNumericConsistency(req);
      expect(result.consistent).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it("finds conflicts in nested parameters when opted in", () => {
      const req = createRequest({ meta: { report: { body: KASPI_REPORT } } });
      const result = evaluateNumericConsistency(req);
      expect(result.consistent).toBe(false);
      expect(result.findings.length).toBe(3);
      expect(result.findings[0]!.path).toBe("action.parameters.meta.report.body");
    });
  });

  describe("HTTP transport", () => {
    it("provides pre-flight scan endpoint /v1/numeric-consistency/scan", async () => {
      const res = await handleHttpRequest(
        new Request("https://vizier.example/v1/numeric-consistency/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: KASPI_REPORT }),
        }),
      );
      expect(res.status).toBe(200);
      const data = (await res.json()) as {
        consistent: boolean;
        findings: Array<{ kind: string; label: string }>;
        mentions_count: number;
      };
      expect(data.consistent).toBe(false);
      expect(data.findings).toHaveLength(3);
      expect(data.mentions_count).toBeGreaterThan(0);
    });

    it("returns consistent for a clean text", async () => {
      const res = await handleHttpRequest(
        new Request("https://vizier.example/v1/numeric-consistency/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            text: "Target price: $100\nCurrent price: $80\nUpside: 25%",
          }),
        }),
      );
      expect(res.status).toBe(200);
      const data = (await res.json()) as { consistent: boolean; findings: unknown[] };
      expect(data.consistent).toBe(true);
      expect(data.findings).toHaveLength(0);
    });

    it("rejects a scan request without text or parameters", async () => {
      const res = await handleHttpRequest(
        new Request("https://vizier.example/v1/numeric-consistency/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        }),
      );
      expect(res.status).toBe(422);
    });

    it("answers 405 to GET on the scan endpoint", async () => {
      const res = await handleHttpRequest(
        new Request("https://vizier.example/v1/numeric-consistency/scan", {
          method: "GET",
        }),
      );
      expect(res.status).toBe(405);
    });

    it("mints a signed JWS clearance receipt when receiptSigningKey is configured", async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
      );
      const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      const signingKey = JSON.stringify({ ...jwk, kid: "test-num-receipt-key", alg: "ES256", use: "sig" });
      const text = "Target price: $100\nCurrent price: $80\nUpside: 25%";

      const res = await handleHttpRequest(
        new Request("https://vizier.example/v1/numeric-consistency/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text }),
        }),
        { receiptSigningKey: signingKey },
      );
      expect(res.status).toBe(200);
      const data = (await res.json()) as { consistent: boolean; receipt?: string };
      expect(data.consistent).toBe(true);
      expect(typeof data.receipt).toBe("string");
      const [header, payload, signature] = data.receipt!.split(".");
      const claims = JSON.parse(Buffer.from(payload!, "base64url").toString("utf8"));
      expect(claims.scope).toBe("numeric_consistency_scan_only");
      expect(claims.consistent).toBe(true);
      expect(claims.input_sha256).toBe(await sha256(canonicalize({ text })));
      expect(await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" }, keyPair.publicKey,
        Buffer.from(signature!, "base64url"), new TextEncoder().encode(`${header}.${payload}`),
      )).toBe(true);
    });

    it("routes an opted-in inconsistent report to REVIEW at /v1/verify", async () => {
      const payload = {
        agent: { id: "publisher-bot", owner: "acme" },
        principal: { id: "acme" },
        action: {
          type: "publish_report",
          target: "research-portal",
          parameters: { body: KASPI_REPORT },
        },
        authority: {
          allowed_actions: ["publish_report"],
          constraints: {
            numeric_consistency: true,
            dlp_screening: false,
            sanctions_screening: false,
          },
        },
        context: {
          request_id: "req-num-02",
          timestamp: "2026-11-11T12:00:00Z",
          source: "rest",
        },
      };

      const res = await postVerify(payload);
      expect(res.status).toBe(200);
      const body = (await res.json()) as VerificationResponseBody;
      expect(body.decision).toBe("REVIEW");
      expect(body.reason_codes).toContain("NUMERIC_INCONSISTENCY");
      expect(body.policy_results).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule_id: "quality.numeric_consistency",
            result: "REVIEW",
            reason_code: "NUMERIC_INCONSISTENCY",
          }),
        ]),
      );
    });

    it("does not run the check at /v1/verify without the opt-in", async () => {
      const payload = {
        agent: { id: "publisher-bot", owner: "acme" },
        principal: { id: "acme" },
        action: {
          type: "publish_report",
          target: "research-portal",
          parameters: { body: KASPI_REPORT },
        },
        authority: {
          allowed_actions: ["publish_report"],
          constraints: {
            dlp_screening: false,
            sanctions_screening: false,
          },
        },
        context: {
          request_id: "req-num-03",
          timestamp: "2026-11-11T12:00:00Z",
          source: "rest",
        },
      };

      const res = await postVerify(payload);
      expect(res.status).toBe(200);
      const body = (await res.json()) as VerificationResponseBody;
      expect(body.decision).toBe("ALLOW");
      expect(body.policy_results?.map((r) => r.rule_id)).not.toContain(
        "quality.numeric_consistency",
      );
    });
  });
});
