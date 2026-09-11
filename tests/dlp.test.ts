import { describe, expect, it } from "vitest";
import {
  calculateShannonEntropy,
  evaluateDlp,
  isValidLuhn,
  maskSecret,
  scanDlpText,
} from "../src/core/dlp";
import { handleHttpRequest } from "../src/transport/http";
import type { VerificationRequest } from "../src/core/schemas";

const TEST_API_KEY = "test-enforcement-key";

interface VerificationResponseBody {
  readonly decision: "ALLOW" | "REVIEW" | "BLOCK";
  readonly reason_codes: string[];
  readonly policy_results?: Array<{
    readonly rule_id: string;
    readonly result: string;
    readonly reason_code?: string | null;
    readonly details?: {
      readonly findings?: Array<{
        readonly category: string;
        readonly detector: string;
        readonly snippet_masked: string;
        readonly path: string;
      }>;
      readonly count?: number;
    };
  }>;
}

interface DlpScanResponseBody {
  readonly clean: boolean;
  readonly total_leaks_prevented: number;
  readonly findings: Array<{
    readonly category: string;
    readonly detector: string;
    readonly snippet_masked: string;
    readonly path: string;
  }>;
}

function createDummyRequest(parameters: Record<string, unknown>, overrides: Record<string, unknown> = {}): VerificationRequest {
  return {
    agent: { id: "test-agent", owner: "acme" },
    principal: { id: "acme" },
    action: {
      type: "send_message",
      target: "external-slack-channel",
      parameters,
    },
    authority: {
      allowed_actions: ["send_message"],
      constraints: {
        dlp_screening: true,
      },
    },
    context: {
      request_id: "req-dlp-01",
      timestamp: "2026-09-11T12:00:00Z",
      source: "rest",
    },
    ...overrides,
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

describe("PII & Secret Leak Firewall (DLP)", () => {
  describe("Detectors & Algorithms", () => {
    it("masks secrets correctly while preserving ends", () => {
      expect(maskSecret("short")).toBe("******");
      expect(maskSecret("sk-proj-1234567890abcdef1234")).toBe("sk-p******1234");
    });

    it("validates payment cards via Luhn algorithm (no false positives)", () => {
      // Valid Luhn test card (4532 0151 1283 0366)
      expect(isValidLuhn("4532015112830366")).toBe(true);
      expect(isValidLuhn("4532-0151-1283-0366")).toBe(true);
      // Invalid Luhn (last digit changed)
      expect(isValidLuhn("4532015112830367")).toBe(false);
      // Too short
      expect(isValidLuhn("123456")).toBe(false);
    });

    it("calculates Shannon entropy", () => {
      expect(calculateShannonEntropy("aaaa")).toBe(0);
      expect(calculateShannonEntropy("abcdefgh12345678!@#$%^&*")).toBeGreaterThan(4.0);
    });

    it("detects OpenAI API keys", () => {
      const text = "Please call OpenAI with sk-proj-abcdef1234567890abcdef1234567890.";
      const findings = scanDlpText(text);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.category).toBe("api_key");
      expect(findings[0]?.detector).toBe("openai_api_key");
      expect(findings[0]?.snippet_masked).toContain("sk-p******");
    });

    it("detects AWS Access Keys", () => {
      const text = "Found AWS creds: AKIAIOSFODNN7EXAMPLE";
      const findings = scanDlpText(text);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.category).toBe("api_key");
      expect(findings[0]?.detector).toBe("aws_access_key");
    });

    it("detects Stripe Live API keys", () => {
      const mockStripeKey = ["sk", "live", "51TestDummyKeyForTestingOnly123"].join("_");
      const text = `API key is ${mockStripeKey}`;
      const findings = scanDlpText(text);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.category).toBe("api_key");
      expect(findings[0]?.detector).toBe("stripe_api_key");
    });

    it("detects GitHub Personal Access Tokens", () => {
      const mockGhp = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz";
      const text = `Token: ${mockGhp}`;
      const findings = scanDlpText(text);
      expect(findings).toHaveLength(1);
      expect(findings[0]?.category).toBe("api_key");
      expect(findings[0]?.detector).toBe("github_token");
    });

    it("detects Private Key PEM headers", () => {
      const text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...";
      const findings = scanDlpText(text);
      expect(findings.some((f) => f.category === "private_key")).toBe(true);
    });

    it("detects JWT tokens", () => {
      const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4sPqPOpfs3n74wX_Vf0GAKPgnv_nI2nlvW3wYmo";
      const findings = scanDlpText(`Auth bearer ${jwt}`);
      expect(findings.some((f) => f.category === "jwt")).toBe(true);
    });

    it("detects valid payment cards and ignores invalid numbers", () => {
      const validText = "Customer card: 4532-0151-1283-0366";
      const validFindings = scanDlpText(validText);
      expect(validFindings.some((f) => f.category === "payment_card")).toBe(true);

      const invalidText = "Order ID: 4532-0151-1283-0367";
      const invalidFindings = scanDlpText(invalidText);
      expect(invalidFindings.filter((f) => f.category === "payment_card")).toHaveLength(0);
    });

    it("detects US SSN", () => {
      const text = "SSN is 123-45-6789 in records.";
      const findings = scanDlpText(text);
      expect(findings.some((f) => f.category === "ssn")).toBe(true);
    });
  });

  describe("Request Evaluation", () => {
    it("flags leaks deep inside nested parameter objects", () => {
      const req = createDummyRequest({
        request_body: {
          headers: {
            Authorization: "Bearer sk-proj-1234567890abcdef1234567890",
          },
        },
      });
      const result = evaluateDlp(req);
      expect(result.clean).toBe(false);
      expect(result.total_leaks_prevented).toBe(1);
      expect(result.findings[0]?.path).toBe("action.parameters.request_body.headers.Authorization");
    });

    it("allows clean requests without findings", () => {
      const req = createDummyRequest({
        query: "What is the weather in London?",
        options: { format: "json", limit: 5 },
      });
      const result = evaluateDlp(req);
      expect(result.clean).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it("respects allowed_dlp_categories in authority constraints", () => {
      const req = createDummyRequest(
        {
          api_key: "sk-proj-1234567890abcdef1234567890",
        },
        {
          authority: {
            allowed_actions: ["send_message"],
            constraints: {
              dlp_screening: true,
              allowed_dlp_categories: ["api_key"],
            },
          },
        },
      );
      const result = evaluateDlp(req);
      expect(result.clean).toBe(true);
      expect(result.findings).toHaveLength(0);
    });
  });

  describe("HTTP Transport Endpoints", () => {
    it("provides pre-flight scan endpoint /v1/dlp/scan", async () => {
      const res = await handleHttpRequest(
        new Request("https://vizier.example/v1/dlp/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            text: "My secret AWS key: AKIAIOSFODNN7EXAMPLE",
          }),
        }),
      );
      expect(res.status).toBe(200);
      const data = (await res.json()) as DlpScanResponseBody;
      expect(data.clean).toBe(false);
      expect(data.findings[0]?.category).toBe("api_key");
      expect(data.findings[0]?.detector).toBe("aws_access_key");
    });

    it("blocks secret leak at /v1/verify with SECRET_LEAK_PREVENTED", async () => {
      const leakedPayload = {
        agent: { id: "leaking-bot", owner: "acme" },
        principal: { id: "acme" },
        action: {
          type: "web_search",
          target: "duckduckgo.com",
          parameters: {
            query: "how to use key sk-proj-1234567890abcdef1234567890",
          },
        },
        authority: {
          allowed_actions: ["web_search"],
          constraints: {
            dlp_screening: true,
          },
        },
        context: {
          request_id: "req-leak-01",
          timestamp: "2026-09-11T12:00:00Z",
          source: "rest",
        },
      };

      const res = await postVerify(leakedPayload);
      expect(res.status).toBe(200);
      const body = (await res.json()) as VerificationResponseBody;
      expect(body.decision).toBe("BLOCK");
      expect(body.reason_codes).toContain("SECRET_LEAK_PREVENTED");
      expect(body.policy_results).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            rule_id: "security.dlp",
            result: "FAIL",
            reason_code: "SECRET_LEAK_PREVENTED",
          }),
        ]),
      );
    });

    it("allows clean requests at /v1/verify", async () => {
      const cleanPayload = {
        agent: { id: "clean-bot", owner: "acme" },
        principal: { id: "acme" },
        action: {
          type: "web_search",
          target: "duckduckgo.com",
          parameters: {
            query: "how to bake sourdough bread",
          },
        },
        authority: {
          allowed_actions: ["web_search"],
          constraints: {
            dlp_screening: true,
          },
        },
        context: {
          request_id: "req-clean-01",
          timestamp: "2026-09-11T12:00:00Z",
          source: "rest",
        },
      };

      const res = await postVerify(cleanPayload);
      expect(res.status).toBe(200);
      const body = (await res.json()) as VerificationResponseBody;
      expect(body.decision).toBe("ALLOW");
      expect(body.reason_codes).toHaveLength(0);
    });
  });
});
