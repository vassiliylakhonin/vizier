import { handleHttpRequest } from "./transport/http";
import { handleScheduled } from "./scheduled";

interface ExtendedEnv extends Env {
  readonly VIZIER_PRINCIPAL_KEYS?: string;
  readonly VIZIER_SIGNED_GRANT_MODE?: string;
  readonly VIZIER_REVIEWER_KEY?: string;
  readonly VIZIER_MONITORED_WALLET?: string;
}

export default {
  fetch(request, env: ExtendedEnv, ctx): Promise<Response> {
    return handleHttpRequest(request, {
      apiKey: env.VIZIER_API_KEY,
      reviewerApiKey: env.VIZIER_REVIEWER_KEY,
      anonymousRateLimiter: env.ANONYMOUS_RATE_LIMIT,
      circuitBreakerKv: env.CIRCUIT_BREAKER_KV,
      agentCardSigningKey: env.AGENT_CARD_SIGNING_KEY,
      receiptSigningKey: env.RECEIPT_SIGNING_KEY,
      principalKeySource: env.VIZIER_PRINCIPAL_KEYS,
      signedGrantModeSource: env.VIZIER_SIGNED_GRANT_MODE,
      db: env.DB,
      ctx,
    });
  },
  scheduled: handleScheduled,
} satisfies ExportedHandler<ExtendedEnv>;
