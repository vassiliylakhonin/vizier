import { handleHttpRequest } from "./transport/http";
import { pruneAuditMetadata } from "./storage/audit";

interface ExtendedEnv extends Env {
  readonly VIZIER_PRINCIPAL_KEYS?: string;
}

export default {
  fetch(request, env: ExtendedEnv, ctx): Promise<Response> {
    return handleHttpRequest(request, {
      apiKey: env.VIZIER_API_KEY,
      anonymousRateLimiter: env.ANONYMOUS_RATE_LIMIT,
      circuitBreakerKv: env.CIRCUIT_BREAKER_KV,
      agentCardSigningKey: env.AGENT_CARD_SIGNING_KEY,
      receiptSigningKey: env.RECEIPT_SIGNING_KEY,
      principalKeySource: env.VIZIER_PRINCIPAL_KEYS,
      db: env.DB,
      ctx,
    });
  },
  scheduled(controller, env: ExtendedEnv, ctx): void {
    ctx.waitUntil(
      pruneAuditMetadata(env.DB, new Date(controller.scheduledTime))
        .then((result) => {
          console.log(
            JSON.stringify({
              event: "vizier.audit.pruned",
              cutoff: result.cutoff,
              deleted: result.deleted,
            }),
          );
        })
        .catch((error: unknown) => {
          console.error(
            JSON.stringify({
              event: "vizier.audit.prune_failed",
              error: error instanceof Error ? error.name : "UnknownError",
            }),
          );
        }),
    );
  },
} satisfies ExportedHandler<ExtendedEnv>;
