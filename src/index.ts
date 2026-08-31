import { handleHttpRequest } from "./transport/http";
import { pruneAuditMetadata } from "./storage/audit";

export default {
  fetch(request, env, ctx): Promise<Response> {
    return handleHttpRequest(request, {
      apiKey: env.VIZIER_API_KEY,
      agentCardSigningKey: env.AGENT_CARD_SIGNING_KEY,
      receiptSigningKey: env.RECEIPT_SIGNING_KEY,
      db: env.DB,
      ctx,
    });
  },
  scheduled(controller, env, ctx): void {
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
} satisfies ExportedHandler<Env>;
