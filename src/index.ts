import { handleHttpRequest } from "./transport/http";

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
} satisfies ExportedHandler<Env>;
