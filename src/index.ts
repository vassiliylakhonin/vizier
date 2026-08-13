import { handleHttpRequest } from "./transport/http";

export default {
  fetch(request, env): Promise<Response> {
    return handleHttpRequest(request, {
      apiKey: env.VIZIER_API_KEY,
      agentCardSigningKey: env.AGENT_CARD_SIGNING_KEY,
    });
  },
} satisfies ExportedHandler<Env>;
