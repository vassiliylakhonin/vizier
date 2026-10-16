/** Content-free observations. Declared owner/probe labels are not authentication. */
export const ACCESS_OPERATIONS = new Set([
  'initialize', 'server/discover', 'tools/list', 'tools/call', 'ping',
  'notifications/initialized', 'metadata', 'health', 'action', 'other',
]);

const observed = new WeakSet<Response>();
export const hasAccessObservation = (response: Response): boolean => observed.has(response);

export function logServiceAccess(request: Request, operation: string, response: Response, rpcError = false): void {
  observed.add(response);
  try {
    const client = (request.headers.get('x-client-id') ?? '').toLowerCase();
    const ua = (request.headers.get('user-agent') ?? '').toLowerCase();
    const caller = client.startsWith('agenda-owner-') || /^(instinctowner|vizier-(live-)?smoke|agenda-owner-|agenda-intelligence-)/.test(ua)
      ? 'owner_synthetic' : /agenstry|glama|crawler|monitor|probe|registry/.test(ua) ? 'service_probe' : 'unsigned_external';
    const status = response.status;
    console.log(JSON.stringify({
      event: 'agenda_service_access', event_version: 1, service: 'vizier',
      timestamp: new Date().toISOString(), event_id: crypto.randomUUID(),
      transport: new URL(request.url).pathname === '/mcp' ? 'mcp' : 'http',
      operation: ACCESS_OPERATIONS.has(operation) ? operation : 'other',
      access_mode: request.headers.has('authorization') || request.headers.has('x-vizier-key') ? 'credential_present' : 'unverified',
      http_status: status,
      outcome: status >= 500 ? 'runtime_error' : status === 429 ? 'quota_rejected' : status === 401 || status === 403 ? 'access_rejected'
        : status >= 400 ? 'input_rejected' : rpcError ? 'protocol_error' : 'success',
      caller_kind: caller, origin_verification: 'unverified',
    }));
  } catch { /* Observability must not change authorization or response handling. */ }
}
