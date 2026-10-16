import { describe, expect, it, vi } from 'vitest';
import { handleHttpRequest } from '../src/transport/http';

describe('content-free standalone access telemetry', () => {
  it('separates MCP discovery, tool errors and access refusals exactly once without submitted values', async () => {
    const log=vi.spyOn(console,'log').mockImplementation(()=>{});
    try {
      for (const [method, expected] of [['initialize','success'],['tools/list','success'],['tools/call','protocol_error']] as const) {
        log.mockClear();
        const response=await handleHttpRequest(new Request('https://vizier.example/mcp?private-query',{
          method:'POST', headers:{'content-type':'application/json','accept':'application/json','x-client-id':'agenda-owner-test',
            'user-agent':'private-user-agent','referer':'https://private.example/private-path'},
          body:JSON.stringify({jsonrpc:'2.0',id:'private-id',method,params:method==='tools/call'?{name:'private-tool',arguments:{secret:'private-secret'}}:{}}),
        }));
        expect(response.status).toBe(200);
        const events=log.mock.calls.map(c=>{try{return typeof c[0]==='string'?JSON.parse(c[0]):c[0]}catch{return null}})
          .filter(e=>e?.event==='agenda_service_access');
        expect(events).toHaveLength(1);
        expect(events[0]).toMatchObject({service:'vizier',operation:method,outcome:expected,caller_kind:'owner_synthetic',access_mode:'unverified'});
        expect(events[0]).not.toHaveProperty('authorization');
        expect(JSON.stringify(events)).not.toMatch(/private-query|private-user-agent|private-path|private-id|private-tool|private-secret/);
      }
      log.mockClear();
      await handleHttpRequest(new Request('https://vizier.example/mcp', {method:'POST',headers:{Origin:'https://other.example'},body:'private-secret'}));
      const events=log.mock.calls.map(c=>{try{return JSON.parse(c[0])}catch{return null}}).filter(e=>e?.event==='agenda_service_access');
      expect(events).toHaveLength(1);
      expect(events[0].outcome).toBe('access_rejected');
    } finally {log.mockRestore()}
  });
});
