export function createReviewConsole(): Response {
  const nonce = crypto.randomUUID();
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Vizier · Human review</title>
<style nonce="${nonce}">body{font:16px system-ui;margin:40px auto;max-width:1000px;padding:0 20px;background:#101820;color:#eee}input,textarea,button{font:inherit;padding:10px;margin:5px 0;border-radius:6px}input,textarea{box-sizing:border-box;width:100%;background:#1c2935;color:#fff;border:1px solid #627384}textarea{min-height:160px}button{cursor:pointer;margin-right:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1c2935;padding:16px}article{border-top:1px solid #627384;margin-top:24px}label{display:block}#message{white-space:pre-wrap;color:#ffd18c}small{color:#bdcad5}</style>
<h1>Human review</h1><p>Review the exact action and submitted evidence. Approval does not verify the evidence, clear sanctions or sign a payment. Wallet signing stays manual.</p>
<p><small>Reviews are stored for 7 days. Unresolved financial claims stay until reconciled; resolved financial records stay at least 7 days after settlement. Policy audit is retained until operator removal. Never paste secrets, private keys, seed phrases or confidential documents. Credentials stay in this page's memory; reload to clear them.</small></p>
<label>Integration key (submit / claim)<input id="integration" type="password" autocomplete="off"></label>
<label>Reviewer key (decide)<input id="reviewer" type="password" autocomplete="off"></label>
<button id="load">Refresh queue</button><button id="clear">Clear credentials and results</button>
<details><summary>Base USDC workflow budget</summary><p>Limits cover requests through this queue, not transfers made elsewhere. One USDC is 1,000,000 base units. Only the reviewer can set owner-approved limits. Claimed funds remain held until a matching finalized transaction is verified.</p><button id="policies">Show current policies</button><pre id="policyResult"></pre><textarea id="policy" aria-label="Owner-approved budget policy" placeholder='{"wallet":"0x…","single_limit":"…","daily_limit":"…","enabled":false,"reason":"Owner-approved policy"}'></textarea><button id="savePolicy">Save policy</button></details>
<details><summary>Submit a review</summary><p>Amounts must use exact strings in base units. Include the chain, sender, recipient, token contract and full calldata for a wallet action. Evidence is supplied by the submitter and must be checked independently.</p><textarea id="submission" spellcheck="false">{
  "audience": "agenda-financial-guard",
  "action": {"type": "manual-review-example"},
  "evidence": {},
  "escalation_reason": "Example only: replace with the exact action and report",
  "expires_in_seconds": 1800
}</textarea><button id="submit">Store review request</button></details>
<p id="message" role="status"></p><main id="queue"></main>
<script nonce="${nonce}">
const el = id => document.getElementById(id);
function message(value) { el('message').textContent = value; }
async function api(path, key, body) {
 if (!key) throw new Error('Enter the credential for this operation.');
 const response = await fetch(path, {method:body ? 'POST':'GET', credentials:'omit', headers:{Authorization:'Bearer '+key,'Content-Type':'application/json'}, ...(body ? {body:JSON.stringify(body)}:{})});
 const data = await response.json();
 if (!response.ok) throw new Error(data.error?.message || 'Request failed.');
 return data;
}
function button(label, fn) { const b=document.createElement('button'); b.textContent=label; b.onclick=async()=>{ b.disabled=true; try { await fn(); } catch(e) {message(e.message);} finally {b.disabled=false;} }; return b; }
async function refresh() {
 const data=await api('/v1/reviews',el('reviewer').value || el('integration').value);
 el('queue').replaceChildren();
 for(const row of data.reviews) {
  const article=document.createElement('article'); const title=document.createElement('h2'); title.textContent=row.id+' · '+row.effective_status; article.append(title);
  const content=document.createElement('pre'); content.textContent=JSON.stringify(row,null,2); article.append(content);
  const reason=document.createElement('textarea'); reason.placeholder='Decision reason (required)'; reason.setAttribute('aria-label','Decision reason for '+row.id);
  if(row.effective_status==='PENDING') {
   article.append(reason);
   for(const decision of ['APPROVED','REJECTED']) article.append(button(decision==='APPROVED'?'Approve exact request':'Reject',async()=>{
    if(!reason.value.trim()) throw new Error('A decision reason is required.');
    if(!confirm(decision+' request '+row.id+' with hash '+row.request_hash+'?')) return;
    await api('/v1/reviews/'+row.id+'/decision',el('reviewer').value,{request_hash:row.request_hash,decision,reason:reason.value}); await refresh(); message('Decision recorded. No action executed.');
   }));
  }
  if(row.effective_status==='APPROVED') article.append(button('Claim once for manual execution',async()=>{
   if(!confirm('Claim this exact approval once? No payment will be signed. A lost response cannot safely be retried as a new execution.')) return;
   const result=await api('/v1/reviews/'+row.id+'/consume',el('integration').value,{token:row.token,request_hash:row.request_hash,audience:row.request.audience}); await refresh(); message(JSON.stringify(result,null,2));
  }));
  if(['PENDING','APPROVED'].includes(row.effective_status)) article.append(button('Cancel unclaimed request',async()=>{
   const reason=prompt('Cancellation reason'); if(!reason || !reason.trim()) return;
   await api('/v1/reviews/'+row.id+'/cancel',el('reviewer').value,{request_hash:row.request_hash,reason}); await refresh();
  }));
  if(row.status==='CONSUMED' && row.request.audience==='agenda-financial-guard:base-native-usdc') article.append(button('Verify transaction in Base',async()=>{
   const hash=prompt('Transaction hash from your wallet. This attachment cannot be replaced; check it carefully.'); if(!hash) return;
   if(!confirm('Attach and verify '+hash+' for '+row.id+'? No transaction will be sent.')) return;
   const result=await api('/v1/reviews/'+row.id+'/transaction',el('integration').value,{transaction_hash:hash.trim()}); message(JSON.stringify(result,null,2));
  }));
  article.append(button('Show audit trail',async()=>{const detail=await api('/v1/reviews/'+row.id,el('reviewer').value || el('integration').value);content.textContent=JSON.stringify(detail,null,2);}));
  el('queue').append(article);
 }
 message('Showing up to '+data.limit+' most recent requests.');
}
el('policies').onclick=async()=>{try{el('policyResult').textContent=JSON.stringify(await api('/v1/reviews/policies',el('reviewer').value || el('integration').value),null,2);}catch(e){message(e.message);}};
el('savePolicy').onclick=async()=>{try{const policy=JSON.parse(el('policy').value);if(!confirm('Save this exact owner-approved policy? '+JSON.stringify(policy)))return;el('policyResult').textContent=JSON.stringify(await api('/v1/reviews/policies',el('reviewer').value,policy),null,2);}catch(e){message(e.message);}};
el('load').onclick=()=>refresh().catch(e=>message(e.message));
el('submit').onclick=async()=>{try{await api('/v1/reviews',el('integration').value,JSON.parse(el('submission').value));await refresh();message('Review stored.');}catch(e){message(e.message);}};
el('clear').onclick=()=>{el('integration').value='';el('reviewer').value='';el('queue').replaceChildren();el('policyResult').textContent='';el('policy').value='';message('Cleared.');};
</script></html>`, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'` } });
}
