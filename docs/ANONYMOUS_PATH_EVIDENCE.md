# Anonymous path evidence

What a visitor with no account sees. Checked live on 9 November 2026, read-only.
Registry version re-checked on 12 November 2026.

| Step | Observed |
| --- | --- |
| Playground | Reachable without sign-in at `/playground`. |
| MCP registry listing | Shows Vizier at 0.5.17. |
| Missing-grant example (anonymous) | `BLOCK` with `GRANT_REQUIRED` (and `AUTHORITY_SOURCE_UNTRUSTED`), exactly as documented. |
| REST `/v1/verify` without a token | HTTP 401. |

This is what the public deployment promises: anonymous callers can see a real
decision, but anonymous evaluation never returns `ALLOW`. An `ALLOW` needs a
principal-signed grant. The `/examples` document states the same: its allow
scenario returns `ALLOW` only with a valid grant, and `BLOCK` with
`GRANT_REQUIRED` anonymously in required mode.

Try it: open the playground and run the fictional purchase. The action is within
its declared limit, and it still blocks because no principal signed a grant.

This is a point-in-time read-only check, not a
monitored guarantee. It says nothing about adoption.
