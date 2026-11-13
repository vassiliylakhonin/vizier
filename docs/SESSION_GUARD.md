# Session guard and policy probes

Included in the v0.5.18 GitHub Release archives. Not published to npm or PyPI.

The Node MCP enforcement proxy now blocks the third consecutive identical tool
call within 30 seconds by default. The identity is the tool name plus canonical
JSON arguments, not the JSON-RPC request id. A different call or an expired
window resets the consecutive count. Explicit `circuitBreaker.maxRepeats` keeps
its existing meaning: number of repeats admitted before the next is blocked.
Reason code: `CIRCUIT_TRIPPED:LOOP_DETECTED`. The older Worker KV circuit breaker
is unchanged and is not an atomic, distributed consecutive-call guarantee.
Python already implements a third-consecutive-call circuit breaker.

BLOCK recovery is advisory, never new authority. Worker recovery appears inside
`integration.authority.trusted` policy details to preserve released SDKs' strict
top-level response schema. Proxy argument/taint refusals have `data.recovery`.
Always inspect every failing policy, not only the first message.

## Operator-owned argument policy

Start with an existing workspace and an operator-owned JSON file:

```json
{
  "tools": {
    "write_file": {
      "arguments": [{ "kind": "path", "argument": "path", "root": "/workspace/project" }]
    },
    "read_private": { "label": "source:private" },
    "send_message": {
      "label": "sink:external",
      "arguments": [{ "kind": "url", "argument": "url", "origins": ["https://example.com"] }]
    }
  }
}
```

```sh
npm run build:packages
node packages/mcp-proxy/dist/cli.js --guard-policy /operator/policy.json --help
# Add --guard-policy to the normal proxy start command with its upstream/tools.
node packages/mcp-proxy/dist/policy-cli.js test-policy /operator/policy.json
# The package also installs the bin: vizier test-policy /operator/policy.json
```

Policy files must be writable only by the operator, not the agent. Programmatic
clients pass `guardPolicy` to `createMcpEnforcementProxy`. Only explicitly named,
top-level arguments are checked. Unknown settings fail validation. This is not
a SQL/shell parser, recursive scanner, glob engine, or general Unicode sanitizer.

URL comparisons use HTTP(S) origins, with host case, default ports and IDNA
handled by WHATWG URL. Paths remain case-sensitive. Single percent decoding is
checked as well as the original path; controls, double encoding, Windows path
ambiguities and credential-bearing URLs are refused. Values are never rewritten:
the verifier receipt and upstream still bind to the original call. Filesystem
roots and candidate symlinks resolve on the proxy host. A new file requires an
existing real parent. Unavailable roots and dangling links fail closed.

**Filesystem boundary:** path checks are useful only if the executor uses the
same filesystem namespace and path semantics. They cannot inspect a remote
server's symlinks, prevent a symlink swap between check and use, or constrain a
malicious tool implementation. Use an OS/container sandbox and descriptor-based
file access for containment. Do not describe these checks as a filesystem
sandbox or remote-executor isolation.

## Session taint MVP

One proxy instance is one operator-owned agent/principal session. Calls are
serialized from check through upstream response. Immediately before forwarding
a labelled private source, the proxy conservatively marks the session private,
even if that request later fails or its response is lost. Any later labelled
external sink is BLOCKed as `TAINT_PRIVATE_TO_EXTERNAL`. A denied source does not
taint. Client-provided session ids, labels and metadata cannot clear the mark.
There is no in-session reset/declassification endpoint.

Only labelled tools are covered. This is coarse session state, not tracking of
actual bytes: harmless sends after a private read also block. It does not cover
unlabelled tools, direct upstream access, another proxy, or process restart.
State is in memory, not shared/durable; changing instances must be an operator
decision, not an agent escape hatch. The executor must be reachable only through
the proxy. This is not full prompt-injection prevention.

## What test-policy measures

The CLI uses the same argument evaluator as the proxy. Each configured rule is
tested independently so a missing second argument cannot hide a bypass. It
reports individual synthetic attacks, allowed controls, bypasses, false alarms,
and unavailable filesystem checks. Exit 1 means bypass, false alarm,
unverifiable state, or zero applicable cases; exit 2 means invalid input/usage.
A bypass is reported even if the policy deliberately permits that fixture's
origin. A missing root is not a successful containment test. No network calls
or file writes are made by the probes.

Local symlink fixtures, default loops, signed-request byte preservation,
concurrent source/sink ordering, source failures and denied-source behavior
are covered by regression tests. The CLI does not claim to evaluate these
stateful scenarios, real executor behavior, symlink races, or unconfigured
arguments. All-green synthetic probes are not a security certification.
