# ACP enforcement integration

This document describes the smallest enforcement path between an ACP host and
the existing nxtlinq attest verification and signed-scope primitives. It does
not claim that ACP contains an agent or controls operations that never cross an
ACP permission boundary.

## Concrete host hook

ACP agents can send `session/request_permission` before a protected tool call.
The host must answer with one of the option identifiers supplied by the agent.
Selecting an option whose kind is `reject_once` prevents a conforming agent
from performing that requested operation. Selecting `allow_once` permits it.

Buzz already receives this request in
`AcpClient::handle_permission_request`. At the time of this proposal, Buzz
automatically selects `allow_once`. That method is the narrow integration point:

```text
ACP agent
  | session/request_permission (pending tool call)
  v
Buzz AcpClient::handle_permission_request
  | map observable tool kind to existing capability, e.g. tool:write
  v
nxtlinq-attest authorize tool:write
  | verify signed manifest + covered artifacts
  | evaluate exact capability against signed manifest scope
  v
ALLOW -> select ACP allow_once option -> agent continues
DENY  -> select ACP reject_once option -> agent does not execute the call
```

The CLI is a language-neutral integration seam for a Rust host:

```bash
nxtlinq-attest authorize tool:write
```

It prints one JSON decision to stdout. Exit status `0` means allow; exit status
`2` means deny. The decision references existing verifiable evidence through
the signed manifest and artifact digests. It is not a separately signed
decision receipt; the repository does not yet expose that primitive.

## Minimal capability mapping

The first integration should map only operations that the ACP agent actually
submits for permission:

| Observable ACP tool kind | Existing manifest capability |
| --- | --- |
| edit or filesystem write | `tool:write` |
| execute or terminal command | `tool:exec` |

Do not infer path-level or argument-level authorization from the current
manifest vocabulary. Add such restrictions only when the authoritative core
defines and enforces them.

## Host enforcement requirement

The host integration must dynamically choose the option whose `kind` is
`allow_once` or `reject_once`; it must never hardcode protocol-specific option
identifiers. A deny decision must choose `reject_once` and must not invoke any
host-side protected downstream handler.

The exported `executeIfAuthorized()` helper encodes the same invariant for
in-process TypeScript hosts and tests: the downstream callback is invoked only
after an allow decision.

## Evidence behavior

Allow and out-of-scope decisions include:

- verified manifest name and version;
- manifest content digest;
- covered artifact digest;
- covered artifact file count, when present; and
- the exact requested capability and decision code.

Raw command arguments, file contents, environment variables, private keys, and
secret values are not included. A future integration may replace or augment
this evidence reference with an existing nxtlinq decision-receipt API when one
is exposed publicly.

## Enforcement boundaries

This guard does not control:

- filesystem or subprocess activity that an agent performs without an ACP
  `session/request_permission` request;
- direct network access that does not cross the guarded host boundary;
- MCP calls routed through a separate unguarded server;
- an agent configured to bypass permission requests;
- runtime activity after an allowed terminal command starts; or
- path- or argument-level restrictions not represented by the signed scope.

Stronger containment requires host/runtime controls such as filesystem and
shell wrappers, containers, network policy, MCP middleware, or OS sandboxing.
