# Minimal MCP gateway adapter

This example shows the intended protocol-neutral seam. It is deliberately not
a complete MCP server or a second policy engine.

An MCP gateway maps an observable operation into the signed Nxtlinq capability
vocabulary, calls `authorize()`, and forwards the operation only after an
`allow` decision.

```ts
import { withAuthorization } from '@nxtlinq/attest';

type McpToolCall = {
  name: string;
  sessionId?: string;
  resource?: string;
};

const capabilityByTool: Record<string, string> = {
  write_file: 'tool:write',
  execute_command: 'tool:exec',
};

export async function guardMcpToolCall<T>(
  call: McpToolCall,
  invokeDownstream: () => Promise<T>,
) {
  const capability = capabilityByTool[call.name];

  if (capability == null) {
    return {
      decision: {
        outcome: 'deny',
        reason: 'capability_not_in_scope',
        capability: `mcp:${call.name}`,
      },
    };
  }

  return withAuthorization(
    {
      capability,
      protocol: 'mcp',
      sessionId: call.sessionId,
      resource: call.resource,
    },
    invokeDownstream,
  );
}
```

The important invariant is:

> A denied or unverifiable request never invokes the downstream handler.

The adapter owns protocol mapping. Nxtlinq remains authoritative for signed
manifest verification, artifact verification, and capability scope.
