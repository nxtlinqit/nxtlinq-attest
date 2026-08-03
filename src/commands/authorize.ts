import { authorize } from '../authorization.js';

export function runAuthorize(cwd: string, capability?: string): never {
  if (capability == null || capability.trim().length === 0) {
    console.error(
      JSON.stringify({
        outcome: 'deny',
        reason: 'invalid_request',
        capability: '',
      }),
    );
    process.exit(1);
  }

  const decision = authorize({ capability, cwd });
  console.log(JSON.stringify(decision));

  process.exit(decision.outcome === 'allow' ? 0 : 2);
}
