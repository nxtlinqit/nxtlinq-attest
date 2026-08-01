import { authorize } from '../guard.js';

/**
 * Language-neutral process boundary for hosts such as Buzz. stdout is a
 * structured decision; exit 0 means allow and exit 2 means deny.
 */
export function runAuthorize(cwd: string, capability: string | undefined): boolean {
  const decision = authorize({ capability: capability ?? '' }, { cwd });
  process.stdout.write(JSON.stringify(decision) + '\n');
  if (decision.outcome === 'deny') {
    process.exitCode = 2;
    return false;
  }
  return true;
}
