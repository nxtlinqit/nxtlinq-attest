/**
 * Output manifest scope as JSON to stdout for use by any runtime (Node, Python, etc.).
 * Exit 0 with scope array on success; exit 1 and stderr message on missing/invalid manifest.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AgentManifest } from '../lib/manifest.js';

const NXTLINQ_DIR = 'nxtlinq';
const MANIFEST_BASENAME = 'agent.manifest.json';

export function runScope(cwd: string): void {
  const manifestPath = join(cwd, NXTLINQ_DIR, MANIFEST_BASENAME);

  let raw: string;
  try {
    raw = readFileSync(manifestPath, 'utf8');
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === 'ENOENT') {
      console.error('Error:', join(NXTLINQ_DIR, MANIFEST_BASENAME), 'not found.');
    } else {
      console.error('Error reading manifest:', (e as Error).message);
    }
    process.exit(1);
  }

  let manifest: AgentManifest;
  try {
    manifest = JSON.parse(raw) as AgentManifest;
  } catch {
    console.error('Error: invalid JSON in', join(NXTLINQ_DIR, MANIFEST_BASENAME));
    process.exit(1);
  }

  const scope = Array.isArray(manifest.scope) ? manifest.scope : [];
  process.stdout.write(JSON.stringify(scope) + '\n');
}
