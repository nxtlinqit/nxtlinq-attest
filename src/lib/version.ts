/**
 * Read nxtlinq-attest CLI version from package.json (relative to this module).
 * When installed, dist/lib/version.js lives under package root, so ../../package.json.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

let cached: string | undefined;

export function getCliVersion(): string {
  if (cached !== undefined) return cached;
  try {
    const pkgPath = join(__dirname, '..', '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version?: string };
    cached = typeof pkg.version === 'string' ? pkg.version : '0.0.0';
  } catch {
    cached = '0.0.0';
  }
  return cached;
}
