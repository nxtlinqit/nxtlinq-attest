import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateEd25519KeyPair } from '../lib/crypto.js';
import { getCliVersion } from '../lib/version.js';

const NXTLINQ_DIR = 'nxtlinq';
const MANIFEST_BASENAME = 'agent.manifest.json';

export function runInit(cwd: string): void {
  const nxtlinqPath = join(cwd, NXTLINQ_DIR);
  mkdirSync(nxtlinqPath, { recursive: true });

  const { privateKeyPem, publicKeyPem } = generateEd25519KeyPair();
  writeFileSync(join(nxtlinqPath, 'private.key'), privateKeyPem, { mode: 0o600 });
  writeFileSync(join(nxtlinqPath, 'public.key'), publicKeyPem);

  const manifest: Record<string, unknown> = {
    name: 'my-agent',
    version: '1.0.0',
    scope: ['tool:ExampleTool'],
    issuedAt: Math.floor(Date.now() / 1000),
    publicKey: publicKeyPem.trim(),
    contentHash: '<set by attest sign>',
    artifactHash: '<set by attest sign>',
    attestCliVersion: getCliVersion(),
  };
  const manifestPath = join(nxtlinqPath, MANIFEST_BASENAME);
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

  console.log('Initialized nxtlinq attest in', cwd);
  console.log('  -', join(NXTLINQ_DIR, 'private.key'), '(do not commit)');
  console.log('  -', join(NXTLINQ_DIR, 'public.key'));
  console.log('  -', join(NXTLINQ_DIR, MANIFEST_BASENAME));
  console.log('');
  console.log('Next: edit', join(NXTLINQ_DIR, MANIFEST_BASENAME), '— set name, version, and scope (see README). Then run: nxtlinq-attest sign');
}
