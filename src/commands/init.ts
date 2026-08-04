import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { generateEd25519KeyPair } from '../lib/crypto.js';
import { publicKeyFingerprint } from '../lib/trust.js';
import { getCliVersion } from '../lib/version.js';

const NXTLINQ_DIR = 'nxtlinq';
const MANIFEST_BASENAME = 'agent.manifest.json';

export interface InitCommandOptions {
  publicKeyPath?: string;
  keyId?: string;
}

export function runInit(cwd: string, options: InitCommandOptions = {}): void {
  if ((options.publicKeyPath === undefined) !== (options.keyId === undefined)) {
    throw new Error('--public-key and --key-id must be provided together');
  }
  if (options.keyId !== undefined && options.keyId.trim().length === 0) {
    throw new Error('--key-id must be a non-empty value');
  }

  const projectRoot = resolve(cwd);
  const nxtlinqPath = join(projectRoot, NXTLINQ_DIR);
  const privateKeyPath = join(nxtlinqPath, 'private.key');
  let privateKeyPem: string | undefined;
  let publicKeyPem: string;

  if (options.publicKeyPath === undefined) {
    ({ privateKeyPem, publicKeyPem } = generateEd25519KeyPair());
  } else {
    const sourcePath = isAbsolute(options.publicKeyPath)
      ? options.publicKeyPath
      : resolve(projectRoot, options.publicKeyPath);
    try {
      publicKeyPem = readFileSync(sourcePath, 'utf8');
      publicKeyFingerprint(publicKeyPem);
    } catch (cause) {
      throw new Error(`Cannot use public key ${sourcePath}`, { cause });
    }
    if (existsSync(privateKeyPath)) {
      throw new Error(
        `${join(NXTLINQ_DIR, 'private.key')} already exists; remove or relocate it before public-key-only initialization`,
      );
    }
  }

  mkdirSync(nxtlinqPath, { recursive: true });

  if (privateKeyPem !== undefined) {
    writeFileSync(privateKeyPath, privateKeyPem, { mode: 0o600 });
  }
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
    ...(options.keyId === undefined ? {} : { signerKeyId: options.keyId }),
  };
  const manifestPath = join(nxtlinqPath, MANIFEST_BASENAME);
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

  console.log('Initialized nxtlinq attest in', projectRoot);
  if (privateKeyPem !== undefined) {
    console.log('  -', join(NXTLINQ_DIR, 'private.key'), '(do not commit)');
  } else {
    console.log('  - public-key-only identity:', options.keyId);
  }
  console.log('  -', join(NXTLINQ_DIR, 'public.key'));
  console.log('  -', join(NXTLINQ_DIR, MANIFEST_BASENAME));
  console.log('');
  console.log('Next: edit', join(NXTLINQ_DIR, MANIFEST_BASENAME), '— set name, version, and scope (see README). Then run: nxtlinq-attest sign');
}
