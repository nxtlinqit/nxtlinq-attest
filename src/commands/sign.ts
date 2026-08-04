import { readFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { derivePublicKeyPem } from '../lib/crypto.js';
import { publicKeysEqual } from '../lib/trust.js';
import { signAttestation } from '../lib/sign.js';
import { createEd25519PrivateKeySigner } from '../lib/signer.js';

const NXTLINQ_DIR = 'nxtlinq';
const PRIVATE_KEY_BASENAME = 'private.key';
const PUBLIC_KEY_BASENAME = 'public.key';

export interface SignCommandOptions {
  privateKeyPath?: string;
}

function readKey(path: string, label: string): string {
  try {
    return readFileSync(path, 'utf8');
  } catch (cause) {
    const error = cause as NodeJS.ErrnoException;
    if (error.code === 'ENOENT') throw new Error(`${label} not found`, { cause });
    throw new Error(`${label} is unreadable`, { cause });
  }
}

export async function runSign(cwd: string, options: SignCommandOptions = {}): Promise<void> {
  const projectRoot = resolve(cwd);
  const privateKeyPath = options.privateKeyPath === undefined
    ? join(projectRoot, NXTLINQ_DIR, PRIVATE_KEY_BASENAME)
    : isAbsolute(options.privateKeyPath)
      ? options.privateKeyPath
      : resolve(projectRoot, options.privateKeyPath);
  const publicKeyPath = join(projectRoot, NXTLINQ_DIR, PUBLIC_KEY_BASENAME);
  const privateKeyPem = readKey(
    privateKeyPath,
    options.privateKeyPath === undefined
      ? join(NXTLINQ_DIR, PRIVATE_KEY_BASENAME)
      : `private key ${privateKeyPath}`,
  );
  const publicKeyPem = readKey(publicKeyPath, join(NXTLINQ_DIR, PUBLIC_KEY_BASENAME));

  try {
    const derivedPublicKeyPem = derivePublicKeyPem(privateKeyPem);
    if (!publicKeysEqual(derivedPublicKeyPem, publicKeyPem)) {
      throw new Error('private key does not match nxtlinq/public.key');
    }
  } catch (error) {
    throw new Error(
      `Cannot use signing key: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }

  const keyLabel = options.privateKeyPath === undefined ? 'local-project-key' : privateKeyPath;
  const result = await signAttestation({
    projectRoot,
    signer: createEd25519PrivateKeySigner(privateKeyPem, keyLabel),
  });

  console.log('Signed manifest and artifact.');
  console.log('  contentHash:', result.contentHash.slice(0, 16) + '...');
  console.log('  artifactHash:', result.artifactHash.slice(0, 16) + '...');
  console.log('  artifactFileCount:', result.artifactFileCount);
  console.log('  signer:', result.signerKeyId);
  console.log('  signature:', join(NXTLINQ_DIR, 'agent.manifest.sig'));
}
