import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { computeArtifactHash, listArtifactFiles } from './artifact.js';
import { canonicalString } from './canonical.js';
import { assertCapabilities } from './capability.js';
import { sha256Hex, verifyEd25519Hex } from './crypto.js';
import type { AgentManifest } from './manifest.js';
import type { AttestationSigner } from './signer.js';
import { publicKeysEqual } from './trust.js';
import { getCliVersion } from './version.js';

const NXTLINQ_DIR = 'nxtlinq';
const MANIFEST_BASENAME = 'agent.manifest.json';
const SIG_BASENAME = 'agent.manifest.sig';
const PUBLIC_KEY_BASENAME = 'public.key';

export interface SignAttestationOptions {
  projectRoot?: string;
  signer: AttestationSigner;
}

export interface SignedAttestation {
  readonly projectRoot: string;
  readonly contentHash: string;
  readonly artifactHash: string;
  readonly artifactFileCount: number;
  readonly signaturePath: string;
  readonly signerKeyId: string;
}

function readRequired(path: string, label: string): string {
  try {
    return readFileSync(path, 'utf8');
  } catch (cause) {
    const error = cause as NodeJS.ErrnoException;
    if (error.code === 'ENOENT') {
      throw new Error(`${label} not found`, { cause });
    }
    throw new Error(`${label} is unreadable`, { cause });
  }
}

function parseAndValidateManifest(raw: string): AgentManifest {
  let manifest: AgentManifest;
  try {
    manifest = JSON.parse(raw) as AgentManifest;
  } catch (cause) {
    throw new Error('agent.manifest.json contains invalid JSON', { cause });
  }
  if (
    manifest === null ||
    typeof manifest !== 'object' ||
    Array.isArray(manifest) ||
    typeof manifest.name !== 'string' ||
    manifest.name.length === 0 ||
    typeof manifest.version !== 'string' ||
    manifest.version.length === 0 ||
    !Array.isArray(manifest.scope) ||
    manifest.scope.length === 0 ||
    manifest.scope.some((entry) => typeof entry !== 'string' || entry.length === 0)
  ) {
    throw new Error('manifest must have a name, version, and non-empty string scope');
  }
  if (manifest.capabilities !== undefined) {
    try {
      assertCapabilities(manifest.capabilities);
    } catch (cause) {
      throw new Error(
        `manifest capabilities are invalid: ${cause instanceof Error ? cause.message : String(cause)}`,
        { cause },
      );
    }
  }
  if (
    manifest.signerKeyId !== undefined &&
    (typeof manifest.signerKeyId !== 'string' || manifest.signerKeyId.length === 0)
  ) {
    throw new Error('manifest signerKeyId must be a non-empty string');
  }
  return manifest;
}

/**
 * Compute and sign an attestation using a caller-provided signing boundary.
 * The signer sees only the contentHash bytes. Files are written only after the
 * returned signature has been verified against nxtlinq/public.key.
 */
export async function signAttestation(
  options: SignAttestationOptions,
): Promise<SignedAttestation> {
  if (
    options.signer === null ||
    typeof options.signer !== 'object' ||
    typeof options.signer.keyId !== 'string' ||
    options.signer.keyId.length === 0 ||
    typeof options.signer.signDigest !== 'function'
  ) {
    throw new Error('signer must provide a non-empty keyId and signDigest function');
  }

  const projectRoot = resolve(options.projectRoot ?? process.cwd());
  const nxtlinqPath = join(projectRoot, NXTLINQ_DIR);
  const manifestPath = join(nxtlinqPath, MANIFEST_BASENAME);
  const publicKeyPath = join(nxtlinqPath, PUBLIC_KEY_BASENAME);
  const signaturePath = join(nxtlinqPath, SIG_BASENAME);
  const manifest = parseAndValidateManifest(
    readRequired(manifestPath, join(NXTLINQ_DIR, MANIFEST_BASENAME)),
  );
  const publicKeyPem = readRequired(
    publicKeyPath,
    join(NXTLINQ_DIR, PUBLIC_KEY_BASENAME),
  );

  if (manifest.publicKey == null || manifest.publicKey === '') {
    manifest.publicKey = publicKeyPem.trim();
  } else {
    try {
      if (!publicKeysEqual(manifest.publicKey, publicKeyPem)) {
        throw new Error('manifest publicKey does not match nxtlinq/public.key');
      }
    } catch (cause) {
      if (cause instanceof Error && cause.message === 'manifest publicKey does not match nxtlinq/public.key') {
        throw cause;
      }
      throw new Error('manifest or nxtlinq/public.key is invalid', { cause });
    }
  }

  const artifactFiles = listArtifactFiles(projectRoot);
  manifest.artifactHash = computeArtifactHash(projectRoot, artifactFiles);
  manifest.artifactFileCount = artifactFiles.length;
  manifest.issuedAt = Math.floor(Date.now() / 1000);
  manifest.attestCliVersion = getCliVersion();

  const { contentHash: _drop, ...manifestForHash } = manifest;
  manifest.contentHash = sha256Hex(canonicalString(manifestForHash));
  const digest = Buffer.from(manifest.contentHash, 'utf8');

  let signatureHex: string;
  try {
    signatureHex = await options.signer.signDigest(digest);
  } catch (cause) {
    throw new Error(`signer ${options.signer.keyId} failed`, { cause });
  }
  if (typeof signatureHex !== 'string' || !/^[0-9a-f]{128}$/.test(signatureHex)) {
    throw new Error(`signer ${options.signer.keyId} returned an invalid Ed25519 signature`);
  }
  try {
    if (!verifyEd25519Hex(manifest.contentHash, signatureHex, publicKeyPem)) {
      throw new Error(`signer ${options.signer.keyId} does not match nxtlinq/public.key`);
    }
  } catch (cause) {
    if (cause instanceof Error && cause.message.startsWith('signer ')) throw cause;
    throw new Error('nxtlinq/public.key is invalid', { cause });
  }

  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
  writeFileSync(signaturePath, signatureHex, { encoding: 'utf8', mode: 0o600 });

  return Object.freeze({
    projectRoot,
    contentHash: manifest.contentHash,
    artifactHash: manifest.artifactHash,
    artifactFileCount: artifactFiles.length,
    signaturePath,
    signerKeyId: options.signer.keyId,
  });
}
