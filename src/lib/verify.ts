import { readFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { canonicalString } from './canonical.js';
import { computeArtifactHash, listArtifactFiles } from './artifact.js';
import { sha256Hex, verifyEd25519Hex } from './crypto.js';
import { assertRequiredFields, type AgentManifest } from './manifest.js';
import {
  assertCapabilities,
  type VerifiedCapability,
} from './capability.js';
import {
  publicKeyFingerprint,
  publicKeysEqual,
  type TrustedSigner,
  type TrustStore,
} from './trust.js';

const NXTLINQ_DIR = 'nxtlinq';
const MANIFEST_BASENAME = 'agent.manifest.json';
const SIG_BASENAME = 'agent.manifest.sig';
const PUBLIC_KEY_BASENAME = 'public.key';

export type AttestationVerificationCode =
  | 'file_missing'
  | 'manifest_invalid'
  | 'scope_empty'
  | 'manifest_integrity'
  | 'public_key_mismatch'
  | 'signature_invalid'
  | 'signer_untrusted'
  | 'signer_revoked'
  | 'manifest_expired'
  | 'audience_mismatch'
  | 'artifact_integrity';

export class AttestationVerificationError extends Error {
  constructor(
    public readonly code: AttestationVerificationCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'AttestationVerificationError';
  }
}

export interface VerifyAttestationOptions {
  projectRoot?: string;
  trustStore?: TrustStore;
  /**
   * Integrity-only compatibility mode. Never use this for authorization.
   * Secure callers should provide a trustStore and leave this false.
   */
  allowUntrustedSigner?: boolean;
  /** Require at least one scope entry. Defaults to true. */
  requireNonEmptyScope?: boolean;
  expectedAudience?: string;
  now?: Date;
}

export type VerifiedAgentManifest = Readonly<Omit<AgentManifest, 'scope' | 'capabilities' | 'aud'>> & {
  readonly scope: readonly string[];
  readonly capabilities?: readonly VerifiedCapability[];
  readonly aud?: string | readonly string[];
};

export interface VerifiedAttestation {
  readonly projectRoot: string;
  readonly manifest: VerifiedAgentManifest;
  readonly manifestDigest: string;
  readonly artifactDigest: string;
  readonly artifactFiles: readonly string[];
  readonly scope: readonly string[];
  readonly capabilities: readonly VerifiedCapability[];
  readonly signer: {
    readonly keyId: string;
    readonly fingerprint: string;
    readonly trusted: boolean;
  };
}

const trustedVerificationResults = new WeakSet<object>();

/** Internal runtime brand used to reject structurally forged verification data. */
export function isTrustedVerificationResult(
  value: unknown,
): value is VerifiedAttestation {
  return value !== null && typeof value === 'object' && trustedVerificationResults.has(value);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
}

function readRequired(path: string, label: string): string {
  try {
    return readFileSync(path, 'utf8');
  } catch (cause) {
    throw new AttestationVerificationError('file_missing', `${label} not found or unreadable`, { cause });
  }
}

function parseManifest(raw: string): AgentManifest {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch (cause) {
    throw new AttestationVerificationError('manifest_invalid', 'invalid JSON in agent.manifest.json', { cause });
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new AttestationVerificationError('manifest_invalid', 'agent.manifest.json must contain an object');
  }
  try {
    assertRequiredFields(value as Record<string, unknown>);
  } catch (cause) {
    throw new AttestationVerificationError(
      'manifest_invalid',
      cause instanceof Error ? cause.message : String(cause),
      { cause },
    );
  }
  const manifest = value as AgentManifest;
  for (const field of ['name', 'version', 'publicKey', 'contentHash', 'artifactHash'] as const) {
    if (typeof manifest[field] !== 'string' || manifest[field].length === 0) {
      throw new AttestationVerificationError('manifest_invalid', `${field} must be a non-empty string`);
    }
  }
  if (manifest.scope.some((entry) => typeof entry !== 'string' || entry.length === 0)) {
    throw new AttestationVerificationError(
      'manifest_invalid',
      'scope entries must be non-empty strings',
    );
  }
  if (manifest.capabilities !== undefined) {
    try {
      assertCapabilities(manifest.capabilities);
    } catch (cause) {
      throw new AttestationVerificationError(
        'manifest_invalid',
        cause instanceof Error ? cause.message : String(cause),
        { cause },
      );
    }
  }
  if (
    manifest.signerKeyId !== undefined &&
    (typeof manifest.signerKeyId !== 'string' || manifest.signerKeyId.length === 0)
  ) {
    throw new AttestationVerificationError(
      'manifest_invalid',
      'signerKeyId must be a non-empty string',
    );
  }
  if (
    !(
      (typeof manifest.issuedAt === 'number' && Number.isSafeInteger(manifest.issuedAt) && manifest.issuedAt >= 0) ||
      (typeof manifest.issuedAt === 'string' && manifest.issuedAt.length > 0)
    )
  ) {
    throw new AttestationVerificationError(
      'manifest_invalid',
      'issuedAt must be a non-negative Unix timestamp or non-empty string',
    );
  }
  if (!/^[0-9a-f]{64}$/.test(manifest.contentHash)) {
    throw new AttestationVerificationError('manifest_invalid', 'contentHash must be a lowercase SHA-256 hex digest');
  }
  if (!/^[0-9a-f]{64}$/.test(manifest.artifactHash)) {
    throw new AttestationVerificationError('manifest_invalid', 'artifactHash must be a lowercase SHA-256 hex digest');
  }
  if (
    manifest.artifactFileCount !== undefined &&
    (!Number.isSafeInteger(manifest.artifactFileCount) || manifest.artifactFileCount < 0)
  ) {
    throw new AttestationVerificationError(
      'manifest_invalid',
      'artifactFileCount must be a non-negative safe integer',
    );
  }
  if (manifest.aud !== undefined) {
    const validAudience =
      (typeof manifest.aud === 'string' && manifest.aud.length > 0) ||
      (Array.isArray(manifest.aud) &&
        manifest.aud.length > 0 &&
        manifest.aud.every((item) => typeof item === 'string' && item.length > 0));
    if (!validAudience) {
      throw new AttestationVerificationError(
        'manifest_invalid',
        'aud must be a non-empty string or non-empty string array',
      );
    }
  }
  return manifest;
}

function findTrustedSigner(keyId: string, signers: readonly TrustedSigner[]): TrustedSigner | undefined {
  const matches = signers.filter((signer) => signer.keyId === keyId);
  if (matches.length > 1) {
    throw new AttestationVerificationError(
      'signer_untrusted',
      `trust store contains duplicate signer keyId: ${keyId}`,
    );
  }
  return matches[0];
}

function verifyTimeAndAudience(manifest: AgentManifest, options: VerifyAttestationOptions): void {
  if (manifest.exp !== undefined) {
    if (!Number.isSafeInteger(manifest.exp) || manifest.exp < 0) {
      throw new AttestationVerificationError(
        'manifest_invalid',
        'exp must be a non-negative safe-integer Unix timestamp',
      );
    }
    const now = options.now ?? new Date();
    if (!Number.isFinite(now.getTime())) {
      throw new AttestationVerificationError('manifest_invalid', 'verification time must be valid');
    }
    const nowSeconds = Math.floor(now.getTime() / 1000);
    if (manifest.exp <= nowSeconds) {
      throw new AttestationVerificationError('manifest_expired', 'manifest has expired');
    }
  }
  if (options.expectedAudience !== undefined) {
    const audiences = typeof manifest.aud === 'string'
      ? [manifest.aud]
      : Array.isArray(manifest.aud) && manifest.aud.every((item) => typeof item === 'string')
        ? manifest.aud
        : [];
    if (!audiences.includes(options.expectedAudience)) {
      throw new AttestationVerificationError(
        'audience_mismatch',
        `manifest audience does not include ${options.expectedAudience}`,
      );
    }
  }
}

/**
 * Fully verify a signed project attestation and return an immutable authorization input.
 * With a trust store, signerKeyId selects the authoritative external public key.
 * Without one, allowUntrustedSigner explicitly enables local public.key verification.
 */
export function verifyAttestation(options: VerifyAttestationOptions = {}): VerifiedAttestation {
  const projectRoot = resolve(options.projectRoot ?? process.cwd());
  const nxtlinqPath = join(projectRoot, NXTLINQ_DIR);
  const manifestRaw = readRequired(join(nxtlinqPath, MANIFEST_BASENAME), MANIFEST_BASENAME);
  const signatureHex = readRequired(join(nxtlinqPath, SIG_BASENAME), SIG_BASENAME).trim();
  const manifest = parseManifest(manifestRaw);

  if (!/^[0-9a-f]{128}$/.test(signatureHex)) {
    throw new AttestationVerificationError(
      'signature_invalid',
      'manifest signature must be a lowercase Ed25519 hex signature',
    );
  }

  if ((options.requireNonEmptyScope ?? true) && manifest.scope.length === 0) {
    throw new AttestationVerificationError('scope_empty', 'manifest scope must not be empty');
  }

  let verificationPublicKeyPem: string;
  let trustedSigner: TrustedSigner | undefined;
  if (options.trustStore !== undefined) {
    if (manifest.signerKeyId === undefined) {
      throw new AttestationVerificationError(
        'signer_untrusted',
        'manifest signerKeyId is required when a trust store is configured',
      );
    }
    trustedSigner = findTrustedSigner(manifest.signerKeyId, options.trustStore.trustedSigners);
    if (!trustedSigner) {
      throw new AttestationVerificationError(
        'signer_untrusted',
        `manifest signer ${manifest.signerKeyId} is not present in the configured trust store`,
      );
    }
    if (trustedSigner.revoked) {
      throw new AttestationVerificationError(
        'signer_revoked',
        `manifest signer ${trustedSigner.keyId} is revoked`,
      );
    }
    verificationPublicKeyPem = trustedSigner.publicKey;
  } else {
    const localPublicKeyPem = readRequired(join(nxtlinqPath, PUBLIC_KEY_BASENAME), PUBLIC_KEY_BASENAME);
    try {
      if (!publicKeysEqual(manifest.publicKey, localPublicKeyPem)) {
        throw new AttestationVerificationError(
          'public_key_mismatch',
          'manifest publicKey does not match nxtlinq/public.key',
        );
      }
    } catch (cause) {
      if (cause instanceof AttestationVerificationError) throw cause;
      throw new AttestationVerificationError(
        'manifest_invalid',
        'manifest or nxtlinq/public.key contains an invalid public key',
        { cause },
      );
    }
    verificationPublicKeyPem = localPublicKeyPem;
  }

  const { contentHash: _drop, ...manifestForHash } = manifest;
  const computedContentHash = sha256Hex(canonicalString(manifestForHash));
  if (computedContentHash !== manifest.contentHash) {
    throw new AttestationVerificationError(
      'manifest_integrity',
      'manifest integrity check failed (contentHash mismatch)',
    );
  }
  try {
    if (!verifyEd25519Hex(manifest.contentHash, signatureHex, verificationPublicKeyPem)) {
      throw new AttestationVerificationError('signature_invalid', 'invalid manifest signature');
    }
  } catch (cause) {
    if (cause instanceof AttestationVerificationError) throw cause;
    throw new AttestationVerificationError('signature_invalid', 'invalid manifest signature', { cause });
  }

  let fingerprint: string;
  try {
    fingerprint = publicKeyFingerprint(verificationPublicKeyPem);
  } catch (cause) {
    throw new AttestationVerificationError(
      trustedSigner ? 'signer_untrusted' : 'manifest_invalid',
      trustedSigner
        ? `trusted signer ${trustedSigner.keyId} contains an invalid public key`
        : 'nxtlinq/public.key is invalid',
      { cause },
    );
  }
  if (
    !trustedSigner &&
    (options.trustStore !== undefined || options.allowUntrustedSigner !== true)
  ) {
    throw new AttestationVerificationError(
      'signer_untrusted',
      'manifest signer is not present in the configured trust store',
    );
  }
  verifyTimeAndAudience(manifest, options);

  let artifactFiles: string[];
  let artifactDigest: string;
  try {
    artifactFiles = listArtifactFiles(projectRoot);
    artifactDigest = computeArtifactHash(projectRoot, artifactFiles);
  } catch (cause) {
    throw new AttestationVerificationError(
      'artifact_integrity',
      `artifact verification failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
  if (artifactDigest !== manifest.artifactHash) {
    throw new AttestationVerificationError(
      'artifact_integrity',
      'artifact integrity check failed (artifactHash mismatch)',
    );
  }
  if (manifest.artifactFileCount !== undefined && artifactFiles.length !== manifest.artifactFileCount) {
    throw new AttestationVerificationError(
      'artifact_integrity',
      `artifact file count mismatch (expected ${manifest.artifactFileCount}, got ${artifactFiles.length})`,
    );
  }

  const result = deepFreeze({
    projectRoot,
    manifest: deepFreeze(manifest) as VerifiedAgentManifest,
    manifestDigest: manifest.contentHash,
    artifactDigest,
    artifactFiles,
    scope: Object.freeze([...manifest.scope]),
    capabilities: deepFreeze(
      (manifest.capabilities ?? []).map((capability) => ({ ...capability })),
    ) as readonly VerifiedCapability[],
    signer: {
      keyId: trustedSigner?.keyId ?? fingerprint,
      fingerprint,
      trusted: trustedSigner !== undefined,
    },
  });
  if (trustedSigner) trustedVerificationResults.add(result);
  return result;
}
