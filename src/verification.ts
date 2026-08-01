import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalString } from './lib/canonical.js';
import { sha256Hex, verifyEd25519Hex } from './lib/crypto.js';
import { listArtifactFiles, computeArtifactHash } from './lib/artifact.js';
import { assertRequiredFields, type AgentManifest } from './lib/manifest.js';

const NXTLINQ_DIR = 'nxtlinq';
const MANIFEST_BASENAME = 'agent.manifest.json';
const SIG_BASENAME = 'agent.manifest.sig';

export interface VerificationEvidence {
  name: string;
  version: string;
  scope: string[];
  manifestDigest: string;
  artifactDigest: string;
  artifactFileCount?: number;
}

export type VerificationFailureCode =
  | 'missing_attestation_file'
  | 'invalid_manifest'
  | 'manifest_digest_mismatch'
  | 'invalid_signature'
  | 'artifact_digest_mismatch'
  | 'artifact_file_count_mismatch';

export type ProjectVerification =
  | { ok: true; manifest: AgentManifest; evidence: VerificationEvidence }
  | { ok: false; code: VerificationFailureCode; reason: string };

/**
 * Verify the signed manifest and covered project artifacts without terminating
 * the host process. This is the programmatic form of `nxtlinq-attest verify`.
 */
export function verifyProject(cwd: string): ProjectVerification {
  const nxtlinqPath = join(cwd, NXTLINQ_DIR);

  let manifestRaw: string;
  let signatureHex: string;
  let publicKeyPem: string;
  try {
    manifestRaw = readFileSync(join(nxtlinqPath, MANIFEST_BASENAME), 'utf8');
    signatureHex = readFileSync(join(nxtlinqPath, SIG_BASENAME), 'utf8').trim();
    publicKeyPem = readFileSync(join(nxtlinqPath, 'public.key'), 'utf8');
  } catch (error) {
    return {
      ok: false,
      code: 'missing_attestation_file',
      reason: `Unable to read required attestation files: ${(error as Error).message}`,
    };
  }

  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(manifestRaw) as Record<string, unknown>;
    assertRequiredFields(manifest);
  } catch (error) {
    return {
      ok: false,
      code: 'invalid_manifest',
      reason: (error as Error).message,
    };
  }

  const typedManifest = manifest as AgentManifest;
  const { contentHash: _drop, ...manifestForHash } = typedManifest;
  const computedContentHash = sha256Hex(canonicalString(manifestForHash));
  if (computedContentHash !== typedManifest.contentHash) {
    return {
      ok: false,
      code: 'manifest_digest_mismatch',
      reason: 'Manifest integrity check failed.',
    };
  }

  if (!verifyEd25519Hex(typedManifest.contentHash, signatureHex, publicKeyPem)) {
    return { ok: false, code: 'invalid_signature', reason: 'Manifest signature is invalid.' };
  }

  const artifactFiles = listArtifactFiles(cwd);
  const computedArtifactHash = computeArtifactHash(cwd, artifactFiles);
  if (computedArtifactHash !== typedManifest.artifactHash) {
    return {
      ok: false,
      code: 'artifact_digest_mismatch',
      reason: 'Covered project artifacts have changed since signing.',
    };
  }
  if (
    typedManifest.artifactFileCount != null &&
    artifactFiles.length !== typedManifest.artifactFileCount
  ) {
    return {
      ok: false,
      code: 'artifact_file_count_mismatch',
      reason: 'Covered project artifact count has changed since signing.',
    };
  }

  return {
    ok: true,
    manifest: typedManifest,
    evidence: {
      name: typedManifest.name,
      version: typedManifest.version,
      scope: [...typedManifest.scope],
      manifestDigest: typedManifest.contentHash,
      artifactDigest: typedManifest.artifactHash,
      artifactFileCount: typedManifest.artifactFileCount,
    },
  };
}
