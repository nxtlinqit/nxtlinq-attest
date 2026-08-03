import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalString } from './lib/canonical.js';
import { sha256Hex, verifyEd25519Hex } from './lib/crypto.js';
import { listArtifactFiles, computeArtifactHash } from './lib/artifact.js';
import { assertRequiredFields, type AgentManifest } from './lib/manifest.js';

const NXTLINQ_DIR = 'nxtlinq';
const MANIFEST_BASENAME = 'agent.manifest.json';
const SIG_BASENAME = 'agent.manifest.sig';
const PUBLIC_KEY_BASENAME = 'public.key';

export type AuthorizationOutcome = 'allow' | 'deny';

export interface AuthorizationRequest {
  /**
   * Capability from the signed manifest scope, for example `tool:write`.
   * Bare names are normalized to the `tool:` namespace.
   */
  capability: string;
  /**
   * Project root containing the `nxtlinq/` directory.
   * Defaults to process.cwd().
   */
  cwd?: string;
  /**
   * Optional protocol metadata for evidence and adapters.
   * It does not affect authorization semantics.
   */
  protocol?: string;
  sessionId?: string;
  resource?: string;
}

export interface AuthorizationEvidence {
  manifestDigest: string;
  artifactDigest: string;
  protocol?: string;
  sessionId?: string;
  resource?: string;
}

export interface AuthorizationDecision {
  outcome: AuthorizationOutcome;
  reason:
    | 'authorized'
    | 'capability_not_in_scope'
    | 'invalid_request'
    | 'manifest_unavailable'
    | 'invalid_manifest'
    | 'manifest_integrity_failed'
    | 'invalid_signature'
    | 'artifact_integrity_failed'
    | 'artifact_file_count_mismatch'
    | 'verification_failed';
  capability: string;
  evidence?: AuthorizationEvidence;
}

type VerificationSuccess = {
  ok: true;
  manifest: AgentManifest;
  manifestDigest: string;
  artifactDigest: string;
};

type VerificationFailure = {
  ok: false;
  reason: AuthorizationDecision['reason'];
};

type VerificationResult = VerificationSuccess | VerificationFailure;

function normalizeCapability(capability: string): string {
  const value = capability.trim();
  if (value.length === 0) return '';
  return value.includes(':') ? value : `tool:${value}`;
}

/**
 * Verify the signed manifest and covered artifact without writing output or
 * terminating the process. This is intentionally separate from the existing
 * human-oriented `verify` command.
 */
export function verifyAuthorizationContext(cwd = process.cwd()): VerificationResult {
  const nxtlinqPath = join(cwd, NXTLINQ_DIR);
  const manifestPath = join(nxtlinqPath, MANIFEST_BASENAME);
  const sigPath = join(nxtlinqPath, SIG_BASENAME);
  const publicKeyPath = join(nxtlinqPath, PUBLIC_KEY_BASENAME);

  let manifestRaw: string;
  let signatureHex: string;
  let publicKeyPem: string;

  try {
    manifestRaw = readFileSync(manifestPath, 'utf8');
    signatureHex = readFileSync(sigPath, 'utf8').trim();
    publicKeyPem = readFileSync(publicKeyPath, 'utf8');
  } catch {
    return { ok: false, reason: 'manifest_unavailable' };
  }

  let manifestRecord: Record<string, unknown>;
  try {
    manifestRecord = JSON.parse(manifestRaw) as Record<string, unknown>;
    assertRequiredFields(manifestRecord);
  } catch {
    return { ok: false, reason: 'invalid_manifest' };
  }

  const manifest = manifestRecord as AgentManifest;

  try {
    const { contentHash: _drop, ...manifestForHash } = manifest;
    const computedContentHash = sha256Hex(canonicalString(manifestForHash));

    if (computedContentHash !== manifest.contentHash) {
      return { ok: false, reason: 'manifest_integrity_failed' };
    }

    if (!verifyEd25519Hex(manifest.contentHash, signatureHex, publicKeyPem)) {
      return { ok: false, reason: 'invalid_signature' };
    }

    const artifactFiles = listArtifactFiles(cwd);
    const computedArtifactHash = computeArtifactHash(cwd, artifactFiles);

    if (computedArtifactHash !== manifest.artifactHash) {
      return { ok: false, reason: 'artifact_integrity_failed' };
    }

    if (
      manifest.artifactFileCount != null &&
      artifactFiles.length !== manifest.artifactFileCount
    ) {
      return { ok: false, reason: 'artifact_file_count_mismatch' };
    }

    return {
      ok: true,
      manifest,
      manifestDigest: manifest.contentHash,
      artifactDigest: manifest.artifactHash,
    };
  } catch {
    return { ok: false, reason: 'verification_failed' };
  }
}

/**
 * Produce one fail-closed authorization decision from the signed Nxtlinq
 * context. Protocol adapters should call this function before forwarding a
 * protected operation.
 */
export function authorize(request: AuthorizationRequest): AuthorizationDecision {
  const capability = normalizeCapability(request.capability);

  if (capability.length === 0) {
    return {
      outcome: 'deny',
      reason: 'invalid_request',
      capability,
    };
  }

  const verification = verifyAuthorizationContext(request.cwd);

  if (!verification.ok) {
    return {
      outcome: 'deny',
      reason: verification.reason,
      capability,
    };
  }

  const allowed = verification.manifest.scope.includes(capability);

  return {
    outcome: allowed ? 'allow' : 'deny',
    reason: allowed ? 'authorized' : 'capability_not_in_scope',
    capability,
    evidence: {
      manifestDigest: verification.manifestDigest,
      artifactDigest: verification.artifactDigest,
      ...(request.protocol ? { protocol: request.protocol } : {}),
      ...(request.sessionId ? { sessionId: request.sessionId } : {}),
      ...(request.resource ? { resource: request.resource } : {}),
    },
  };
}

/**
 * Guard a downstream operation. The handler is never invoked unless the
 * authorization decision is `allow`.
 */
export async function withAuthorization<T>(
  request: AuthorizationRequest,
  handler: () => T | Promise<T>,
): Promise<{ decision: AuthorizationDecision; value?: T }> {
  const decision = authorize(request);

  if (decision.outcome !== 'allow') {
    return { decision };
  }

  return {
    decision,
    value: await handler(),
  };
}
