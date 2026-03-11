import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalString } from '../lib/canonical.js';
import { sha256Hex, verifyEd25519Hex } from '../lib/crypto.js';
import { listArtifactFiles, computeArtifactHash } from '../lib/artifact.js';
import { assertRequiredFields, type AgentManifest } from '../lib/manifest.js';
import { getCliVersion } from '../lib/version.js';

const NXTLINQ_DIR = 'nxtlinq';
const MANIFEST_BASENAME = 'agent.manifest.json';
const SIG_BASENAME = 'agent.manifest.sig';

export function runVerify(cwd: string): boolean {
  const nxtlinqPath = join(cwd, NXTLINQ_DIR);
  const manifestPath = join(nxtlinqPath, MANIFEST_BASENAME);
  const sigPath = join(nxtlinqPath, SIG_BASENAME);
  const publicKeyPath = join(nxtlinqPath, 'public.key');

  let manifestRaw: string;
  let signatureHex: string;
  let publicKeyPem: string;
  try {
    manifestRaw = readFileSync(manifestPath, 'utf8');
    signatureHex = readFileSync(sigPath, 'utf8').trim();
    publicKeyPem = readFileSync(publicKeyPath, 'utf8');
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === 'ENOENT') {
      if (err.path === manifestPath) console.error('Error:', join(NXTLINQ_DIR, MANIFEST_BASENAME), 'not found.');
      else if (err.path === sigPath) console.error('Error:', join(NXTLINQ_DIR, SIG_BASENAME), 'not found.');
      else console.error('Error:', join(NXTLINQ_DIR, 'public.key'), 'not found.');
      process.exit(1);
    }
    throw e;
  }

  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(manifestRaw) as Record<string, unknown>;
  } catch {
    console.error('Error: invalid JSON in agent.manifest.json');
    process.exit(1);
  }

  try {
    assertRequiredFields(manifest);
  } catch (e) {
    console.error('Error:', (e as Error).message);
    process.exit(1);
  }

  const m = manifest as AgentManifest;

  // 1) Recompute contentHash (hash excludes contentHash field)
  const { contentHash: _drop, ...mForHash } = m;
  const canonical = canonicalString(mForHash);
  const computedContentHash = sha256Hex(canonical);
  if (computedContentHash !== m.contentHash) {
    console.error('Error: manifest integrity check failed (contentHash mismatch).');
    process.exit(1);
  }

  // 2) Verify signature (signature is over contentHash)
  if (!verifyEd25519Hex(m.contentHash, signatureHex, publicKeyPem)) {
    console.error('Error: invalid signature.');
    process.exit(1);
  }

  // 3) Recompute artifactHash and optionally check file count
  const artifactFiles = listArtifactFiles(cwd);
  const computedArtifactHash = computeArtifactHash(cwd, artifactFiles);
  if (computedArtifactHash !== m.artifactHash) {
    console.error('Error: artifact integrity check failed (artifactHash mismatch).');
    process.exit(1);
  }
  if (m.artifactFileCount != null && artifactFiles.length !== m.artifactFileCount) {
    console.error('Error: artifact file count mismatch (expected', m.artifactFileCount, 'got', artifactFiles.length, ').');
    process.exit(1);
  }

  console.log('Verification passed.');
  console.log('  name:', m.name, 'version:', m.version);
  console.log('  scope:', m.scope.join(', '));
  if (m.artifactFileCount != null) {
    console.log('  artifactFileCount:', m.artifactFileCount);
  }
  const currentCli = getCliVersion();
  if (m.attestCliVersion != null && m.attestCliVersion !== currentCli) {
    console.warn('');
    console.warn('Note: manifest was signed with nxtlinq-attest@' + m.attestCliVersion + ', you are running @' + currentCli + '.');
    console.warn('If you see compatibility issues, update nxtlinq-attest or re-sign with the current version.');
  }
  return true;
}
