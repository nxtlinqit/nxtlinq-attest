import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalString } from '../lib/canonical.js';
import { sha256Hex, signEd25519Hex } from '../lib/crypto.js';
import { listArtifactFiles, computeArtifactHash } from '../lib/artifact.js';
import type { AgentManifest } from '../lib/manifest.js';
import { getCliVersion } from '../lib/version.js';

const NXTLINQ_DIR = 'nxtlinq';
const MANIFEST_BASENAME = 'agent.manifest.json';
const SIG_BASENAME = 'agent.manifest.sig';

export function runSign(cwd: string): void {
  const nxtlinqPath = join(cwd, NXTLINQ_DIR);
  const manifestPath = join(nxtlinqPath, MANIFEST_BASENAME);
  const privateKeyPath = join(nxtlinqPath, 'private.key');

  let manifestRaw: string;
  let privateKeyPem: string;
  try {
    manifestRaw = readFileSync(manifestPath, 'utf8');
    privateKeyPem = readFileSync(privateKeyPath, 'utf8');
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === 'ENOENT') {
      if (err.path === manifestPath) {
        console.error('Error:', join(NXTLINQ_DIR, MANIFEST_BASENAME), 'not found. Run "nxtlinq-attest init" first.');
      } else {
        console.error('Error:', join(NXTLINQ_DIR, 'private.key'), 'not found. Run "nxtlinq-attest init" first.');
      }
      process.exit(1);
    }
    throw e;
  }

  const manifest: AgentManifest = JSON.parse(manifestRaw) as AgentManifest;
  if (!manifest.name || !manifest.version || !Array.isArray(manifest.scope)) {
    console.error('Error: manifest must have name, version, and scope.');
    process.exit(1);
  }

  // 1) Artifact: list files, then hash and set count
  const artifactFiles = listArtifactFiles(cwd);
  manifest.artifactHash = computeArtifactHash(cwd, artifactFiles);
  manifest.artifactFileCount = artifactFiles.length;

  // 2) Set issuedAt to current time (time of this signing)
  manifest.issuedAt = Math.floor(Date.now() / 1000);

  // 3) Record CLI version used for this sign
  manifest.attestCliVersion = getCliVersion();

  // 4) Content hash = SHA256(canonical(manifest without contentHash))
  const { contentHash: _drop, ...manifestForHash } = manifest;
  const canonical = canonicalString(manifestForHash);
  manifest.contentHash = sha256Hex(canonical);

  // 5) Write manifest (with contentHash, artifactHash, issuedAt, attestCliVersion)
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

  // 6) Sign the contentHash (so any change to manifest invalidates signature)
  const signatureHex = signEd25519Hex(manifest.contentHash, privateKeyPem);
  const sigPath = join(nxtlinqPath, SIG_BASENAME);
  writeFileSync(sigPath, signatureHex, 'utf8');

  console.log('Signed manifest and artifact.');
  console.log('  contentHash:', manifest.contentHash.slice(0, 16) + '...');
  console.log('  artifactHash:', manifest.artifactHash.slice(0, 16) + '...');
  console.log('  artifactFileCount:', manifest.artifactFileCount);
  console.log('  signature:', join(NXTLINQ_DIR, SIG_BASENAME));
}
