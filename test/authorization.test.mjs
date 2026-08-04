import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { computeArtifactHash, listArtifactFiles } from '../dist/lib/artifact.js';
import { canonicalString } from '../dist/lib/canonical.js';
import { generateEd25519KeyPair, sha256Hex, signEd25519Hex } from '../dist/lib/crypto.js';
import {
  authorizationContextFromVerified,
  createAuthorizationContext,
  evaluateAuthorization,
  executeIfAuthorized,
} from '../dist/lib/authorization.js';

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'nxtlinq-authorization-'));
  mkdirSync(join(root, 'nxtlinq'));
  mkdirSync(join(root, 'src'));
  writeFileSync(join(root, 'README.md'), '# Demo\n');
  writeFileSync(join(root, '.env'), 'SECRET=not-for-agents\n');
  writeFileSync(join(root, 'src', 'index.js'), 'export const answer = 42;\n');

  const keys = generateEd25519KeyPair();
  writeFileSync(join(root, 'nxtlinq', 'public.key'), keys.publicKeyPem);
  const artifactFiles = listArtifactFiles(root);
  const manifest = {
    name: 'authorization-demo',
    version: '1.0.0',
    scope: ['tool:Search'],
    capabilities: [
      { type: 'filesystem:read', include: ['README.md', 'src/**'], exclude: ['.env'] },
      { type: 'terminal:execute', commands: ['node --version'], environment: ['CI'] },
      { type: 'mcp:invoke', server: 'company-tools', tools: ['search'] },
    ],
    issuedAt: 1_700_000_000,
    publicKey: keys.publicKeyPem.trim(),
    artifactHash: computeArtifactHash(root, artifactFiles),
    artifactFileCount: artifactFiles.length,
    contentHash: '',
  };
  const { contentHash: _drop, ...manifestForHash } = manifest;
  manifest.contentHash = sha256Hex(canonicalString(manifestForHash));
  writeFileSync(join(root, 'nxtlinq', 'agent.manifest.json'), JSON.stringify(manifest, null, 2));
  writeFileSync(
    join(root, 'nxtlinq', 'agent.manifest.sig'),
    signEd25519Hex(manifest.contentHash, keys.privateKeyPem),
  );
  return { root, manifest, ...keys };
}

function contextFor(value) {
  return createAuthorizationContext({
    projectRoot: value.root,
    trustStore: {
      trustedSigners: [{ keyId: 'company-owner', publicKey: value.publicKeyPem }],
    },
  });
}

test('protocol-neutral actions are evaluated against the verified signed ceiling', () => {
  const value = fixture();
  const context = contextFor(value);

  const readme = evaluateAuthorization(context, {
    type: 'filesystem:read',
    resource: join(value.root, 'README.md'),
  });
  assert.equal(readme.outcome, 'allow');
  assert.equal(readme.reason, 'authorized');

  const secret = evaluateAuthorization(context, {
    type: 'filesystem:read',
    resource: join(value.root, '.env'),
  });
  assert.equal(secret.outcome, 'deny');
  assert.equal(secret.reason, 'constraint_mismatch');

  assert.equal(evaluateAuthorization(context, {
    type: 'terminal:execute', command: 'node', args: ['--version'], environmentNames: ['CI'],
  }).outcome, 'allow');
  assert.equal(evaluateAuthorization(context, {
    type: 'terminal:execute', command: 'npm', args: ['publish'], environmentNames: [],
  }).outcome, 'deny');

  assert.equal(evaluateAuthorization(context, {
    type: 'mcp:invoke', server: 'company-tools', tool: 'search',
  }).outcome, 'allow');
  assert.equal(evaluateAuthorization(context, {
    type: 'mcp:invoke', server: 'company-tools', tool: 'delete_everything',
  }).outcome, 'deny');

  assert.equal(readme.policyDigest, value.manifest.contentHash);
  assert.equal(readme.signerKeyId, 'company-owner');
  assert.match(readme.actionDigest, /^[a-f0-9]{64}$/);
  assert.equal('resource' in readme, false, 'decision evidence must not copy sensitive input');
});

test('denied handlers run zero times and allowed handlers run exactly once', async () => {
  const value = fixture();
  const context = contextFor(value);
  let calls = 0;

  const denied = await executeIfAuthorized(context, {
    type: 'filesystem:read', resource: join(value.root, '.env'),
  }, () => {
    calls += 1;
    return 'secret';
  });
  assert.equal(denied.executed, false);
  assert.equal(calls, 0);

  const allowed = await executeIfAuthorized(context, {
    type: 'filesystem:read', resource: join(value.root, 'README.md'),
  }, () => {
    calls += 1;
    return 'safe value';
  });
  assert.equal(allowed.executed, true);
  assert.equal(allowed.value, 'safe value');
  assert.equal(calls, 1);
});

test('a project cannot replace its public key to create its own authorization context', () => {
  const value = fixture();
  const attacker = generateEd25519KeyPair();
  writeFileSync(join(value.root, 'nxtlinq', 'public.key'), attacker.publicKeyPem);

  assert.throws(
    () => contextFor(value),
    (error) => error?.code === 'public_key_mismatch',
  );
});

test('an immutable look-alike cannot impersonate verified authorization data', () => {
  const forged = Object.freeze({
    projectRoot: '/tmp/forged',
    manifest: Object.freeze({}),
    manifestDigest: '0'.repeat(64),
    artifactDigest: '0'.repeat(64),
    artifactFiles: Object.freeze([]),
    scope: Object.freeze(['filesystem:read']),
    capabilities: Object.freeze([]),
    signer: Object.freeze({ keyId: 'attacker', fingerprint: 'fake', trusted: true }),
  });
  assert.throws(
    () => authorizationContextFromVerified(forged),
    /immutable trusted attestation/,
  );
});
