import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { computeArtifactHash, listArtifactFiles } from '../dist/lib/artifact.js';
import { canonicalString } from '../dist/lib/canonical.js';
import {
  generateEd25519KeyPair,
  sha256Hex,
  signEd25519Hex,
} from '../dist/lib/crypto.js';
import {
  AttestationVerificationError,
  verifyAttestation,
} from '../dist/lib/verify.js';
import { loadTrustStore } from '../dist/lib/trust.js';
import { runSign } from '../dist/commands/sign.js';
import { signAttestation } from '../dist/lib/sign.js';

function signManifest(root, manifest, privateKeyPem) {
  const { contentHash: _drop, ...manifestForHash } = manifest;
  manifest.contentHash = sha256Hex(canonicalString(manifestForHash));
  writeFileSync(
    join(root, 'nxtlinq', 'agent.manifest.json'),
    JSON.stringify(manifest, null, 2),
  );
  writeFileSync(
    join(root, 'nxtlinq', 'agent.manifest.sig'),
    signEd25519Hex(manifest.contentHash, privateKeyPem),
  );
}

function signedFixture(overrides = {}) {
  const root = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-verified-'));
  mkdirSync(join(root, 'nxtlinq'));
  writeFileSync(join(root, 'agent-source.txt'), 'trusted source\n');
  const keys = generateEd25519KeyPair();
  writeFileSync(join(root, 'nxtlinq', 'private.key'), keys.privateKeyPem);
  writeFileSync(join(root, 'nxtlinq', 'public.key'), keys.publicKeyPem);
  const artifactFiles = listArtifactFiles(root);
  const manifest = {
    name: 'verified-agent',
    version: '1.0.0',
    scope: ['tool:Search'],
    issuedAt: 1_700_000_000,
    publicKey: keys.publicKeyPem.trim(),
    signerKeyId: 'project-owner',
    artifactHash: computeArtifactHash(root, artifactFiles),
    artifactFileCount: artifactFiles.length,
    contentHash: '',
    ...overrides,
  };
  signManifest(root, manifest, keys.privateKeyPem);
  return { root, manifest, ...keys };
}

function trustStore(publicKey, overrides = {}) {
  return {
    trustedSigners: [{ keyId: 'project-owner', publicKey, ...overrides }],
  };
}

function assertCode(expected, operation) {
  assert.throws(operation, (error) => {
    assert.ok(error instanceof AttestationVerificationError);
    assert.equal(error.code, expected);
    return true;
  });
}

test('secure verification returns a trusted immutable authorization input', () => {
  const fixture = signedFixture();
  const result = verifyAttestation({
    projectRoot: fixture.root,
    trustStore: trustStore(fixture.publicKeyPem),
  });
  assert.equal(result.signer.keyId, 'project-owner');
  assert.equal(result.signer.trusted, true);
  assert.deepEqual(result.scope, ['tool:Search']);
  assert.equal(result.manifestDigest, fixture.manifest.contentHash);
  assert.equal(result.artifactDigest, fixture.manifest.artifactHash);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.manifest), true);
  assert.equal(Object.isFrozen(result.scope), true);
  assert.deepEqual(result.capabilities, []);
  assert.equal(Object.isFrozen(result.capabilities), true);
});

test('structured capabilities are validated and returned as immutable authorization data', () => {
  const fixture = signedFixture({
    capabilities: [
      {
        type: 'filesystem:read',
        include: ['src/**', 'package.json'],
        exclude: ['.env'],
      },
      {
        type: 'terminal:execute',
        commands: ['npm test'],
        approvalRequired: true,
      },
    ],
  });
  const result = verifyAttestation({
    projectRoot: fixture.root,
    trustStore: trustStore(fixture.publicKeyPem),
  });

  assert.deepEqual(result.capabilities, fixture.manifest.capabilities);
  assert.equal(Object.isFrozen(result.capabilities), true);
  assert.equal(Object.isFrozen(result.capabilities[0]), true);
  assert.equal(Object.isFrozen(result.capabilities[0].include), true);
  assert.throws(() => result.capabilities[0].include.push('secrets/**'), TypeError);
});

test('invalid structured capabilities fail closed during sign and verify', async () => {
  for (const capabilities of [
    { type: 'filesystem:read' },
    [{ type: 'Filesystem:Read' }],
    [{ type: 'filesystem:read', include: [] }],
    [{ type: 'filesystem:read', nested: { path: 'src/**' } }],
  ]) {
    const fixture = signedFixture({ capabilities });
    assertCode('manifest_invalid', () => verifyAttestation({
      projectRoot: fixture.root,
      trustStore: trustStore(fixture.publicKeyPem),
    }));
  }

  const signFixture = signedFixture({
    capabilities: [{ type: 'filesystem:read', include: ['src/**'] }],
  });
  const manifestPath = join(signFixture.root, 'nxtlinq', 'agent.manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  manifest.capabilities[0].include = [''];
  writeFileSync(manifestPath, JSON.stringify(manifest));
  await assert.rejects(runSign(signFixture.root), /manifest capabilities are invalid/);

  const invalidKeyId = signedFixture({ signerKeyId: '' });
  assertCode('manifest_invalid', () => verifyAttestation({
    projectRoot: invalidKeyId.root,
    trustStore: trustStore(invalidKeyId.publicKeyPem),
  }));
  await assert.rejects(runSign(invalidKeyId.root), /signerKeyId must be a non-empty string/);
});

test('sign safely upgrades a legacy manifest that is missing publicKey', async () => {
  const root = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-legacy-sign-'));
  mkdirSync(join(root, 'nxtlinq'));
  writeFileSync(join(root, 'agent-source.txt'), 'legacy source\n');
  const keys = generateEd25519KeyPair();
  writeFileSync(join(root, 'nxtlinq', 'private.key'), keys.privateKeyPem);
  writeFileSync(join(root, 'nxtlinq', 'public.key'), keys.publicKeyPem);
  writeFileSync(
    join(root, 'nxtlinq', 'agent.manifest.json'),
    JSON.stringify({
      name: 'legacy-agent',
      version: '1.0.0',
      scope: ['tool:Search'],
      issuedAt: 1_700_000_000,
      contentHash: 'legacy',
      artifactHash: 'legacy',
    }),
  );

  await runSign(root);
  const upgraded = JSON.parse(
    readFileSync(join(root, 'nxtlinq', 'agent.manifest.json'), 'utf8'),
  );
  assert.equal(upgraded.publicKey, keys.publicKeyPem.trim());
  const verified = verifyAttestation({
    projectRoot: root,
    allowUntrustedSigner: true,
  });
  assert.equal(verified.signer.trusted, false);
});

test('sign refuses mismatched private and public keys', async () => {
  const root = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-mismatched-sign-'));
  mkdirSync(join(root, 'nxtlinq'));
  const privateKeys = generateEd25519KeyPair();
  const publicKeys = generateEd25519KeyPair();
  writeFileSync(join(root, 'nxtlinq', 'private.key'), privateKeys.privateKeyPem);
  writeFileSync(join(root, 'nxtlinq', 'public.key'), publicKeys.publicKeyPem);
  writeFileSync(
    join(root, 'nxtlinq', 'agent.manifest.json'),
    JSON.stringify({ name: 'agent', version: '1.0.0', scope: ['tool:Search'] }),
  );
  await assert.rejects(
    runSign(root),
    /private key does not match nxtlinq\/public\.key/,
  );
});

test('async external signer receives only the content digest and is verified before writes', async () => {
  const fixture = signedFixture();
  const manifestPath = join(fixture.root, 'nxtlinq', 'agent.manifest.json');
  let receivedDigest;
  const result = await signAttestation({
    projectRoot: fixture.root,
    signer: {
      keyId: 'kms/project-owner/1',
      async signDigest(digest) {
        receivedDigest = Buffer.from(digest);
        return signEd25519Hex(receivedDigest, fixture.privateKeyPem);
      },
    },
  });

  assert.equal(receivedDigest.toString('utf8'), result.contentHash);
  assert.equal(result.signerKeyId, 'kms/project-owner/1');
  const verified = verifyAttestation({
    projectRoot: fixture.root,
    trustStore: trustStore(fixture.publicKeyPem, { keyId: 'kms/project-owner/1' }),
  });
  assert.equal(verified.manifestDigest, result.contentHash);

  const manifestBeforeFailure = readFileSync(manifestPath, 'utf8');
  await assert.rejects(
    signAttestation({
      projectRoot: fixture.root,
      signer: {
        keyId: 'wrong-kms-key',
        async signDigest() {
          return '00'.repeat(64);
        },
      },
    }),
    /does not match nxtlinq\/public\.key/,
  );
  assert.equal(readFileSync(manifestPath, 'utf8'), manifestBeforeFailure);
});

test('sign CLI accepts a private key stored outside the project', () => {
  const fixture = signedFixture();
  const keyDirectory = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-external-key-'));
  const externalKeyPath = join(keyDirectory, 'owner-private.pem');
  writeFileSync(externalKeyPath, fixture.privateKeyPem, { mode: 0o600 });

  const unrelatedKey = generateEd25519KeyPair();
  writeFileSync(join(fixture.root, 'nxtlinq', 'private.key'), unrelatedKey.privateKeyPem);
  const binPath = join(process.cwd(), 'bin', 'nxtlinq-attest.mjs');
  const signed = spawnSync(
    process.execPath,
    [binPath, 'sign', '--private-key', externalKeyPath],
    { cwd: fixture.root, encoding: 'utf8', env: { ...process.env, FORCE_COLOR: '0' } },
  );

  assert.equal(signed.status, 0, signed.stderr);
  assert.match(signed.stdout, /Signed manifest and artifact/);
  const verified = verifyAttestation({
    projectRoot: fixture.root,
    trustStore: trustStore(fixture.publicKeyPem),
  });
  assert.equal(verified.signer.trusted, true);
});

test('init CLI supports a public-key-only project identity', () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-public-init-'));
  const keyDirectory = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-authority-'));
  const keys = generateEd25519KeyPair();
  const publicKeyPath = join(keyDirectory, 'owner-public.pem');
  const privateKeyPath = join(keyDirectory, 'owner-private.pem');
  writeFileSync(publicKeyPath, keys.publicKeyPem);
  writeFileSync(privateKeyPath, keys.privateKeyPem, { mode: 0o600 });
  const binPath = join(process.cwd(), 'bin', 'nxtlinq-attest.mjs');
  const cliOptions = {
    cwd: projectRoot,
    encoding: 'utf8',
    env: { ...process.env, FORCE_COLOR: '0' },
  };

  const initialized = spawnSync(
    process.execPath,
    [
      binPath,
      'init',
      '--public-key',
      publicKeyPath,
      '--key-id',
      'project-owner-2026',
    ],
    cliOptions,
  );
  assert.equal(initialized.status, 0, initialized.stderr);
  assert.equal(existsSync(join(projectRoot, 'nxtlinq', 'private.key')), false);
  const manifest = JSON.parse(
    readFileSync(join(projectRoot, 'nxtlinq', 'agent.manifest.json'), 'utf8'),
  );
  assert.equal(manifest.signerKeyId, 'project-owner-2026');
  assert.equal(manifest.publicKey, keys.publicKeyPem.trim());

  writeFileSync(join(projectRoot, 'agent-source.txt'), 'formal project source\n');
  const signed = spawnSync(
    process.execPath,
    [binPath, 'sign', '--private-key', privateKeyPath],
    cliOptions,
  );
  assert.equal(signed.status, 0, signed.stderr);
  const verified = verifyAttestation({
    projectRoot,
    trustStore: trustStore(keys.publicKeyPem, { keyId: 'project-owner-2026' }),
  });
  assert.equal(verified.manifest.signerKeyId, 'project-owner-2026');

  const missingKeyIdRoot = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-public-init-invalid-'));
  const missingKeyId = spawnSync(
    process.execPath,
    [binPath, 'init', '--public-key', publicKeyPath],
    { ...cliOptions, cwd: missingKeyIdRoot },
  );
  assert.equal(missingKeyId.status, 1);
  assert.match(missingKeyId.stderr, /--public-key and --key-id must be provided together/);
});

test('secure verification requires an externally configured signer', () => {
  const fixture = signedFixture();
  assertCode('signer_untrusted', () => verifyAttestation({ projectRoot: fixture.root }));

  const anotherKey = generateEd25519KeyPair();
  assertCode('signature_invalid', () => verifyAttestation({
    projectRoot: fixture.root,
    trustStore: trustStore(anotherKey.publicKeyPem),
    allowUntrustedSigner: true,
  }));

  const compatibility = verifyAttestation({
    projectRoot: fixture.root,
    allowUntrustedSigner: true,
  });
  assert.equal(compatibility.signer.trusted, false);
});

test('trust-store verification ignores the project public.key and uses the key selected by signerKeyId', () => {
  const fixture = signedFixture();
  const ownerTrust = trustStore(fixture.publicKeyPem);
  const attacker = generateEd25519KeyPair();
  writeFileSync(join(fixture.root, 'nxtlinq', 'public.key'), attacker.publicKeyPem);

  const verified = verifyAttestation({
    projectRoot: fixture.root,
    trustStore: ownerTrust,
  });
  assert.equal(verified.signer.keyId, 'project-owner');

  assertCode('public_key_mismatch', () => verifyAttestation({
    projectRoot: fixture.root,
    allowUntrustedSigner: true,
  }));
});

test('trust-store verification requires signerKeyId and verifies with that external key', () => {
  const missingKeyId = signedFixture();
  delete missingKeyId.manifest.signerKeyId;
  signManifest(missingKeyId.root, missingKeyId.manifest, missingKeyId.privateKeyPem);
  assertCode('signer_untrusted', () => verifyAttestation({
    projectRoot: missingKeyId.root,
    trustStore: trustStore(missingKeyId.publicKeyPem),
  }));

  const fixture = signedFixture();
  const attacker = generateEd25519KeyPair();
  assertCode('signature_invalid', () => verifyAttestation({
    projectRoot: fixture.root,
    trustStore: trustStore(attacker.publicKeyPem),
  }));
});

test('revoked signer, empty scope, expiry, and audience all fail closed', () => {
  const revoked = signedFixture();
  assertCode('signer_revoked', () => verifyAttestation({
    projectRoot: revoked.root,
    trustStore: trustStore(revoked.publicKeyPem, { revoked: true }),
  }));

  const empty = signedFixture({ scope: [] });
  assertCode('scope_empty', () => verifyAttestation({
    projectRoot: empty.root,
    trustStore: trustStore(empty.publicKeyPem),
  }));

  const expired = signedFixture({ exp: 1_800_000_000 });
  assertCode('manifest_expired', () => verifyAttestation({
    projectRoot: expired.root,
    trustStore: trustStore(expired.publicKeyPem),
    now: new Date('2030-01-01T00:00:00Z'),
  }));

  const audience = signedFixture({ aud: ['another-runtime'] });
  assertCode('audience_mismatch', () => verifyAttestation({
    projectRoot: audience.root,
    trustStore: trustStore(audience.publicKeyPem),
    expectedAudience: 'nxtlinq-authorization-gateway',
  }));
});

test('manifest and artifact tampering fail closed; local-key tampering fails in local mode', () => {
  const artifact = signedFixture();
  writeFileSync(join(artifact.root, 'agent-source.txt'), 'tampered source\n');
  assertCode('artifact_integrity', () => verifyAttestation({
    projectRoot: artifact.root,
    trustStore: trustStore(artifact.publicKeyPem),
  }));

  const manifest = signedFixture();
  const manifestPath = join(manifest.root, 'nxtlinq', 'agent.manifest.json');
  const changed = JSON.parse(readFileSync(manifestPath, 'utf8'));
  changed.scope = ['tool:Exec'];
  writeFileSync(manifestPath, JSON.stringify(changed));
  assertCode('manifest_integrity', () => verifyAttestation({
    projectRoot: manifest.root,
    trustStore: trustStore(manifest.publicKeyPem),
  }));

  const key = signedFixture();
  const anotherKey = generateEd25519KeyPair();
  writeFileSync(join(key.root, 'nxtlinq', 'public.key'), anotherKey.publicKeyPem);
  assertCode('public_key_mismatch', () => verifyAttestation({
    projectRoot: key.root,
    allowUntrustedSigner: true,
  }));
});

test('artifact hashing fails instead of skipping a missing covered file', () => {
  const root = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-missing-artifact-'));
  assert.throws(
    () => computeArtifactHash(root, ['missing.txt']),
    /ENOENT|no such file/i,
  );
});

test('trust stores support external key files relative to the store', () => {
  const fixture = signedFixture({ signerKeyId: 'owner-from-file' });
  const configDir = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-trust-'));
  writeFileSync(join(configDir, 'owner.pem'), fixture.publicKeyPem);
  writeFileSync(
    join(configDir, 'trust.json'),
    JSON.stringify({
      trustedSigners: [{ keyId: 'owner-from-file', publicKeyPath: 'owner.pem' }],
    }),
  );
  const loaded = loadTrustStore(join(configDir, 'trust.json'));
  const result = verifyAttestation({ projectRoot: fixture.root, trustStore: loaded });
  assert.equal(result.signer.keyId, 'owner-from-file');
});

test('verify CLI distinguishes trusted verification from integrity-only compatibility', () => {
  const fixture = signedFixture({ signerKeyId: 'cli-owner' });
  const configDir = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-cli-trust-'));
  const trustPath = join(configDir, 'trust.json');
  writeFileSync(
    trustPath,
    JSON.stringify({
      trustedSigners: [{ keyId: 'cli-owner', publicKey: fixture.publicKeyPem }],
    }),
  );
  const binPath = join(process.cwd(), 'bin', 'nxtlinq-attest.mjs');
  const cliEnvironment = { ...process.env, FORCE_COLOR: '0' };

  const trusted = spawnSync(
    process.execPath,
    [binPath, 'verify', '--trust-store', trustPath],
    { cwd: fixture.root, encoding: 'utf8', env: cliEnvironment },
  );
  assert.equal(trusted.status, 0, trusted.stderr);
  assert.match(trusted.stdout, /signerTrusted: true/);

  const compatibility = spawnSync(
    process.execPath,
    [binPath, 'verify'],
    { cwd: fixture.root, encoding: 'utf8', env: cliEnvironment },
  );
  assert.equal(compatibility.status, 0, compatibility.stderr);
  assert.match(compatibility.stderr, /integrity but not signer authorization/);
});
