import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { authorize, withAuthorization } from '../dist/runtime.js';

const cliPath = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

function runCli(cwd, ...args) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd,
    encoding: 'utf8',
  });
}

function createSignedFixture(scope = ['tool:write']) {
  const cwd = mkdtempSync(join(tmpdir(), 'nxtlinq-authorize-'));
  writeFileSync(join(cwd, 'artifact.txt'), 'original\n');

  const init = runCli(cwd, 'init');
  assert.equal(init.status, 0, init.stderr);

  const manifestPath = join(cwd, 'nxtlinq', 'agent.manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  manifest.scope = scope;
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  const sign = runCli(cwd, 'sign');
  assert.equal(sign.status, 0, sign.stderr);

  return cwd;
}

test('authorize allows a signed in-scope capability', () => {
  const cwd = createSignedFixture(['tool:write']);
  const decision = authorize({ capability: 'tool:write', cwd });

  assert.equal(decision.outcome, 'allow');
  assert.equal(decision.reason, 'authorized');
  assert.equal(decision.capability, 'tool:write');
  assert.ok(decision.evidence?.manifestDigest);
  assert.ok(decision.evidence?.artifactDigest);
});

test('authorize normalizes a bare tool capability', () => {
  const cwd = createSignedFixture(['tool:write']);
  const decision = authorize({ capability: 'write', cwd });

  assert.equal(decision.outcome, 'allow');
  assert.equal(decision.capability, 'tool:write');
});

test('authorize denies a signed out-of-scope capability', () => {
  const cwd = createSignedFixture(['tool:write']);
  const decision = authorize({ capability: 'tool:exec', cwd });

  assert.equal(decision.outcome, 'deny');
  assert.equal(decision.reason, 'capability_not_in_scope');
});

test('authorize fails closed after an artifact is altered', () => {
  const cwd = createSignedFixture(['tool:write']);
  writeFileSync(join(cwd, 'artifact.txt'), 'altered\n');

  const decision = authorize({ capability: 'tool:write', cwd });

  assert.equal(decision.outcome, 'deny');
  assert.equal(decision.reason, 'artifact_integrity_failed');
});

test('withAuthorization never invokes a denied handler', async () => {
  const cwd = createSignedFixture(['tool:write']);
  let calls = 0;

  const result = await withAuthorization(
    { capability: 'tool:exec', cwd },
    () => {
      calls += 1;
      return 'executed';
    },
  );

  assert.equal(result.decision.outcome, 'deny');
  assert.equal(calls, 0);
  assert.equal(result.value, undefined);
});

test('withAuthorization invokes an allowed handler exactly once', async () => {
  const cwd = createSignedFixture(['tool:write']);
  let calls = 0;

  const result = await withAuthorization(
    { capability: 'tool:write', cwd },
    () => {
      calls += 1;
      return 'executed';
    },
  );

  assert.equal(result.decision.outcome, 'allow');
  assert.equal(calls, 1);
  assert.equal(result.value, 'executed');
});

test('authorize CLI emits machine-readable JSON and stable exit codes', () => {
  const cwd = createSignedFixture(['tool:write']);

  const allowed = runCli(cwd, 'authorize', 'tool:write');
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.equal(JSON.parse(allowed.stdout).outcome, 'allow');

  const denied = runCli(cwd, 'authorize', 'tool:exec');
  assert.equal(denied.status, 2, denied.stderr);
  assert.equal(JSON.parse(denied.stdout).outcome, 'deny');
});
