import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { runInit } from '../dist/commands/init.js';
import { runSign } from '../dist/commands/sign.js';
import { authorize, executeIfAuthorized } from '../dist/guard.js';

const vectors = JSON.parse(
  readFileSync(new URL('./fixtures/authorization.json', import.meta.url), 'utf8'),
);

function signedProject(scope) {
  const root = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-guard-'));
  writeFileSync(join(root, 'agent.js'), 'export const agent = true;\n');
  runInit(root);
  const manifestPath = join(root, 'nxtlinq', 'agent.manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  manifest.scope = scope;
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  runSign(root);
  return root;
}

function applyVerificationState(root, vector) {
  if (!vector.manifestVerified) {
    writeFileSync(join(root, 'nxtlinq', 'agent.manifest.sig'), '00'.repeat(64));
  }
  if (!vector.artifactVerified) {
    writeFileSync(join(root, 'agent.js'), 'export const agent = false;\n');
  }
}

for (const vector of vectors) {
  test(`authorization conformance: ${vector.id}`, async () => {
    const root = signedProject(vector.signedScope);
    applyVerificationState(root, vector);
    let executions = 0;

    const result = await executeIfAuthorized(
      { capability: vector.requestedCapability },
      () => {
        executions += 1;
        return 'executed';
      },
      { cwd: root },
    );

    assert.equal(result.decision.outcome, vector.expected.outcome);
    assert.equal(result.decision.code, vector.expected.code);
    assert.equal(result.executed, vector.expected.executed);
    assert.equal(executions, vector.expected.executions);
    if (result.executed) {
      assert.equal(result.value, 'executed');
      assert.equal(result.decision.evidence.manifestDigest.length, 64);
    }
  });
}

test('authorization returns only digest evidence, not request arguments or secrets', () => {
  const root = signedProject(['tool:exec']);
  const decision = authorize(
    { capability: 'tool:exec', protocol: 'acp', sessionId: 'session-1' },
    { cwd: root },
  );

  assert.equal(decision.outcome, 'allow');
  assert.equal('arguments' in decision, false);
  assert.equal('sessionId' in decision, false);
});
