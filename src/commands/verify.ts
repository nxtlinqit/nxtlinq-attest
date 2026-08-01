import { verifyProject } from '../verification.js';
import { getCliVersion } from '../lib/version.js';

export function runVerify(cwd: string): boolean {
  const verification = verifyProject(cwd);
  if (!verification.ok) {
    console.error('Error:', verification.reason);
    process.exitCode = 1;
    return false;
  }
  const m = verification.manifest;

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
