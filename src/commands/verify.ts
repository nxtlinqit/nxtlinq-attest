import { getCliVersion } from '../lib/version.js';
import { AttestationVerificationError, verifyAttestation } from '../lib/verify.js';
import { loadTrustStore } from '../lib/trust.js';

export interface VerifyCommandOptions {
  trustStorePath?: string;
  expectedAudience?: string;
}

export function runVerify(cwd: string, options: VerifyCommandOptions = {}): boolean {
  try {
    const trustStore = options.trustStorePath
      ? loadTrustStore(options.trustStorePath)
      : undefined;
    const result = verifyAttestation({
      projectRoot: cwd,
      trustStore,
      allowUntrustedSigner: trustStore === undefined,
      expectedAudience: options.expectedAudience,
    });

    console.log('Verification passed.');
    console.log('  name:', result.manifest.name, 'version:', result.manifest.version);
    console.log('  scope:', result.scope.join(', '));
    console.log('  signer:', result.signer.keyId);
    console.log('  signerTrusted:', result.signer.trusted);
    if (result.manifest.artifactFileCount != null) {
      console.log('  artifactFileCount:', result.manifest.artifactFileCount);
    }
    if (!result.signer.trusted) {
      console.warn('');
      console.warn('Warning: no trust store was supplied; this proves integrity but not signer authorization.');
      console.warn('Use --trust-store <path> for security-sensitive verification.');
    }
    const currentCli = getCliVersion();
    if (
      result.manifest.attestCliVersion != null &&
      result.manifest.attestCliVersion !== currentCli
    ) {
      console.warn('');
      console.warn(
        'Note: manifest was signed with nxtlinq-attest@' +
          result.manifest.attestCliVersion +
          ', you are running @' +
          currentCli +
          '.',
      );
      console.warn(
        'If you see compatibility issues, update nxtlinq-attest or re-sign with the current version.',
      );
    }
    return true;
  } catch (error) {
    const prefix = error instanceof AttestationVerificationError
      ? `Error [${error.code}]:`
      : 'Error:';
    console.error(prefix, error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
    return false;
  }
}
