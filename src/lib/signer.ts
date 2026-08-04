import { signEd25519Hex } from './crypto.js';

/**
 * A signing boundary for local keys, CI services, KMS, Vault, or hardware keys.
 * The signer receives only the UTF-8 bytes of the canonical content digest.
 */
export interface AttestationSigner {
  readonly keyId: string;
  signDigest(digest: Uint8Array): Promise<string>;
}

export function createEd25519PrivateKeySigner(
  privateKeyPem: string,
  keyId = 'local-project-key',
): AttestationSigner {
  if (typeof keyId !== 'string' || keyId.length === 0) {
    throw new Error('signer keyId must be a non-empty string');
  }
  return {
    keyId,
    async signDigest(digest: Uint8Array): Promise<string> {
      return signEd25519Hex(Buffer.from(digest), privateKeyPem);
    },
  };
}
