import { createHash, sign, verify, generateKeyPairSync } from 'node:crypto';

const HASH_ALGO = 'sha256';

export function sha256Hex(data: string | Buffer): string {
  return createHash(HASH_ALGO).update(data).digest('hex');
}

/**
 * Ed25519 sign (algorithm null for Ed25519).
 */
export function signEd25519Hex(message: string | Buffer, privateKeyPem: string): string {
  const buf = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
  const sig = sign(null, buf, { key: privateKeyPem });
  return sig.toString('hex');
}

export function verifyEd25519Hex(message: string | Buffer, signatureHex: string, publicKeyPem: string): boolean {
  const buf = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;
  const sig = Buffer.from(signatureHex, 'hex');
  return verify(null, buf, { key: publicKeyPem }, sig);
}

export function generateEd25519KeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}
