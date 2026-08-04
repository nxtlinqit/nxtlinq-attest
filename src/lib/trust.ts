import { createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { sha256Hex } from './crypto.js';

export interface TrustedSigner {
  keyId: string;
  publicKey: string;
  revoked?: boolean;
}

export interface TrustStore {
  trustedSigners: readonly TrustedSigner[];
}

interface TrustStoreFileSigner {
  keyId?: unknown;
  publicKey?: unknown;
  publicKeyPath?: unknown;
  revoked?: unknown;
}

function publicKeyDer(publicKeyPem: string): Buffer {
  return createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
}

export function publicKeyFingerprint(publicKeyPem: string): string {
  return `sha256:${sha256Hex(publicKeyDer(publicKeyPem))}`;
}

export function publicKeysEqual(left: string, right: string): boolean {
  return publicKeyDer(left).equals(publicKeyDer(right));
}

export function loadTrustStore(path: string): TrustStore {
  const raw = readFileSync(path, 'utf8');
  const parsed = JSON.parse(raw) as { trustedSigners?: unknown };
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.trustedSigners)) {
    throw new Error('trust store must contain a trustedSigners array');
  }

  const baseDir = dirname(resolve(path));
  const trustedSigners = parsed.trustedSigners.map((value, index): TrustedSigner => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error(`trustedSigners[${index}] must be an object`);
    }
    const signer = value as TrustStoreFileSigner;
    if (typeof signer.keyId !== 'string' || signer.keyId.length === 0) {
      throw new Error(`trustedSigners[${index}].keyId must be a non-empty string`);
    }
    if (signer.revoked !== undefined && typeof signer.revoked !== 'boolean') {
      throw new Error(`trustedSigners[${index}].revoked must be a boolean`);
    }
    const hasInlineKey = typeof signer.publicKey === 'string' && signer.publicKey.length > 0;
    const hasKeyPath = typeof signer.publicKeyPath === 'string' && signer.publicKeyPath.length > 0;
    if (hasInlineKey === hasKeyPath) {
      throw new Error(
        `trustedSigners[${index}] must contain exactly one of publicKey or publicKeyPath`,
      );
    }
    const publicKey = hasInlineKey
      ? signer.publicKey as string
      : readFileSync(resolve(baseDir, signer.publicKeyPath as string), 'utf8');
    // Parse eagerly so malformed keys fail when the trust store is loaded.
    publicKeyFingerprint(publicKey);
    return { keyId: signer.keyId, publicKey, revoked: signer.revoked as boolean | undefined };
  });

  if (trustedSigners.length === 0) {
    throw new Error('trust store must contain at least one trusted signer');
  }
  const keyIds = new Set<string>();
  const fingerprints = new Set<string>();
  for (const signer of trustedSigners) {
    if (keyIds.has(signer.keyId)) {
      throw new Error(`duplicate trusted signer keyId: ${signer.keyId}`);
    }
    keyIds.add(signer.keyId);
    const fingerprint = publicKeyFingerprint(signer.publicKey);
    if (fingerprints.has(fingerprint)) {
      throw new Error(`duplicate trusted signer public key: ${fingerprint}`);
    }
    fingerprints.add(fingerprint);
  }
  return { trustedSigners };
}
