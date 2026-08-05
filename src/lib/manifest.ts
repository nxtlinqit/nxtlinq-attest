/**
 * Manifest type and I/O.
 */

import type { Capability } from './capability.js';

export interface AgentManifest {
  name: string;
  version: string;
  scope: string[];
  /** Optional structured authorization ceiling for policy-aware consumers. */
  capabilities?: Capability[];
  issuedAt: number | string;
  publicKey: string;
  /** Required by trust-store verification; selects the authoritative external key. */
  signerKeyId?: string;
  contentHash: string;
  artifactHash: string;
  /** Number of files included in artifact hash (set by sign, optional for verify) */
  artifactFileCount?: number;
  /** nxtlinq-attest CLI version used at init/sign (set by init and sign) */
  attestCliVersion?: string;
  jti?: string;
  exp?: number;
  iss?: string;
  aud?: string | string[];
  audit?: { request_id?: string; trace_id?: string; reason?: string };
  [key: string]: unknown;
}

const REQUIRED = ['name', 'version', 'scope', 'issuedAt', 'publicKey', 'contentHash', 'artifactHash'];

export function assertRequiredFields(m: Record<string, unknown>): asserts m is AgentManifest {
  for (const k of REQUIRED) {
    if (!(k in m) || (m[k] !== 0 && !m[k])) {
      throw new Error(`Missing or empty required field: ${k}`);
    }
  }
  if (!Array.isArray(m.scope)) throw new Error('scope must be an array');
}
