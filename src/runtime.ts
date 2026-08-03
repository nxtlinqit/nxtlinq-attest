/**
 * Runtime API for consumers: read manifest scope, check tool allowance, and
 * produce verified authorization decisions.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AgentManifest } from './lib/manifest.js';

export {
  authorize,
  verifyAuthorizationContext,
  withAuthorization,
} from './authorization.js';

export type {
  AuthorizationDecision,
  AuthorizationEvidence,
  AuthorizationOutcome,
  AuthorizationRequest,
} from './authorization.js';

const NXTLINQ_DIR = 'nxtlinq';
const MANIFEST_BASENAME = 'agent.manifest.json';

const scopeCache = new Map<string, string[] | null>();

export interface AttestScopeOptions {
  /**
   * Preserve the pre-1.1 permissive behavior for applications that explicitly
   * need it. Disabled by default so missing, invalid, and empty manifests fail
   * closed.
   */
  allowEmptyScope?: boolean;
}

function getManifestPath(cwd: string): string {
  return join(cwd, NXTLINQ_DIR, MANIFEST_BASENAME);
}

/**
 * Get the attested scope from nxtlinq/agent.manifest.json. Cached per cwd.
 * @param cwd - Project root (default: process.cwd())
 * @returns scope array, or [] if manifest missing/invalid
 */
export function getAttestScope(cwd?: string): string[] {
  const root = cwd ?? process.cwd();
  const cached = scopeCache.get(root);
  if (cached !== undefined) {
    return cached ?? [];
  }

  try {
    const path = getManifestPath(root);
    const raw = readFileSync(path, 'utf8');
    const manifest = JSON.parse(raw) as AgentManifest;
    const scope = Array.isArray(manifest.scope) ? manifest.scope : [];
    scopeCache.set(root, scope);
    return scope;
  } catch {
    scopeCache.set(root, null);
    return [];
  }
}

/**
 * Check if a tool is allowed by the manifest scope without performing signature
 * or artifact verification. Use `authorize()` when an enforcement decision is
 * required.
 */
export function isToolInAttestScope(
  toolName: string,
  cwd?: string,
  options: AttestScopeOptions = {},
): boolean {
  const scope = getAttestScope(cwd);
  if (scope.length === 0) {
    return options.allowEmptyScope === true;
  }
  const normalized = toolName.startsWith('tool:') ? toolName : `tool:${toolName}`;
  return scope.includes(normalized);
}

/**
 * Clear cached scope (e.g. for tests). Next getAttestScope() will re-read from disk.
 * @param cwd - If provided, clear only this cwd's cache; otherwise clear all.
 */
export function clearAttestScopeCache(cwd?: string): void {
  if (cwd !== undefined) {
    scopeCache.delete(cwd);
  } else {
    scopeCache.clear();
  }
}
