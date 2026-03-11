/**
 * Runtime API for consumers: read manifest scope and check tool allowance.
 * Use this in your agent app to enforce attested scope without re-implementing file read logic.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AgentManifest } from './lib/manifest.js';

const NXTLINQ_DIR = 'nxtlinq';
const MANIFEST_BASENAME = 'agent.manifest.json';

const scopeCache = new Map<string, string[] | null>();

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
 * Check if a tool is allowed by the attested manifest scope.
 * Scope entries are typically "tool:ToolName"; we accept either "ToolName" or "tool:ToolName".
 * If no scope is defined (no manifest or empty scope), returns true for backward compatibility.
 */
export function isToolInAttestScope(toolName: string, cwd?: string): boolean {
  const scope = getAttestScope(cwd);
  if (scope.length === 0) {
    return true;
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
