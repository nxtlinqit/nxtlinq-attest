import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const ATTEST_IGNORE_FILE = '.nxtlinq-attest-ignore';

const DEFAULT_IGNORE = new Set([
  'node_modules',
  '.git',
  'nxtlinq',
  'dist',
  '.DS_Store',
  // Node.js
  // (node_modules, dist above)
  // Python
  '__pycache__',
  '.venv',
  'venv',
  '.pytest_cache',
  '.mypy_cache',
]);

/**
 * Load project-level ignore entries from .nxtlinq-attest-ignore in rootDir (one basename per line; # comments and empty lines skipped).
 * Merged with DEFAULT_IGNORE so build outputs (e.g. dist/, build/, output/) are never verified.
 */
export function loadProjectIgnore(rootDir: string): Set<string> {
  const ignore = new Set(DEFAULT_IGNORE);
  const path = join(rootDir, ATTEST_IGNORE_FILE);
  if (!existsSync(path)) return ignore;
  try {
    const content = readFileSync(path, 'utf8');
    for (const line of content.split(/\r?\n/)) {
      const name = line.replace(/#.*/, '').trim();
      if (name) ignore.add(name);
    }
  } catch {
    // ignore read errors; fall back to default only
  }
  return ignore;
}

/**
 * List files to include in artifact (deterministic order).
 * Root = cwd or given dir; ignores common build/cache dirs (node_modules, dist, etc.) and any entries from .nxtlinq-attest-ignore.
 * Build output (e.g. dist/) is never verified.
 */
export function listArtifactFiles(rootDir: string, ignore?: Set<string>): string[] {
  const effectiveIgnore = ignore ?? loadProjectIgnore(rootDir);
  const files: string[] = [];

  function walk(dir: string, base: string) {
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      if (effectiveIgnore.has(e.name)) continue;
      const full = join(dir, e.name);
      const rel = relative(base, full);
      if (e.isDirectory()) {
        walk(full, base);
      } else if (e.isFile()) {
        files.push(rel);
      }
    }
  }

  walk(rootDir, rootDir);
  return files.sort();
}

/**
 * Deterministic artifact hash: for each file (sorted), hash path + content, then hash concatenation.
 */
export function computeArtifactHash(rootDir: string, fileList?: string[]): string {
  const files = fileList ?? listArtifactFiles(rootDir);
  const hasher = createHash('sha256');
  for (const rel of files) {
    const full = join(rootDir, rel);
    try {
      const stat = statSync(full);
      if (!stat.isFile()) continue;
      const content = readFileSync(full);
      hasher.update(rel);
      hasher.update('\0');
      hasher.update(content);
      hasher.update('\0');
    } catch {
      // skip missing/unreadable
    }
  }
  return hasher.digest('hex');
}
