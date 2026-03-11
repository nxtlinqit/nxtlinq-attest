import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

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
 * List files to include in artifact (deterministic order).
 * Root = cwd or given dir; ignore common build/cache dirs (Node: node_modules, dist; Python: __pycache__, .venv, venv, .pytest_cache, .mypy_cache), .git, nxtlinq, .DS_Store.
 */
export function listArtifactFiles(rootDir: string, ignore: Set<string> = DEFAULT_IGNORE): string[] {
  const files: string[] = [];

  function walk(dir: string, base: string) {
    const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      if (ignore.has(e.name)) continue;
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
