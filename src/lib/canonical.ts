/**
 * Canonical JSON: deterministic key ordering and no extra whitespace.
 * Used for contentHash and signing.
 */
export function canonicalString(obj: unknown): string {
  if (obj === null) return 'null';
  if (typeof obj === 'boolean') return obj ? 'true' : 'false';
  if (typeof obj === 'number') return Number.isInteger(obj) ? String(obj) : String(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    const parts = obj.map((item) => canonicalString(item));
    return '[' + parts.join(',') + ']';
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    const parts = keys.map((k) => JSON.stringify(k) + ':' + canonicalString((obj as Record<string, unknown>)[k]));
    return '{' + parts.join(',') + '}';
  }
  throw new Error('Unsupported type for canonical JSON');
}
