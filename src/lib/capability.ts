/**
 * Protocol-neutral structured authorization data carried by an attestation.
 * Runtime consumers decide how a capability maps to concrete operations.
 */

export type CapabilityConstraintValue = string | number | boolean | string[];

export interface Capability {
  type: string;
  [constraint: string]: CapabilityConstraintValue;
}

export type VerifiedCapability = Readonly<{
  readonly type: string;
  readonly [constraint: string]: string | number | boolean | readonly string[];
}>;

const CAPABILITY_TYPE = /^[a-z][a-z0-9_-]*(?::[a-z][a-z0-9_-]*)+$/;
const CONSTRAINT_NAME = /^[A-Za-z][A-Za-z0-9_-]*$/;

function assertConstraintValue(value: unknown, path: string): void {
  if (typeof value === 'string') {
    if (value.length === 0) throw new Error(`${path} must not be an empty string`);
    return;
  }
  if (typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error(`${path} must be a finite number`);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) throw new Error(`${path} must not be an empty array`);
    if (value.some((entry) => typeof entry !== 'string' || entry.length === 0)) {
      throw new Error(`${path} must contain only non-empty strings`);
    }
    return;
  }
  throw new Error(`${path} must be a string, number, boolean, or string array`);
}

export function assertCapabilities(value: unknown): asserts value is Capability[] {
  if (!Array.isArray(value)) throw new Error('capabilities must be an array');

  for (const [index, entry] of value.entries()) {
    const path = `capabilities[${index}]`;
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`${path} must be an object`);
    }

    const record = entry as Record<string, unknown>;
    if (typeof record.type !== 'string' || !CAPABILITY_TYPE.test(record.type)) {
      throw new Error(`${path}.type must be a namespaced lowercase capability`);
    }

    for (const [name, constraint] of Object.entries(record)) {
      if (name === 'type') continue;
      if (!CONSTRAINT_NAME.test(name)) {
        throw new Error(`${path} contains an invalid constraint name: ${name}`);
      }
      assertConstraintValue(constraint, `${path}.${name}`);
    }
  }
}
