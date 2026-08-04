import { createHash } from 'node:crypto';
import { existsSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { canonicalString } from './canonical.js';
import {
  verifyAttestation,
  isTrustedVerificationResult,
  type VerifiedAttestation,
  type VerifyAttestationOptions,
} from './verify.js';
import type { VerifiedCapability } from './capability.js';

export interface AuthorizationAction {
  /** Canonical namespaced operation, for example `filesystem:read`. */
  readonly type: string;
  /** Filesystem target. Absolute inputs are confined to the verified project. */
  readonly resource?: string;
  /** Shell-free executable identity for `terminal:execute`. */
  readonly command?: string;
  readonly args?: readonly string[];
  readonly cwd?: string;
  readonly environmentNames?: readonly string[];
  /** MCP connection or invocation source. */
  readonly server?: string;
  readonly tool?: string;
  /** Adapter-owned, policy-neutral context. Never copied into decision evidence. */
  readonly attributes?: Readonly<Record<string, string | number | boolean | readonly string[]>>;
}

export interface AuthorizationContext {
  readonly version: 1;
  readonly projectRoot: string;
  readonly attestation: VerifiedAttestation;
}

export type AuthorizationReason =
  | 'authorized'
  | 'invalid_action'
  | 'capability_missing'
  | 'constraint_mismatch'
  | 'outside_workspace'
  | 'approval_required'
  | 'unknown_constraint';

export interface AuthorizationDecision {
  readonly outcome: 'allow' | 'deny';
  readonly reason: AuthorizationReason;
  readonly capability: string;
  readonly policyDigest: string;
  readonly actionDigest: string;
  readonly signerKeyId: string;
}

export type AuthorizationExecution<T> =
  | {
      readonly executed: true;
      readonly decision: AuthorizationDecision & { readonly outcome: 'allow' };
      readonly value: T;
    }
  | {
      readonly executed: false;
      readonly decision: AuthorizationDecision & { readonly outcome: 'deny' };
    };

const ACTION_TYPE = /^[a-z][a-z0-9_-]*(?::[a-z][a-z0-9_-]*)+$/;
const KNOWN_CONSTRAINTS: Readonly<Record<string, ReadonlySet<string>>> = {
  'filesystem:read': new Set(['include', 'exclude']),
  'filesystem:write': new Set(['include', 'exclude', 'approvalRequired']),
  'terminal:execute': new Set(['commands', 'environment', 'approvalRequired']),
  'mcp:connect': new Set(['server', 'servers', 'approvalRequired']),
  'mcp:invoke': new Set(['server', 'servers', 'tool', 'tools', 'approvalRequired']),
};

function freezeContext(attestation: VerifiedAttestation): AuthorizationContext {
  return Object.freeze({
    version: 1 as const,
    projectRoot: attestation.projectRoot,
    attestation,
  });
}

/** Verify once and bind an immutable, trusted authorization context. */
export function createAuthorizationContext(
  options: VerifyAttestationOptions = {},
): AuthorizationContext {
  return freezeContext(verifyAttestation(options));
}

/** Bind an already verified attestation without repeating artifact hashing. */
export function authorizationContextFromVerified(
  attestation: VerifiedAttestation,
): AuthorizationContext {
  if (!isTrustedVerificationResult(attestation)) {
    throw new Error('authorization requires an immutable trusted attestation');
  }
  return freezeContext(attestation);
}

function digestAction(action: AuthorizationAction): string {
  return createHash('sha256').update(canonicalString(action)).digest('hex');
}

function decision(
  context: AuthorizationContext,
  action: AuthorizationAction,
  outcome: 'allow' | 'deny',
  reason: AuthorizationReason,
): AuthorizationDecision {
  return Object.freeze({
    outcome,
    reason,
    capability: action.type,
    policyDigest: context.attestation.manifestDigest,
    actionDigest: digestAction(action),
    signerKeyId: context.attestation.signer.keyId,
  });
}

function strings(capability: VerifiedCapability, name: string): readonly string[] | undefined {
  const value = capability[name];
  if (typeof value === 'string') return [value];
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string')
    ? value
    : undefined;
}

function hasUnknownConstraints(capability: VerifiedCapability): boolean {
  const known = KNOWN_CONSTRAINTS[capability.type];
  if (!known) return true;
  return Object.keys(capability).some((key) => key !== 'type' && !known.has(key));
}

function escapeRegex(character: string): string {
  return /[\\^$.*+?()[\]{}|]/.test(character) ? `\\${character}` : character;
}

function matchGlob(path: string, pattern: string): boolean {
  if (pattern.length === 0 || isAbsolute(pattern)) throw new Error('invalid policy path pattern');
  const normalizedPattern = pattern.replaceAll('\\', '/');
  if (normalizedPattern.split('/').includes('..')) throw new Error('invalid policy path pattern');
  let source = '^';
  for (let index = 0; index < normalizedPattern.length; index += 1) {
    const character = normalizedPattern[index];
    if (character === '*') {
      if (normalizedPattern[index + 1] === '*') {
        index += 1;
        if (normalizedPattern[index + 1] === '/') {
          index += 1;
          source += '(?:.*/)?';
        } else source += '.*';
      } else source += '[^/]*';
    } else if (character === '?') source += '[^/]';
    else source += escapeRegex(character);
  }
  return new RegExp(`${source}$`).test(path.replaceAll('\\', '/'));
}

function resolveResource(projectRoot: string, resource: string): string | undefined {
  const requested = resolve(projectRoot, resource);
  try {
    if (existsSync(requested)) return realpathSync(requested);
    const parent = realpathSync(dirname(requested));
    return resolve(parent, requested.slice(dirname(requested).length + 1));
  } catch {
    return undefined;
  }
}

function relativeWithin(root: string, target: string): string | undefined {
  const value = relative(realpathSync(root), target);
  if (value === '' || (value !== '..' && !value.startsWith(`..${sep}`))) {
    return value === '' ? '.' : value.replaceAll(sep, '/');
  }
  return undefined;
}

function validAction(action: AuthorizationAction): boolean {
  if (!ACTION_TYPE.test(action.type)) return false;
  if (action.args && (!Array.isArray(action.args) || action.args.some((value) => typeof value !== 'string'))) {
    return false;
  }
  if (
    action.environmentNames &&
    (!Array.isArray(action.environmentNames) ||
      action.environmentNames.some((value) => typeof value !== 'string' || value.length === 0))
  ) return false;
  if (action.type.startsWith('filesystem:')) {
    return typeof action.resource === 'string' && action.resource.length > 0;
  }
  if (action.type === 'terminal:execute') {
    return typeof action.command === 'string' && action.command.length > 0;
  }
  if (action.type === 'mcp:connect' || action.type === 'mcp:invoke') {
    return typeof action.server === 'string' && action.server.length > 0 &&
      (action.type !== 'mcp:invoke' || (typeof action.tool === 'string' && action.tool.length > 0));
  }
  return true;
}

function evaluateFilesystem(
  context: AuthorizationContext,
  capability: VerifiedCapability,
  action: AuthorizationAction,
): AuthorizationReason | 'allow' {
  const resolved = resolveResource(context.projectRoot, action.resource as string);
  if (!resolved) return 'invalid_action';
  const workspacePath = relativeWithin(context.projectRoot, resolved);
  if (workspacePath === undefined) return 'outside_workspace';
  try {
    const includes = strings(capability, 'include');
    const excludes = strings(capability, 'exclude') ?? [];
    if (includes && !includes.some((pattern) => matchGlob(workspacePath, pattern))) {
      return 'constraint_mismatch';
    }
    if (excludes.some((pattern) => matchGlob(workspacePath, pattern))) {
      return 'constraint_mismatch';
    }
  } catch {
    return 'unknown_constraint';
  }
  return 'allow';
}

function evaluateTerminal(
  context: AuthorizationContext,
  capability: VerifiedCapability,
  action: AuthorizationAction,
): AuthorizationReason | 'allow' {
  if (action.cwd !== undefined) {
    const resolved = resolveResource(context.projectRoot, action.cwd);
    if (!resolved) return 'invalid_action';
    if (relativeWithin(context.projectRoot, resolved) === undefined) return 'outside_workspace';
  }
  const environment = action.environmentNames ?? [];
  const allowedEnvironment = strings(capability, 'environment') ?? [];
  if (environment.some((name) => !allowedEnvironment.includes(name))) return 'constraint_mismatch';
  const commands = strings(capability, 'commands');
  const commandLine = [action.command, ...(action.args ?? [])].join(' ');
  if (commands && !commands.includes(commandLine)) return 'constraint_mismatch';
  return 'allow';
}

function evaluateMcp(
  capability: VerifiedCapability,
  action: AuthorizationAction,
): AuthorizationReason | 'allow' {
  const servers = strings(capability, 'server') ?? strings(capability, 'servers');
  if (servers && !servers.includes(action.server as string)) return 'constraint_mismatch';
  if (action.type === 'mcp:invoke') {
    const tools = strings(capability, 'tool') ?? strings(capability, 'tools');
    if (tools && !tools.includes(action.tool as string)) return 'constraint_mismatch';
  }
  return 'allow';
}

/** Deterministically evaluate one canonical action against a trusted signed ceiling. */
export function evaluateAuthorization(
  context: AuthorizationContext,
  action: AuthorizationAction,
): AuthorizationDecision {
  if (!validAction(action)) return decision(context, action, 'deny', 'invalid_action');
  const candidates = context.attestation.capabilities.filter((item) => item.type === action.type);
  if (candidates.length === 0) {
    const legacyAllowed = context.attestation.scope.includes(action.type) ||
      context.attestation.scope.includes(`tool:${action.type}`);
    return decision(
      context,
      action,
      legacyAllowed ? 'allow' : 'deny',
      legacyAllowed ? 'authorized' : 'capability_missing',
    );
  }

  let lastReason: AuthorizationReason = 'constraint_mismatch';
  for (const capability of candidates) {
    if (hasUnknownConstraints(capability)) {
      lastReason = 'unknown_constraint';
      continue;
    }
    if (capability.approvalRequired === true) {
      lastReason = 'approval_required';
      continue;
    }
    const result = action.type.startsWith('filesystem:')
      ? evaluateFilesystem(context, capability, action)
      : action.type === 'terminal:execute'
        ? evaluateTerminal(context, capability, action)
        : action.type === 'mcp:connect' || action.type === 'mcp:invoke'
          ? evaluateMcp(capability, action)
          : 'unknown_constraint';
    if (result === 'allow') return decision(context, action, 'allow', 'authorized');
    if (result === 'invalid_action' || result === 'outside_workspace') {
      return decision(context, action, 'deny', result);
    }
    lastReason = result;
  }
  return decision(context, action, 'deny', lastReason);
}

/** Execute a protected handler exactly once after allow and zero times otherwise. */
export async function executeIfAuthorized<T>(
  context: AuthorizationContext,
  action: AuthorizationAction,
  handler: () => T | Promise<T>,
): Promise<AuthorizationExecution<T>> {
  const result = evaluateAuthorization(context, action);
  if (result.outcome === 'deny') {
    return { executed: false, decision: result as AuthorizationDecision & { outcome: 'deny' } };
  }
  return {
    executed: true,
    decision: result as AuthorizationDecision & { outcome: 'allow' },
    value: await handler(),
  };
}
