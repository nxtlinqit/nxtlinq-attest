import {
  verifyProject,
  type VerificationEvidence,
  type VerificationFailureCode,
} from './verification.js';

export interface AuthorizationRequest {
  /** Existing manifest capability vocabulary, for example `tool:write`. */
  capability: string;
  /** Protocol context is descriptive only and is not trusted as policy input. */
  protocol?: string;
  sessionId?: string;
  resource?: string;
}

export type AuthorizationDenyCode =
  | VerificationFailureCode
  | 'invalid_request'
  | 'out_of_scope';

export type AuthorizationDecision =
  | {
      outcome: 'allow';
      code: 'scope_allows';
      capability: string;
      evidence: VerificationEvidence;
    }
  | {
      outcome: 'deny';
      code: AuthorizationDenyCode;
      capability: string;
      reason: string;
      evidence?: VerificationEvidence;
    };

export interface GuardOptions {
  cwd?: string;
}

/**
 * Verify the project, then evaluate one observable operation against the
 * signed manifest's existing capability scope. No second policy engine is
 * introduced: verification and the signed scope remain authoritative.
 */
export function authorize(
  request: AuthorizationRequest,
  options: GuardOptions = {},
): AuthorizationDecision {
  const capability = request.capability.trim();
  if (!capability) {
    return {
      outcome: 'deny',
      code: 'invalid_request',
      capability,
      reason: 'A non-empty capability is required.',
    };
  }

  const verification = verifyProject(options.cwd ?? process.cwd());
  if (!verification.ok) {
    return {
      outcome: 'deny',
      code: verification.code,
      capability,
      reason: verification.reason,
    };
  }

  if (!verification.manifest.scope.includes(capability)) {
    return {
      outcome: 'deny',
      code: 'out_of_scope',
      capability,
      reason: `Capability ${capability} is not present in the verified manifest scope.`,
      evidence: verification.evidence,
    };
  }

  return {
    outcome: 'allow',
    code: 'scope_allows',
    capability,
    evidence: verification.evidence,
  };
}

export type GuardedOperationResult<T> =
  | { executed: true; decision: Extract<AuthorizationDecision, { outcome: 'allow' }>; value: T }
  | { executed: false; decision: Extract<AuthorizationDecision, { outcome: 'deny' }> };

/**
 * Enforce an authorization decision in the host execution path. The protected
 * downstream handler is never invoked after a deny decision.
 */
export async function executeIfAuthorized<T>(
  request: AuthorizationRequest,
  downstream: () => T | Promise<T>,
  options: GuardOptions = {},
): Promise<GuardedOperationResult<T>> {
  const decision = authorize(request, options);
  if (decision.outcome === 'deny') {
    return { executed: false, decision };
  }

  return { executed: true, decision, value: await downstream() };
}
