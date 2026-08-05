# Changelog

## 3.0.0 - 2026-08-06

### Changed

- Trust-store verification now requires the signed manifest `signerKeyId` and
  verifies directly with the public key selected by that exact trust-store ID.
- Project-local `nxtlinq/public.key` and `manifest.publicKey` remain available
  for standalone local signing and integrity verification, but are not trust
  inputs when a trust store is supplied.
- `signAttestation()` persists the selected signer's key ID in the signed
  manifest.

### Breaking

- Manifests without `signerKeyId` no longer pass trust-store verification.
- Trusted signer selection no longer falls back to matching a project-provided
  public key against trust-store entries.

## 2.2.0 - 2026-08-05

### Added

- Protocol-neutral `AuthorizationAction`, `AuthorizationContext`, and
  `AuthorizationDecision` APIs.
- `evaluateAuthorization()` for filesystem, terminal, and MCP canonical actions.
- `executeIfAuthorized()` guard with a tested zero-handler-invocation guarantee
  when policy denies an action.

### Architecture

- Attest still has no ACP, MCP, Buzz, transport, session, or UI dependency.
- Protocol adapters translate their messages into canonical actions and consume
  the same trusted signed authorization context.

## 2.1.0 - 2026-08-04

### Added

- Trusted `verifyAttestation()` runtime API with immutable authorization output.
- External trust stores, signer pinning, revocation, expiry, and audience checks.
- Protocol-neutral structured capabilities with legacy string-scope compatibility.
- External private-key and asynchronous signer workflows.
- Public signing, verification, capability, signer, and trust-store TypeScript APIs.
- CLI support for external trust stores, expected audiences, public-key-only init,
  and private keys stored outside the project.

### Security

- Secure verification fails closed for missing trust, invalid capabilities,
  artifact read failures, signer replacement, and protected-file tampering.
- Signing rejects mismatched private/public keys and safely upgrades legacy
  manifests only after validating the selected key pair.

### Compatibility

- Existing standalone `init`, `sign`, `verify`, scope, and integrity-only flows
  remain available. Trusted verification is additive and explicitly configured.

## 2.0.0

- Previous stable release.
