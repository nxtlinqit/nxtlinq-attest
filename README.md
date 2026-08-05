# @nxtlinq/attest

Agent signing and verification for nxtlinq attest; runs entirely locally (no blockchain, no external service).

## Install

### From npm (after publish)

```bash
npm install -g @nxtlinq/attest
```

Then run: `nxtlinq-attest init`, `nxtlinq-attest sign`, `nxtlinq-attest verify`.

### From source (repo)

```bash
cd nxtlinq-attest
npm install
npm run build
```

**Option A — run via node (no global install):**

```bash
node bin/nxtlinq-attest.mjs <command>
# e.g. node bin/nxtlinq-attest.mjs init
```

**Option B — install globally from this repo:**

```bash
npm link
```

Then from any directory: `nxtlinq-attest init`, `nxtlinq-attest sign`, `nxtlinq-attest verify`.

**Requirements:** Node 22+

## Runtime API (for Agent apps)

Install as a dependency in your Agent project to read attested scope at runtime (no need to implement file read yourself):

```bash
npm install @nxtlinq/attest
# or before publish: npm install file:../nxtlinq-attest
```

```ts
import { getAttestScope, isToolInAttestScope } from '@nxtlinq/attest';

const scope = getAttestScope();           // from nxtlinq/agent.manifest.json (cached by cwd)
if (!isToolInAttestScope(toolName)) {
  // deny: tool not in attested scope
}
```

These legacy scope helpers only read `agent.manifest.json`; they do not prove
that the signer is trusted or that the signature and project artifacts are
valid. Do not use them alone as an authorization boundary. Security-sensitive
runtimes and proxies should use the verified API below.

- `getAttestScope(cwd?)` — returns `scope` array; `[]` if no manifest. Cached per cwd.
- `isToolInAttestScope(toolName, cwd?, options?)` — true only when the tool is in a non-empty scope. Missing, invalid, and empty manifests fail closed.

Applications migrating from the pre-2.0 permissive behavior may opt in
temporarily and explicitly:

```ts
isToolInAttestScope(toolName, cwd, { allowEmptyScope: true });
```

Do not enable this compatibility option for security-sensitive runtimes.

### Verified runtime API

`verifyAttestation` validates the manifest, signature, signer trust, artifact
set, optional expiry, optional audience, and non-empty scope as one fail-closed
operation:

```ts
import { loadTrustStore, verifyAttestation } from '@nxtlinq/attest';

const trustStore = loadTrustStore('/etc/nxtlinq/trusted-signers.json');
const attestation = verifyAttestation({
  projectRoot: process.cwd(),
  trustStore,
  expectedAudience: 'nxtlinq-authorization-gateway',
});

// Safe input for a policy engine after successful verification.
console.log(attestation.scope);
console.log(attestation.capabilities);
console.log(attestation.signer.keyId, attestation.manifestDigest);
```

### Optional structured capabilities

The legacy string `scope` remains required and existing manifests continue to
work unchanged. Policy-aware consumers may additionally use `capabilities` as
a signed, protocol-neutral authorization ceiling:

```json
{
  "scope": ["tool:Search"],
  "capabilities": [
    {
      "type": "filesystem:read",
      "include": ["src/**", "package.json"],
      "exclude": [".env"]
    },
    {
      "type": "terminal:execute",
      "commands": ["npm test", "npm run build"],
      "approvalRequired": true
    }
  ]
}
```

Capability types are lowercase namespaced strings such as
`filesystem:read`. Constraint values may be non-empty strings, finite numbers,
booleans, or non-empty string arrays. Paths are policy data and should be
relative to the workspace a consumer has independently verified; do not sign
machine-specific absolute paths.

Attest validates and signs this data but does not interpret ACP methods or make
runtime allow/deny decisions. A consumer such as ACP Proxy must map concrete
actions to capabilities, fail closed on constraints it does not understand,
and may only narrow—not expand—the signed ceiling. The returned capability
objects and arrays are immutable.

The trust store must be controlled outside the attested repository. It can
contain inline PEM keys or paths relative to the trust-store file:

```json
{
  "trustedSigners": [
    {
      "keyId": "project-owner-2026",
      "publicKeyPath": "./keys/project-owner.pem"
    }
  ]
}
```

When a trust store is supplied, `manifest.signerKeyId` selects the signer and
the signature is verified directly with that trust-store public key. The
repository-local `nxtlinq/public.key` and `manifest.publicKey` are not trust
inputs in this mode. They remain part of the standalone local `init`, `sign`,
and integrity-verification workflow only.

Set `"revoked": true` on a signer to fail closed for manifests signed by that
key. A trusted manifest must contain a non-empty `signerKeyId` matching exactly
one trust-store entry. Without a trust store, `verifyAttestation()` rejects the
signer by default. `allowUntrustedSigner: true` explicitly enables the local
`public.key` integrity check and must not be used for authorization.

**Node only.** For **Python or any language**, use the **CLI** instead: run `nxtlinq-attest scope` from the agent project root; it prints the scope array as JSON to stdout (exit 0). Parse stdout once at startup and cache; use it to allow/deny tools. Same CLI works for Node if you prefer not to depend on the package.

For more detail, see the product spec (view via [README-SPEC.md](README-SPEC.md)).

## Commands

| Command | Description |
|---------|-------------|
| `nxtlinq-attest init` | Create `nxtlinq/` with keys and `agent.manifest.json` |
| `nxtlinq-attest sign` | Compute contentHash + artifactHash, sign manifest, write `nxtlinq/agent.manifest.sig` |
| `nxtlinq-attest verify` | Verify manifest and artifact integrity (exit 1 on failure) |
| `nxtlinq-attest scope` | Print manifest scope as JSON to stdout (for any runtime to call) |

**Options:** `-h, --help` — show help; `-v, --version` — print CLI version and exit.

For trusted verification:

```bash
nxtlinq-attest verify \
  --trust-store /etc/nxtlinq/trusted-signers.json \
  --audience nxtlinq-authorization-gateway
```

Running `verify` without `--trust-store` preserves the previous local
integrity-check workflow but prints a warning that signer authorization was
not established.

### Signing key modes

The default local-development flow remains unchanged:

```bash
nxtlinq-attest init
nxtlinq-attest sign
```

`init` creates `nxtlinq/private.key` for convenient local testing. Do not use
that repository-local key as a production policy authority and never commit
it. To keep the private key outside the project, pass an absolute path or a
path relative to the project root:

```bash
nxtlinq-attest sign --private-key /secure/keys/project-owner.pem
```

For a new public-key-only project, initialize it with the authority's public
key and an operational key ID. These options must be supplied together:

```bash
nxtlinq-attest init \
  --public-key /secure/keys/project-owner-public.pem \
  --key-id project-owner-2026

nxtlinq-attest sign --private-key /secure/keys/project-owner-private.pem
```

This mode writes `public.key`, `agent.manifest.json`, and the signed
`signerKeyId`, but does not create `nxtlinq/private.key`. If a local private key
already exists, public-key-only initialization stops instead of deleting or
silently retaining it.

CI, KMS, Vault, and hardware-key integrations can implement the async signer
boundary and call the library API directly:

```ts
import { signAttestation, type AttestationSigner } from '@nxtlinq/attest';

const signer: AttestationSigner = {
  keyId: 'kms/project-owner/1',
  async signDigest(digest) {
    // Return a lowercase Ed25519 signature encoded as 128 hex characters.
    return signingService.sign(digest);
  },
};

await signAttestation({ projectRoot: process.cwd(), signer });
```

The signer receives only the UTF-8 bytes of the canonical SHA-256 content
digest—not the manifest, source files, workspace, or secrets. Attest verifies
the returned signature against `nxtlinq/public.key` before writing the updated
manifest and signature. `keyId` identifies the signing service for operational
output; verifier trust still comes from the external trust store, not from a
self-asserted key ID.

## Protocol-neutral runtime authorization

Attest can verify a signed policy once and apply it to a canonical action. It
does not import or depend on ACP, MCP, Buzz, an IDE, or a transport. Those
systems remain adapters that translate their own messages into this contract:

```ts
import {
  createAuthorizationContext,
  executeIfAuthorized,
  loadTrustStore,
} from '@nxtlinq/attest';

const context = createAuthorizationContext({
  projectRoot: process.cwd(),
  trustStore: loadTrustStore('/operator-controlled/trust.json'),
  expectedAudience: 'my-runtime',
});

const result = await executeIfAuthorized(context, {
  type: 'filesystem:read',
  resource: '/absolute/project/README.md',
}, async () => readProtectedFile());
```

If the decision is `deny`, `readProtectedFile` is invoked zero times. If it is
`allow`, the guard invokes it exactly once. This guarantee applies only to
handlers actually routed through the guard; operating-system sandboxing is
still required to contain a process that bypasses the integration.

Supported structured policy families are `filesystem:read`,
`filesystem:write`, `terminal:execute`, `mcp:connect`, and `mcp:invoke`.
Unknown constraints fail closed. Decisions contain action and policy digests
instead of copying paths, arguments, or secrets into evidence.

## Quick start

```bash
cd your-agent-project
nxtlinq-attest init
# Edit nxtlinq/agent.manifest.json (name, version, scope)
nxtlinq-attest sign
nxtlinq-attest verify
```

## After init: what to edit in `nxtlinq/agent.manifest.json`

| Field | You edit? | Description |
|-------|-----------|-------------|
| **name** | Required | Agent identifier (e.g. `"my-agent"`, `"nxtlinq-ai-agent"`). |
| **version** | Required | Semantic version of this agent (e.g. `"1.0.0"`). |
| **scope** | Required | List of tools/permissions this agent is allowed to use. Each item is a string like `"tool:ToolName"`. Example: `["tool:ExampleTool", "tool:Search"]`. |
| **capabilities** | Optional | Structured, protocol-neutral authorization ceiling for policy-aware consumers. Existing `scope`-only manifests remain supported. |
| **issuedAt** | Optional | Unix timestamp when the manifest was created. Init sets this; you can leave it or update it. |
| **publicKey** | Prohibited | Filled by init. Do not edit. |
| **signerKeyId** | Required for trusted verification | Selects the authoritative external trust-store entry; local-only verification does not require it. |
| **contentHash** | Prohibited | Set by `sign`. Do not edit. |
| **artifactHash** | Prohibited | Set by `sign`. Do not edit. |

**Summary:** Before running `sign`, edit **name**, **version**, and **scope** to match your agent. Do not change `contentHash`, `artifactHash`, or `publicKey`. All attest files live under `nxtlinq/`.

## Artifact verification (build output excluded)

`sign` and `verify` hash only **source and config** files; **build output is never verified**. By default the following are excluded from the artifact hash:

- `node_modules`, `.git`, `nxtlinq`, **`dist`**, `.DS_Store`
- Python: `__pycache__`, `.venv`, `venv`, `.pytest_cache`, `.mypy_cache`

So `dist/` (and similar build dirs) do not affect verification. To exclude more paths (e.g. `build/`, `out/`, `output/`), add a **`.nxtlinq-attest-ignore`** file in the project root with one directory basename per line (comments with `#` and empty lines are ignored). Example:

```
# Build and generated output — not verified
dist
build
output
```

## Requirements

- Node 22+
- Works offline; no wallet. Verification fails (exit 1) on tampered manifest or artifact.

## Files

- **Under `nxtlinq/`:** `agent.manifest.json` (do not edit `contentHash`/`artifactHash`), `agent.manifest.sig`, optional local-development `private.key` (do not commit), and `public.key`.
- **Optional at project root:** `.nxtlinq-attest-ignore` — one directory basename per line to exclude from artifact verification (e.g. `dist`, `build`, `output`). Build output is already excluded by default; use this to add more.

## Spec and docs

- Product spec (with diagrams): run `cd docs && npx serve .` then open http://localhost:3000/ (see `README-SPEC.md`). Single entry with 中文 / English switch. Source: `docs/spec/nxtlinq-attest-product-spec.md`, `docs/spec/nxtlinq-attest-product-spec.en.md`.
- `README-SPEC.md` — How to view the spec.
