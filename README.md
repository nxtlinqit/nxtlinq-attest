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

- `getAttestScope(cwd?)` — returns `scope` array; `[]` if no manifest. Cached per cwd.
- `isToolInAttestScope(toolName, cwd?)` — true if tool is in scope or scope is empty (backward compatible).

**Node only.** For **Python or any language**, use the **CLI** instead: run `nxtlinq-attest scope` from the agent project root; it prints the scope array as JSON to stdout (exit 0). Parse stdout once at startup and cache; use it to allow/deny tools. Same CLI works for Node if you prefer not to depend on the package.

For more detail, see the product spec (view via [README-SPEC.md](README-SPEC.md)).

## Commands

| Command | Description |
|---------|-------------|
| `nxtlinq-attest init` | Create `nxtlinq/` with keys and `agent.manifest.json` |
| `nxtlinq-attest sign` | Compute contentHash + artifactHash, sign manifest, write `nxtlinq/agent.manifest.sig` |
| `nxtlinq-attest verify` | Verify manifest and artifact integrity (exit 1 on failure) |
| `nxtlinq-attest scope` | Print manifest scope as JSON to stdout (for any runtime to call) |

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
| **issuedAt** | Optional | Unix timestamp when the manifest was created. Init sets this; you can leave it or update it. |
| **publicKey** | Prohibited | Filled by init. Do not edit. |
| **contentHash** | Prohibited | Set by `sign`. Do not edit. |
| **artifactHash** | Prohibited | Set by `sign`. Do not edit. |

**Summary:** Before running `sign`, edit **name**, **version**, and **scope** to match your agent. Do not change `contentHash`, `artifactHash`, or `publicKey`. All attest files live under `nxtlinq/`.

## Requirements

- Node 22+
- Works offline; no wallet. Verification fails (exit 1) on tampered manifest or artifact.

## Files (all under `nxtlinq/`)

- `nxtlinq/agent.manifest.json` — Agent declaration (name, version, scope, hashes). Do not edit `contentHash` / `artifactHash`; they are set by `sign`.
- `nxtlinq/agent.manifest.sig` — Signature (hex). Created by `sign`.
- `nxtlinq/private.key` — **Do not commit.** Used by `sign`.
- `nxtlinq/public.key` — Public key for verification.

## Spec and docs

- Product spec (with diagrams): run `cd docs && npx serve .` then open http://localhost:3000/ (see `README-SPEC.md`). Single entry with 中文 / English switch. Source: `docs/spec/nxtlinq-attest-product-spec.md`, `docs/spec/nxtlinq-attest-product-spec.en.md`.
- `README-SPEC.md` — How to view the spec.
