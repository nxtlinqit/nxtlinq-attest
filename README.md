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

**Options:** `-h, --help` — show help; `-v, --version` — print CLI version and exit.

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

- **Under `nxtlinq/`:** `agent.manifest.json` (do not edit `contentHash`/`artifactHash`), `agent.manifest.sig`, `private.key` (do not commit), `public.key`.
- **Optional at project root:** `.nxtlinq-attest-ignore` — one directory basename per line to exclude from artifact verification (e.g. `dist`, `build`, `output`). Build output is already excluded by default; use this to add more.

## Spec and docs

- Product spec (with diagrams): run `cd docs && npx serve .` then open http://localhost:3000/ (see `README-SPEC.md`). Single entry with 中文 / English switch. Source: `docs/spec/nxtlinq-attest-product-spec.md`, `docs/spec/nxtlinq-attest-product-spec.en.md`.
- `README-SPEC.md` — How to view the spec.
