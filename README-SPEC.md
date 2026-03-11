# nxtlinq attest — Spec viewer

The spec entry and Markdown sources live under **`docs/`**; the .md files are in **`docs/spec/`**.

---

## Files

| File | Description |
|------|-------------|
| `docs/index.html` | **Single entry**: view the spec in a browser; switch between 中文 / English |
| `docs/spec/nxtlinq-attest-product-spec.md` | Product spec (Chinese, Markdown), with Mermaid diagrams |
| `docs/spec/nxtlinq-attest-product-spec.en.md` | Product specification (English) |

---

## How to run / view the spec

### Option 1: View in a browser (recommended)

Run a local server inside **`docs/`**, then open the root URL in your browser; use the page controls to switch between Chinese and English.

**Steps:**

1. Go to the **`docs/`** directory.
2. Start a server in one of these ways:

   **Using Node.js (npx):**
   ```bash
   cd docs
   npx serve .
   ```

   **Or using Python 3:**
   ```bash
   cd docs
   python3 -m http.server 8000
   ```

3. Open in your browser (**single entry**):
   - npx serve: `http://localhost:3000/`
   - Python: `http://localhost:8000/`

4. Use the **中文** or **English** link at the top to switch language.

### Option 2: Edit / preview Markdown directly

- Open `docs/spec/nxtlinq-attest-product-spec.md` (Chinese) or `docs/spec/nxtlinq-attest-product-spec.en.md` (English) in **Cursor / VS Code**, and use built-in Markdown preview (or install a Mermaid extension to render diagrams).
- To preview or export a single diagram, copy any ` ```mermaid ` block into [mermaid.live](https://mermaid.live) to edit or export PNG/SVG.

---

## Quick command (run from repo root)

```bash
cd docs
npx serve .

# Then open http://localhost:3000/
```

---

*For the latest spec content, see the source files in `docs/spec/`.*
