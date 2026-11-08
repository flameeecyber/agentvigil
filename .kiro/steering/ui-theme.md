---
inclusion: fileMatch
fileMatchPattern:
  - "vigil/theme.py"
  - "vigil/serve.py"
  - "vigil/dashboard.py"
  - "vigil/graph.py"
  - "tests/test_theme.py"
---

# UI: haunted, but functional

The Costume Contest category asks for a spooky interface that **enhances the
app's function**, not a skin over a generic dashboard. For this project that means:

- **Every visual encodes evidence.** Rooms are surface files; apparitions are
  findings ordered by severity; ghost script is a payload decoded from
  invisible characters; the constellation is the real attack-path graph.
- **Show the decoded text.** A spooky reveal is only honest if the user can read
  what was decoded. Never animate or obscure the payload itself.
- **No deception in the UI.** Do not hide counts, soften severity names, or use
  copy that implies the tool is a sandbox. State "read-only, nothing executed".
- **Accessibility is part of polish.** `prefers-reduced-motion` disables the
  flicker; contrast stays legible; the page works with no JavaScript and no CDN.
- **Escape everything user-derived.** Paths, messages and decoded payloads go
  through `html.escape` and `redact`. No inline event handlers.
- **Keep the plain theme the default.** `--theme kiroween` is opt-in so JSON,
  CI and SARIF consumers are unaffected.
- **Performance budget.** One request, inline CSS, no fonts, no images beyond the
  generated SVG; the page should render in well under a second on a 5k-file repo.
