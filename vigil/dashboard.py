"""Single-file org dashboard: audit + worst findings, no backend.

`vigil dashboard ~/code -o dashboard.html` scans every immediate sub-repo and
embeds a trust card per repo into one HTML file you can host on Pages or attach
to a security review. Uses the same tokens as `vigil serve`; no JS, no
telemetry, no external assets.
"""

from __future__ import annotations

import html as html_mod
from pathlib import Path
from typing import List, Sequence

from . import audit as audit_mod
from . import ui
from .findings import Severity, summarize
from .redact import redact

_DASH_CSS = r"""
.repo-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px;margin-top:14px}
.repo-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:15px;display:flex;flex-direction:column;gap:10px}
.repo-head{display:flex;align-items:center;justify-content:space-between;gap:12px}
.repo-name{font-size:15px;font-weight:650;letter-spacing:-.01em;word-break:break-word}
.repo-meta{font-size:11.5px;color:var(--faint)}
.sev-row{display:flex;flex-wrap:wrap;gap:5px}
.sev-badge{font-size:10px;letter-spacing:.06em;text-transform:uppercase;border:1px solid var(--line);border-radius:999px;padding:2px 7px;color:var(--dim)}
.sev-badge.critical{border-color:var(--crit);color:var(--crit)}
.sev-badge.high{border-color:var(--high);color:var(--high)}
.sev-badge.medium{border-color:var(--med);color:var(--med)}
.repo-list{list-style:none;padding:0;margin:0;display:grid;gap:7px}
.repo-list li{display:grid;gap:1px;font-size:12px;border-left:2px solid var(--sev,var(--line));padding-left:8px}
.repo-list .rid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10.5px;color:var(--faint)}
.repo-list .rwhere{font-size:11px;color:var(--dim);word-break:break-word}
.repo-list .rmsg{color:var(--dim);font-size:11.5px}
.repo-empty{font-size:12px;color:var(--ok)}
"""


def _repo_card(r: audit_mod.RepoResult) -> str:
    worst = sorted(r.findings, key=lambda f: f.severity.rank, reverse=True)[:4]
    counts = summarize(r.findings)
    sev_row = "".join(
        f'<span class="sev-badge {s.value}">{s.value} {counts[s.value]}</span>'
        for s in Severity
        if counts[s.value]
    )
    items = "".join(
        f'<li class="sev-{w.severity.value}"><span class="rid">{html_mod.escape(w.rule_id)}</span>'
        f'<span class="rwhere">{html_mod.escape(w.path)}:{w.line}</span>'
        f'<span class="rmsg">{html_mod.escape(redact(w.message)[:150])}</span></li>'
        for w in worst
    ) or '<li><span class="repo-empty">clean — no findings</span></li>'
    clean_badge = '<span class="sev-badge">clean</span>'
    return (
        '<article class="repo-card">'
        '<div class="repo-head">'
        f'<div><div class="repo-name">{html_mod.escape(r.name)}</div>'
        f'<div class="repo-meta">{len(r.findings)} findings · {len(r.files)} files · {html_mod.escape(r.verdict)}</div></div>'
        f"{ui.ring(r.value, r.grade, 86)}</div>"
        f'<div class="sev-row">{sev_row or clean_badge}</div>'
        f'<ul class="repo-list">{items}</ul>'
        "</article>"
    )


def build(root: Path, max_repos: int = 50) -> str:
    results: Sequence[audit_mod.RepoResult] = audit_mod.audit(root, max_repos=max_repos)
    cards: List[str] = [_repo_card(r) for r in results]
    total_findings = sum(len(r.findings) for r in results)
    critical = sum(
        1
        for r in results
        for f in r.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    average = int(round(sum(r.value for r in results) / len(results))) if results else 100
    worst = results[0] if results else None
    body = (
        '<div class="repo-grid">' + "".join(cards) + "</div>"
        if cards
        else '<div class="empty"><h2>No repositories found</h2>'
        "<p>No immediate subdirectory contained an instruction surface.</p></div>"
    )
    worst_line = (
        f"Worst: <strong>{html_mod.escape(worst.name)}</strong> at {worst.value}/100."
        if worst
        else "Nothing to audit."
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>agentvigil dashboard — {average}/100</title>
<style>{ui.CSS}{_DASH_CSS}</style>
</head>
<body>
<header class="topbar"><div class="wrap topbar-in">
  <a class="brand" href="#top"><span class="dot"></span>agentvigil</a>
  <span class="tag">org dashboard</span>
  <span class="spacer"></span>
  <span class="pill">{len(results)} repo(s)</span>
</div></header>
<main class="wrap" id="top">
  <section class="hero">
    {ui.ring(average, "A" if average >= 90 else ("B" if average >= 75 else ("C" if average >= 50 else ("D" if average >= 25 else "F"))), 120)}
    <div>
      <p class="eyebrow">fleet posture · read-only report</p>
      <h1>Average trust {average}/100</h1>
      <p class="verdict">{worst_line} {total_findings} finding(s) across {len(results)} repositor{'y' if len(results) == 1 else 'ies'}.
      {critical} critical or high.</p>
      <p class="meta-line"><span>generated by <code>vigil dashboard</code></span>
      <span>no JS · no telemetry · no external assets</span></p>
    </div>
  </section>
  <div class="sec-head"><h2>Repositories</h2><span class="count">worst first</span></div>
  {body}
  <footer><span>agentvigil dashboard</span><span>single file · safe to attach to a review</span></footer>
</main>
</body>
</html>
"""


def write(root: Path, out: Path, max_repos: int = 50) -> Path:
    out.write_text(build(root, max_repos=max_repos), encoding="utf-8")
    return out
