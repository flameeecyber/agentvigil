"""Kiroween theme: a haunted instruction-surface report that still works.

Costume Contest rules ask for a spooky interface that *enhances* the app's
function, not a skin. Every visual here maps to a real finding:

* rooms      -> surface files the agent reads
* apparitions-> findings, worst first
* ghost script -> payloads decoded out of invisible Unicode
* constellation -> the attack-path SVG

Opt-in via `vigil serve . --theme kiroween`; the plain report stays the default
so CI, screenshots and JSON consumers are unaffected. No JavaScript, no CDN.
"""

from __future__ import annotations

import html as html_mod
from string import Template
from typing import Sequence

from .findings import Finding
from .redact import redact
from .score import score
from .surface import KIND_LABELS, SurfaceFile

_PAGE = Template(
    """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>agentvigil séance — $value/100 $grade</title>
<style>
:root{--ink:#e8e3d6;--dim:#9b9485;--blood:#c1121f;--bone:#f4efe3;--fog:#0b0a0d;--moss:#7f9c6a}
*{box-sizing:border-box}
body{margin:0;background:
  radial-gradient(60rem 30rem at 15% -10%, #241722 0%, transparent 60%),
  radial-gradient(50rem 30rem at 90% 10%, #12211c 0%, transparent 55%),
  var(--fog);
  color:var(--ink);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;line-height:1.5;min-height:100vh}
body::before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.06;
  background-image:repeating-linear-gradient(0deg,#fff 0 1px,transparent 1px 3px)}
.wrap{max-width:1040px;margin:0 auto;padding:3rem 1.25rem 4rem;position:relative}
.kicker{letter-spacing:.42em;text-transform:uppercase;font-size:.68rem;color:var(--dim)}
h1{font-family:Georgia,"Times New Roman",serif;font-weight:400;font-size:clamp(2.2rem,6vw,4.4rem);
  margin:.2rem 0 .1rem;letter-spacing:.06em;text-shadow:0 0 22px rgba(193,18,31,.35)}
h1 .séance{color:var(--blood)}
.flicker{animation:flicker 7s infinite}
@keyframes flicker{0%,92%,100%{opacity:1}93%{opacity:.45}94%{opacity:1}96%{opacity:.6}97%{opacity:1}}
.sub{color:var(--dim);max-width:62ch;margin:.4rem 0 2rem}
.top{display:grid;grid-template-columns:180px 1fr;gap:2rem;align-items:center;
  border-top:1px solid #2a2530;border-bottom:1px solid #2a2530;padding:1.6rem 0;margin-bottom:2.2rem}
.meter{width:170px;height:170px;border-radius:50%;position:relative;
  background:conic-gradient(var(--blood) calc(var(--trust)*1%), #221d26 0);
  filter:drop-shadow(0 0 18px rgba(193,18,31,.25))}
.meter::after{content:"";position:absolute;inset:12px;border-radius:50%;background:#100d13}
.meter b{position:absolute;inset:0;display:grid;place-items:center;font-size:2rem;z-index:1;color:var(--bone)}
.verdict{font-size:1.05rem}
.verdict strong{color:var(--blood);letter-spacing:.08em}
.verdict small{display:block;color:var(--dim);margin-top:.35rem}
h2{font-family:Georgia,serif;font-weight:400;letter-spacing:.14em;text-transform:uppercase;
  font-size:.9rem;color:var(--dim);margin:2.4rem 0 1rem}
.rooms{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:.7rem}
.room{border:1px solid #2a2530;background:#120f16;border-radius:2px;padding:.7rem .8rem;font-size:.8rem}
.room span{display:block;color:var(--dim);font-size:.68rem;letter-spacing:.12em;text-transform:uppercase}
.cards{display:grid;gap:.8rem}
.card{border-left:3px solid var(--dim);background:linear-gradient(90deg,#141018,transparent);
  padding:.85rem 1rem;border-radius:0 6px 6px 0}
.card.critical{border-color:var(--blood)}
.card.high{border-color:#d9772f}
.card.medium{border-color:#b39b3d}
.card .head{display:flex;flex-wrap:wrap;gap:.6rem;align-items:baseline;font-size:.8rem}
.card .rule{color:var(--bone);font-weight:700;letter-spacing:.05em}
.card .where{color:var(--dim)}
.card .caps{color:var(--moss);font-size:.72rem}
.card p{margin:.45rem 0 0;font-size:.82rem;color:#cfc7b8}
.ghost{margin-top:.55rem;padding:.5rem .65rem;border:1px dashed #4b3f52;background:#0a0810;
  color:#d9c9ff;font-size:.78rem;white-space:pre-wrap;word-break:break-word}
.ghost b{color:var(--dim);font-weight:400;letter-spacing:.14em;text-transform:uppercase;font-size:.62rem;display:block;margin-bottom:.25rem}
.graph{margin-top:.6rem;overflow-x:auto;border:1px solid #2a2530}
footer{margin-top:3.2rem;padding-top:1.2rem;border-top:1px solid #2a2530;color:var(--dim);font-size:.72rem}
footer a{color:var(--moss)}
@media (max-width:640px){.top{grid-template-columns:1fr}.meter{width:130px;height:130px}}
@media (prefers-reduced-motion:reduce){.flicker{animation:none}}
</style>
</head>
<body>
<div class="wrap">
  <div class="kicker">instruction-surface séance · read-only</div>
  <h1 class="flicker">agentvigil <span class="séance">séance</span></h1>
  <p class="sub">Every file below is text an AI agent may obey. We lit a candle in each
  room, read what was written in the margins, and wrote down what it lets the agent do.</p>

  <section class="top">
    <div class="meter" style="--trust:$value"><b>$value</b></div>
    <div class="verdict">
      <strong>$grade · $verdict</strong> — $count finding(s) across $files file(s).
      <small>Decoded payloads are shown, not executed. Nothing here writes to disk.</small>
    </div>
  </section>

  <h2>the rooms ($files)</h2>
  <div class="rooms">$rooms</div>

  <h2>apparitions ($count)</h2>
  <div class="cards">$cards</div>

  <h2>ghost script</h2>
  <p class="sub">Characters a reviewer cannot see, decoded from the surface.</p>
  <div class="cards">$ghosts</div>

  <h2>constellation</h2>
  <div class="graph">$graph</div>

  <footer>agentvigil $version · zero dependencies · no daemon ·
  <a href="/api/scan">/api/scan</a> · <a href="/graph.svg">/graph.svg</a> ·
  <a href="/badge.svg">/badge.svg</a></footer>
</div>
</body>
</html>
"""
)


def _room(file: SurfaceFile) -> str:
    label = KIND_LABELS.get(file.kind, file.kind)
    return (
        f'<div class="room">{html_mod.escape(file.path)}'
        f"<span>{html_mod.escape(label)}</span></div>"
    )


def _card(finding: Finding) -> str:
    caps = ", ".join(finding.capabilities)
    ghost = ""
    if finding.decoded:
        ghost = (
            '<div class="ghost"><b>decoded</b>'
            f"{html_mod.escape(redact(finding.decoded)[:400])}</div>"
        )
    return (
        f'<article class="card {finding.severity.value}">'
        '<div class="head">'
        f'<span class="rule">{html_mod.escape(finding.rule_id)}</span>'
        f'<span class="where">{html_mod.escape(finding.path)}:{finding.line}:{finding.column}</span>'
        f'<span class="caps">{html_mod.escape(caps) or "—"}</span>'
        "</div>"
        f"<p>{html_mod.escape(redact(finding.message)[:400])}</p>"
        f"{ghost}"
        "</article>"
    )


def page(
    files: Sequence[SurfaceFile],
    findings: Sequence[Finding],
    graph_svg: str = "",
    version: str = "",
) -> str:
    value, grade, verdict = score(findings)
    rooms = "".join(_room(f) for f in files) or '<div class="room">no surface found</div>'
    cards = "".join(_card(f) for f in findings) or '<div class="card">clean — no apparitions</div>'
    ghosts = "".join(
        _card(f) for f in findings if f.decoded
    ) or '<div class="card">no hidden characters decoded</div>'
    return _PAGE.substitute(
        value=value,
        grade=grade,
        verdict=verdict,
        count=len(findings),
        files=len(files),
        rooms=rooms,
        cards=cards,
        ghosts=ghosts,
        graph=graph_svg,
        version=html_mod.escape(version),
    )
