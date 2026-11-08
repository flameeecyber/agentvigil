"""The daily-driver report UI: server-rendered, keyboard-first, zero assets.

Design goals, in order:

1. Answer three questions before scrolling: *what is urgent, what can the
   agent do, what do I run next.*
2. Never hide evidence behind a click that a reviewer cannot find with a
   keyboard. Progressive disclosure is `<details>`, not a JS-only modal.
3. Work offline and under a strict CSP: one stylesheet, two small scripts,
   no CDN, no fonts, no telemetry, no innerHTML with finding data.
4. Degrade cleanly: every finding is in the HTML, so filtering is an
   enhancement rather than a requirement.

`page()` is pure: given the same surface and findings it returns the same
bytes. The handler adds security headers and the CSP hashes exposed here.
"""

from __future__ import annotations

import base64
import hashlib
import html as html_mod
import math
from collections import Counter
from typing import Dict, Iterable, List, Sequence

from .findings import CAPABILITIES, Finding, Severity, summarize
from .redact import redact
from .score import breakdown, score
from .surface import KIND_LABELS, SurfaceFile, kinds_summary

__all__ = [
    "CSS",
    "csp",
    "favicon",
    "page",
    "ring",
]

# ---------------------------------------------------------------------------
# Tokens and layout
# ---------------------------------------------------------------------------

CSS = r"""
:root{
  color-scheme:dark;
  --bg:#0a0e13;--panel:#121a24;--panel-2:#0d141c;--line:#223041;--line-soft:#1a2532;
  --ink:#e6edf3;--dim:#9aa7b4;--faint:#6e7b88;--acc:#58a6ff;--ok:#3fb950;--warn:#d29922;--bad:#f85149;
  --crit:#ff7b72;--high:#ffa657;--med:#e3b341;--low:#79c0ff;--info:#8b949e;--focus:#58a6ff;
  --shadow:0 1px 0 rgba(255,255,255,.03),0 8px 24px rgba(0,0,0,.35);
}
@media (prefers-color-scheme:light){
  :root:not([data-theme=dark]){
    color-scheme:light;
    --bg:#f6f8fa;--panel:#ffffff;--panel-2:#f0f3f6;--line:#d1d9e0;--line-soft:#e4e8ec;
    --ink:#1f2328;--dim:#59636e;--faint:#6e7781;--acc:#0969da;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e;
    --crit:#cf222e;--high:#bc4c00;--med:#9a6700;--low:#0969da;--info:#59636e;--focus:#0969da;
    --shadow:0 1px 0 rgba(31,35,40,.03),0 8px 24px rgba(31,35,40,.08);
  }
}
:root[data-theme=light]{
  color-scheme:light;
  --bg:#f6f8fa;--panel:#ffffff;--panel-2:#f0f3f6;--line:#d1d9e0;--line-soft:#e4e8ec;
  --ink:#1f2328;--dim:#59636e;--faint:#6e7781;--acc:#0969da;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e;
  --crit:#cf222e;--high:#bc4c00;--med:#9a6700;--low:#0969da;--info:#59636e;--focus:#0969da;
  --shadow:0 1px 0 rgba(31,35,40,.03),0 8px 24px rgba(31,35,40,.08);
}
:root[data-theme=dark]{color-scheme:dark}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--acc);text-underline-offset:3px}
code,pre,kbd,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
h1,h2,h3,h4{line-height:1.25;margin:0}
p{margin:0}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.skip{position:fixed;left:12px;top:-70px;z-index:100;background:var(--panel);color:var(--ink);padding:10px 14px;border:1px solid var(--line);border-radius:8px;transition:top .15s}
.skip:focus{top:12px}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.wrap{width:100%;max-width:1180px;margin:0 auto;padding:0 20px}
.topbar{position:sticky;top:0;z-index:40;background:var(--bg);border-bottom:1px solid var(--line-soft)}
.topbar-in{display:flex;align-items:center;gap:12px;height:56px}
.brand{display:inline-flex;align-items:center;gap:8px;font-weight:700;color:var(--ink);text-decoration:none;letter-spacing:-.01em}
.brand .dot{width:9px;height:9px;border-radius:50%;background:var(--bad);box-shadow:0 0 0 4px rgba(248,81,73,.15)}
.tag{color:var(--dim);font-size:12px}
.spacer{flex:1}
.pill{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--line);background:var(--panel);border-radius:999px;padding:3px 9px;font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim)}
.pill.good{border-color:var(--ok);color:var(--ok)}
.pill.bad{border-color:var(--bad);color:var(--bad)}
.top-actions{display:flex;gap:6px;align-items:center}
.btn{appearance:none;border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:8px;padding:6px 10px;font:inherit;font-size:12px;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.btn:hover{border-color:var(--dim)}
.btn.ghost{background:transparent}
.hero{display:grid;grid-template-columns:auto 1fr;gap:30px;align-items:center;padding:34px 0 22px}
.eyebrow{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--faint);margin-bottom:8px}
h1{font-size:clamp(24px,3.4vw,34px);letter-spacing:-.02em;font-weight:650}
.grade{display:inline-block;margin-left:8px;padding:2px 9px;border-radius:7px;border:1px solid var(--line);background:var(--panel-2);font-size:15px;vertical-align:3px}
.grade-A{color:var(--ok);border-color:var(--ok)}
.grade-B{color:var(--low);border-color:var(--low)}
.grade-C{color:var(--warn);border-color:var(--warn)}
.grade-D{color:var(--high);border-color:var(--high)}
.grade-F{color:var(--bad);border-color:var(--bad)}
.verdict{color:var(--dim);max-width:72ch;margin-top:9px}
.verdict strong{color:var(--ink)}
.meta-line{color:var(--faint);font-size:12px;margin-top:8px;display:flex;flex-wrap:wrap;gap:4px 12px;align-items:center}
.kpis{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}
.kpi{min-width:96px;border:1px solid var(--line);background:var(--panel);border-radius:10px;padding:8px 11px}
.kpi b{display:block;font-size:17px;letter-spacing:-.01em}
.kpi span{font-size:10.5px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em}
.kpi.bad b{color:var(--crit)}
.kpi.good b{color:var(--ok)}
.ring{flex:0 0 auto;display:block}
.ring-track{stroke:var(--line)}
.ring-value{stroke:var(--ok);transition:stroke-dasharray .5s ease}
.grade-A .ring-value{stroke:var(--ok)}
.grade-B .ring-value{stroke:var(--low)}
.grade-C .ring-value{stroke:var(--warn)}
.grade-D .ring-value{stroke:var(--high)}
.grade-F .ring-value{stroke:var(--bad)}
.ring-score{fill:var(--ink);font:650 30px ui-monospace,SFMono-Regular,Menlo,monospace}
.ring-unit{fill:var(--faint);font:500 10px system-ui,sans-serif;letter-spacing:.06em}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:12px;border:1px solid var(--line);background:var(--panel);border-radius:12px;margin:6px 0 8px}
.search{position:relative;flex:1 1 260px;min-width:190px;display:flex;align-items:center}
.search input{width:100%;background:var(--panel-2);border:1px solid var(--line);border-radius:8px;color:var(--ink);padding:8px 34px 8px 10px;font:inherit;font-size:13px}
.search input::placeholder{color:var(--faint)}
.search kbd{position:absolute;right:8px;font-size:10px;color:var(--faint);border:1px solid var(--line);border-radius:4px;padding:1px 5px;background:var(--panel)}
.chips{display:flex;gap:4px;flex-wrap:wrap}
.chip{appearance:none;font:inherit;font-size:11px;padding:5px 8px;border-radius:999px;border:1px solid var(--line);background:transparent;color:var(--dim);cursor:pointer}
.chip b{font-weight:650;color:var(--ink);margin-left:3px}
.chip[aria-pressed=true]{border-color:var(--ink);color:var(--ink);background:var(--panel-2)}
.chip.sev-critical[aria-pressed=true]{border-color:var(--crit);color:var(--crit)}
.chip.sev-high[aria-pressed=true]{border-color:var(--high);color:var(--high)}
.chip.sev-medium[aria-pressed=true]{border-color:var(--med);color:var(--med)}
.chip.sev-low[aria-pressed=true]{border-color:var(--low);color:var(--low)}
.select{display:flex;flex-direction:column;gap:2px;font-size:9.5px;color:var(--faint);text-transform:uppercase;letter-spacing:.08em}
.select select{background:var(--panel-2);border:1px solid var(--line);border-radius:7px;color:var(--ink);padding:6px 8px;font:inherit;font-size:12px;max-width:190px}
.result-line{font-size:12px;color:var(--dim);margin:2px 2px 12px}
.sec-head{display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin:24px 0 9px}
.sec-head h2{font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:var(--dim)}
.count{font-size:11px;color:var(--faint);font-variant-numeric:tabular-nums}
.findings{display:grid;gap:10px}
.finding{position:relative;background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--sev,var(--info));border-radius:10px;padding:13px 15px;scroll-margin-top:130px;transition:border-color .15s}
.finding:hover{border-color:var(--dim)}
.finding:focus{outline:2px solid var(--focus);outline-offset:1px}
.finding[hidden]{display:none}
.sev-critical{--sev:var(--crit)}
.sev-high{--sev:var(--high)}
.sev-medium{--sev:var(--med)}
.sev-low{--sev:var(--low)}
.sev-info{--sev:var(--info)}
.f-top{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px}
.sev-label{font-size:10px;letter-spacing:.12em;text-transform:uppercase;font-weight:700;color:var(--sev)}
.sev-label::before{content:"";display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--sev);margin-right:5px;vertical-align:1px}
.rule{font-size:11px;color:var(--dim);background:var(--panel-2);border:1px solid var(--line-soft);padding:1px 6px;border-radius:5px}
.title{font-size:14px;font-weight:600;flex:1 1 320px;min-width:220px}
.where{appearance:none;border:0;background:transparent;color:var(--dim);font-size:11px;padding:2px 0;cursor:pointer;text-decoration:underline dotted;text-underline-offset:3px}
.where:hover{color:var(--ink)}
.msg{color:var(--dim);margin-top:6px;font-size:13px;max-width:105ch}
.f-meta{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;align-items:center}
.cap{font-size:10.5px;border:1px solid var(--line);border-radius:999px;padding:2px 7px;color:var(--ink);background:var(--panel-2)}
.cap.muted{color:var(--faint);border-style:dashed}
.tech,.conf{font-size:10.5px;color:var(--faint)}
.detail{margin-top:9px;border-top:1px solid var(--line-soft);padding-top:6px}
.detail summary{cursor:pointer;font-size:11.5px;color:var(--dim);width:max-content;padding:2px 0}
.detail summary:hover{color:var(--ink)}
.detail-body{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;margin-top:10px}
.detail h4{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin-bottom:4px}
pre{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:7px;padding:8px 10px;font-size:12px;line-height:1.5;overflow:auto;max-height:280px;white-space:pre-wrap;word-break:break-word;color:var(--ink)}
.decoded{margin-top:10px;border-left:2px solid var(--low);padding-left:10px}
.decoded pre{border-color:var(--low)}
.card-actions{display:flex;gap:6px;margin-top:10px}
.mini{font-size:11px;padding:3px 8px;border:1px solid var(--line);border-radius:6px;background:transparent;color:var(--dim);cursor:pointer;text-decoration:none}
.mini:hover{color:var(--ink);border-color:var(--dim)}
.panel{border:1px solid var(--line);background:var(--panel);border-radius:12px;padding:16px;margin-top:18px}
.panel h2{font-size:14px;letter-spacing:.02em}
.panel .sub{color:var(--dim);font-size:12px;margin-top:4px}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px;margin-top:10px}
table{border-collapse:collapse;width:100%;font-size:12px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line-soft);white-space:nowrap}
th{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);background:var(--panel-2)}
tr:last-child td{border-bottom:0}
td.path{white-space:normal}
button.path-filter{appearance:none;border:0;background:transparent;color:var(--acc);font:inherit;font-size:12px;padding:0;cursor:pointer;text-align:left}
button.path-filter:hover{text-decoration:underline}
.cap-list{list-style:none;padding:0;margin:10px 0 0;display:grid;gap:8px}
.cap-list li{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center}
.cap-list code{font-size:12px}
.cap-list .desc{color:var(--faint);font-size:11px;margin-left:6px}
.cap-list .num{font-size:11px;color:var(--dim);text-align:right}
meter{appearance:none;width:150px;height:8px;border:0;border-radius:999px;overflow:hidden;background:var(--panel-2)}
meter::-webkit-meter-bar{background:var(--panel-2);border:0}
meter::-webkit-meter-optimum-value{background:var(--warn)}
meter::-moz-meter-bar{background:var(--warn)}
.graph{border:1px solid var(--line);border-radius:10px;overflow:auto;margin-top:10px;background:#0d1117;max-height:460px}
.graph svg{display:block;min-width:760px}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:11px;color:var(--faint);margin-top:8px}
.legend .chain-edge{color:var(--bad)}
.chain{display:flex;gap:10px;padding:9px 0;border-bottom:1px solid var(--line-soft);align-items:baseline}
.chain:last-child{border:0}
.chain .msg{font-size:12px;margin-top:2px}
.actions{display:grid;gap:8px;margin-top:10px}
.action{display:flex;gap:8px;align-items:center;justify-content:space-between;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:8px 10px}
.action code{font-size:12px;overflow:auto;white-space:nowrap}
.empty{border:1px dashed var(--line);border-radius:12px;padding:40px 20px;text-align:center;color:var(--dim)}
.empty .big{font-size:30px;color:var(--ok);line-height:1}
.empty h2{font-size:16px;color:var(--ink);margin:8px 0 4px}
.empty p{font-size:12.5px}
#no-matches{margin-top:10px}
footer{margin:34px 0 50px;padding-top:14px;border-top:1px solid var(--line-soft);color:var(--faint);font-size:11.5px;display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center}
footer a{color:var(--dim)}
dialog{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:12px;padding:0;max-width:460px;width:calc(100% - 32px);box-shadow:var(--shadow)}
dialog::backdrop{background:rgba(0,0,0,.5)}
.dialog-in{padding:18px}
.dialog-in h2{font-size:15px;margin-bottom:10px}
.dialog-note{margin-top:12px}
.keys{display:grid;grid-template-columns:96px 1fr;gap:6px 12px;font-size:12px;color:var(--dim)}
.keys kbd{font-size:10.5px;border:1px solid var(--line);border-radius:4px;padding:1px 5px;background:var(--panel-2);color:var(--ink);width:max-content}
#toast{position:fixed;left:50%;bottom:18px;transform:translate(-50%,12px);background:var(--ink);color:var(--bg);padding:8px 12px;border-radius:999px;font-size:12px;opacity:0;pointer-events:none;transition:opacity .18s,transform .18s;z-index:80}
#toast.show{opacity:1;transform:translate(-50%,0)}
.menu{position:relative;display:inline-flex}
.menu>summary{list-style:none;cursor:pointer}
.menu>summary::-webkit-details-marker{display:none}
.menu>summary::after{content:"▾";font-size:10px;color:var(--faint);margin-left:2px}
.menu[open]>summary{border-color:var(--dim);color:var(--ink)}
.menu-pop{position:absolute;right:0;top:calc(100% + 6px);z-index:60;min-width:196px;background:var(--panel);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow);padding:5px;display:grid;gap:1px}
.menu-pop a{display:block;padding:7px 9px;border-radius:6px;color:var(--ink);text-decoration:none;font-size:12px;white-space:nowrap}
.menu-pop a:hover{background:var(--panel-2)}
.menu-pop .hint{font-size:10px;color:var(--faint);padding:5px 9px 3px;border-top:1px solid var(--line-soft);margin-top:3px}
.toolbar-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;flex-basis:100%;padding-top:9px;border-top:1px solid var(--line-soft)}
.review-modes{display:flex;gap:2px;border:1px solid var(--line);border-radius:999px;padding:2px;background:var(--panel-2)}
.review-modes .chip{border:0;background:transparent;padding:3px 8px;font-size:10.5px}
.review-modes .chip[aria-pressed=true]{background:var(--panel);box-shadow:0 1px 2px rgba(0,0,0,.2)}
.review-count{font-size:11.5px;color:var(--dim);font-variant-numeric:tabular-nums}
.needs-js{display:none!important}
.js .needs-js.flex{display:flex!important}
.js .needs-js.inline-flex{display:inline-flex!important}
.js .needs-js.block{display:block!important}
.riskbar{display:flex;gap:1px;height:7px;margin:0 0 10px;padding:1px;border:1px solid var(--line-soft);border-radius:999px;background:var(--panel-2);overflow:hidden}
.riskbar span{flex:1;min-width:2px;height:100%;border-radius:1px}
.rb-critical{background:var(--crit)}
.rb-high{background:var(--high)}
.rb-medium{background:var(--med)}
.rb-low{background:var(--low)}
.rb-info{background:var(--info)}
.finding[data-reviewed="1"]{opacity:.62}
.finding[data-reviewed="1"]:hover,.finding[data-reviewed="1"]:focus-within{opacity:1}
.review-state{display:none;font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--ok);border:1px solid var(--ok);border-radius:999px;padding:1px 6px}
.finding[data-reviewed="1"] .review-state{display:inline-block}
.mini[aria-pressed=true]{border-color:var(--ok);color:var(--ok)}
.chip.sev-urgent[aria-pressed=true]{border-color:var(--high);color:var(--high)}
[data-density=compact] .finding{padding:9px 12px}
[data-density=compact] .msg{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
[data-density=compact] .f-meta{margin-top:5px}
[data-density=compact] .card-actions{margin-top:7px}
[data-density=compact] .sec-head{margin-top:16px}
@media (max-width:760px){
  .hero{grid-template-columns:1fr;gap:16px}
  .topbar-in{height:auto;min-height:56px;flex-wrap:wrap;row-gap:4px;padding:6px 0}
  .topbar .tag{display:none}
  .top-actions{width:100%;justify-content:flex-end;flex-wrap:wrap;gap:4px}
  .top-actions .readonly,#print{display:none}
  .top-actions .btn{padding:5px 8px}
  .toolbar{padding:10px}
  .search{flex-basis:100%}
  .chips{flex-wrap:nowrap;overflow-x:auto;max-width:100%;padding-bottom:2px}
  .select{flex:1 1 120px}
  .select select{max-width:none;width:100%}
  .toolbar-row{gap:6px}
  .review-count{order:4;flex-basis:100%}
  #copy-summary{margin-left:auto}
  .finding{padding:11px}
  .title{flex-basis:100%}
  .riskbar{height:6px}
}
@media (prefers-reduced-motion:reduce){
  *{scroll-behavior:auto!important;transition:none!important;animation:none!important}
}
@media print{
  body{background:#fff;color:#111}
  .topbar,.toolbar,.card-actions,.top-actions,#toast,.skip,.result-line{display:none!important}
  .finding,.panel{break-inside:avoid;border:1px solid #bbb;background:#fff}
  .detail>:not(summary){display:block!important}
  footer{color:#444}
}
"""

_THEME_JS = r"""
document.documentElement.classList.add("js");
try{var t=localStorage.getItem("vigil-theme");if(t==="light"||t==="dark"){document.documentElement.setAttribute("data-theme",t)}}catch(e){}
"""

_APP_JS = r"""
(function(){
  "use strict";
  var root=document.documentElement;
  root.classList.add("js");
  var $=function(s,c){return (c||document).querySelector(s)};
  var $$=function(s,c){return Array.prototype.slice.call((c||document).querySelectorAll(s))};
  var cards=$$(".finding");
  var search=$("#q"), list=$("#findings-list"), count=$("#result-count");
  var cap=$("#cap"), sort=$("#sort"), noMatch=$("#no-matches");
  var state={q:"",sev:"all",cap:"all",sort:"worst",review:"all",fix:false};
  var toastEl=$("#toast"), toastTimer;
  var rootName=document.body.getAttribute("data-root")||"this repository";
  var score=document.body.getAttribute("data-score")||"?";
  var grade=document.body.getAttribute("data-grade")||"?";
  var REVIEW_KEY="vigil-reviewed:"+rootName;
  var reviewed={};
  function toast(msg){
    if(!toastEl) return;
    toastEl.textContent=msg; toastEl.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer=setTimeout(function(){toastEl.classList.remove("show")},1600);
  }
  function fallbackCopy(text,done){
    var ta=document.createElement("textarea");
    ta.value=text; ta.setAttribute("readonly",""); ta.style.position="fixed"; ta.style.top="-1000px";
    document.body.appendChild(ta); ta.select();
    try{document.execCommand("copy")}catch(e){}
    document.body.removeChild(ta); done();
  }
  function copy(text,btn){
    function done(){
      toast("Copied to clipboard");
      if(btn){btn.setAttribute("data-copied","1");setTimeout(function(){btn.removeAttribute("data-copied")},900)}
    }
    if(navigator.clipboard&&window.isSecureContext){
      navigator.clipboard.writeText(text).then(done,function(){fallbackCopy(text,done)});
    }else{fallbackCopy(text,done)}
  }
  function loadReviews(){
    try{
      var raw=localStorage.getItem(REVIEW_KEY);
      var obj=raw?JSON.parse(raw):null;
      if(obj&&typeof obj==="object"&&!Array.isArray(obj)){
        Object.keys(obj).forEach(function(k){if(obj[k]) reviewed[k]=1});
      }
    }catch(e){}
  }
  function keyOf(card){return card.getAttribute("data-key")||""}
  function isReviewed(card){return card.getAttribute("data-reviewed")==="1"}
  function countReviewed(){
    var n=0;
    cards.forEach(function(c){if(isReviewed(c)) n++});
    return n;
  }
  function updateReviewStatus(){
    var n=countReviewed(), total=cards.length;
    var rc=$("#review-count"); if(rc) rc.textContent=n+" of "+total+" reviewed";
    var rn=$("#reviewed-n"); if(rn) rn.textContent=String(n);
    var rt=$("#reviewed-total"); if(rt) rt.textContent=String(total);
  }
  function writeReviews(){
    var obj={};
    cards.forEach(function(c){
      if(isReviewed(c)){var k=keyOf(c); if(k) obj[k]=1}
    });
    try{localStorage.setItem(REVIEW_KEY,JSON.stringify(obj))}catch(e){}
  }
  function focusAfter(card){
    var next=null, i;
    for(i=cards.indexOf(card)+1;i<cards.length;i++){if(!cards[i].hidden){next=cards[i];break}}
    if(!next){for(i=0;i<cards.length;i++){if(!cards[i].hidden){next=cards[i];break}}}
    if(next) next.focus();
  }
  function mark(card,on,persist){
    if(!card) return;
    var hadFocus=card.contains(document.activeElement);
    card.setAttribute("data-reviewed",on?"1":"0");
    var btn=card.querySelector("[data-review]");
    if(btn){
      btn.setAttribute("aria-pressed",on?"true":"false");
      btn.textContent=on?"Reviewed ✓":"Mark reviewed";
      btn.setAttribute("aria-label",(on?"Unmark ":"Mark ")+card.getAttribute("data-where")+" as reviewed");
    }
    if(!persist) return;
    writeReviews(); updateReviewStatus(); apply();
    if(hadFocus&&card.hidden) focusAfter(card);
  }
  var densityBtn=$("#density");
  var density="comfortable";
  try{density=localStorage.getItem("vigil-density")||"comfortable"}catch(e){}
  if(density!=="compact") density="comfortable";
  function syncDensity(){
    if(density==="compact") root.setAttribute("data-density","compact");
    else root.removeAttribute("data-density");
    if(densityBtn){
      densityBtn.setAttribute("aria-pressed",density==="compact"?"true":"false");
      densityBtn.textContent=density==="compact"?"Comfortable":"Compact";
    }
    try{localStorage.setItem("vigil-density",density)}catch(e){}
  }
  if(densityBtn){
    syncDensity();
    densityBtn.addEventListener("click",function(){
      density=density==="compact"?"comfortable":"compact";
      syncDensity();
    });
  }
  var keys=$("#keys"), themeBtn=$("#theme");
  var modes=["auto","light","dark"], mode="auto";
  try{mode=localStorage.getItem("vigil-theme")||"auto"}catch(e){}
  function syncTheme(){
    if(mode==="auto") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme",mode);
    if(themeBtn) themeBtn.textContent="Theme: "+mode;
    try{localStorage.setItem("vigil-theme",mode)}catch(e){}
  }
  if(themeBtn){
    syncTheme();
    themeBtn.addEventListener("click",function(){
      mode=modes[(modes.indexOf(mode)+1)%modes.length]; syncTheme();
    });
  }
  var printBtn=$("#print");
  if(printBtn) printBtn.addEventListener("click",function(){window.print()});
  var keysBtn=$("#keys-open");
  if(keysBtn&&keys) keysBtn.addEventListener("click",function(){keys.showModal()});
  if(!cards.length){return}
  loadReviews();
  cards.forEach(function(c){if(reviewed[keyOf(c)]) mark(c,true,false)});
  updateReviewStatus();
  function norm(s){return (s||"").toLowerCase()}
  function visible(){return cards.filter(function(c){return !c.hidden})}
  function apply(push){
    state.q=norm(search.value).trim();
    var terms=state.q.split(/\s+/).filter(Boolean), shown=0;
    cards.forEach(function(card){
      var hay=card.getAttribute("data-search")||"", ok=true, i;
      for(i=0;i<terms.length;i++){if(hay.indexOf(terms[i])===-1){ok=false;break}}
      if(ok&&state.sev!=="all"){
        var sev=card.getAttribute("data-sev");
        if(state.sev==="urgent"?(sev!=="critical"&&sev!=="high"):sev!==state.sev) ok=false;
      }
      if(ok&&state.cap!=="all"&&(card.getAttribute("data-caps")||"").split("|").indexOf(state.cap)===-1) ok=false;
      if(ok&&state.review==="unreviewed"&&isReviewed(card)) ok=false;
      if(ok&&state.review==="reviewed"&&!isReviewed(card)) ok=false;
      if(ok&&state.fix&&card.getAttribute("data-fixable")!=="1") ok=false;
      card.hidden=!ok; if(ok) shown++;
    });
    $$("[data-sev-filter]").forEach(function(b){
      b.setAttribute("aria-pressed",String(b.getAttribute("data-sev-filter")===state.sev));
    });
    $$("[data-review-filter]").forEach(function(b){
      b.setAttribute("aria-pressed",String(b.getAttribute("data-review-filter")===state.review));
    });
    var fixBtn=$("#fix-only");
    if(fixBtn) fixBtn.setAttribute("aria-pressed",state.fix?"true":"false");
    if(count){
      count.textContent=(shown===cards.length)?"Showing all "+cards.length+" findings":"Showing "+shown+" of "+cards.length+" findings";
    }
    if(noMatch) noMatch.hidden=(shown!==0);
    if(push!==false){
      try{
        var u=new URL(window.location.href);
        if(state.q) u.searchParams.set("q",state.q); else u.searchParams.delete("q");
        if(state.sev!=="all") u.searchParams.set("sev",state.sev); else u.searchParams.delete("sev");
        if(state.cap!=="all") u.searchParams.set("cap",state.cap); else u.searchParams.delete("cap");
        if(state.sort!=="worst") u.searchParams.set("sort",state.sort); else u.searchParams.delete("sort");
        if(state.review!=="all") u.searchParams.set("review",state.review); else u.searchParams.delete("review");
        if(state.fix) u.searchParams.set("fix","1"); else u.searchParams.delete("fix");
        history.replaceState(null,"",u);
      }catch(e){}
    }
  }
  function sortCards(){
    var arr=cards.slice(), key=state.sort;
    arr.sort(function(a,b){
      if(key==="file"||key==="rule"){
        var x=a.getAttribute(key==="file"?"data-path":"data-rule")||"";
        var y=b.getAttribute(key==="file"?"data-path":"data-rule")||"";
        if(x!==y) return x<y?-1:1;
      }
      var ra=+a.getAttribute("data-rank"), rb=+b.getAttribute("data-rank");
      if(rb!==ra) return rb-ra;
      var pa=a.getAttribute("data-path")||"", pb=b.getAttribute("data-path")||"";
      if(pa!==pb) return pa<pb?-1:1;
      return (+a.getAttribute("data-line"))-(+b.getAttribute("data-line"));
    });
    arr.forEach(function(c){list.appendChild(c)});
  }
  function copySummary(){
    var v=visible();
    if(!v.length){toast("Nothing visible to copy");return}
    var lines=["## agentvigil — "+rootName,"",
      "**Trust:** "+score+"/100 (grade "+grade+") · "+cards.length+" findings · "+countReviewed()+" reviewed",""];
    v.forEach(function(c){
      var titleEl=c.querySelector(".title");
      lines.push("- ["+(isReviewed(c)?"x":" ")+"] **"+String(c.getAttribute("data-sev")).toUpperCase()+"** `"+
        c.getAttribute("data-rule")+"` — `"+c.getAttribute("data-where")+"` — "+
        (titleEl?titleEl.textContent.trim():""));
    });
    lines.push("","Filtered view: "+window.location.href);
    copy(lines.join("\n"),null);
  }
  var summaryBtn=$("#copy-summary");
  if(summaryBtn) summaryBtn.addEventListener("click",copySummary);
  var clearReviewsBtn=$("#clear-reviews");
  if(clearReviewsBtn) clearReviewsBtn.addEventListener("click",function(){
    if(!countReviewed()){toast("No review marks to clear");return}
    if(!window.confirm("Clear all review marks for "+rootName+" in this browser?")) return;
    try{localStorage.removeItem(REVIEW_KEY)}catch(e){}
    cards.forEach(function(c){mark(c,false,false)});
    updateReviewStatus(); apply(); toast("Review marks cleared");
  });
  $$("[data-review-filter]").forEach(function(b){
    b.addEventListener("click",function(){state.review=b.getAttribute("data-review-filter");apply()});
  });
  var fixBtn=$("#fix-only");
  if(fixBtn) fixBtn.addEventListener("click",function(){state.fix=!state.fix;apply()});
  var params=new URLSearchParams(window.location.search);
  var q0=params.get("q"); if(q0) search.value=q0;
  var sev0=params.get("sev");
  if(["all","urgent","critical","high","medium","low","info"].indexOf(sev0)!==-1) state.sev=sev0;
  var cap0=params.get("cap");
  if(cap0){for(var i=0;i<cap.options.length;i++){if(cap.options[i].value===cap0){state.cap=cap0;cap.value=cap0;break}}}
  var sort0=params.get("sort");
  if(["worst","file","rule"].indexOf(sort0)!==-1){state.sort=sort0;sort.value=sort0}
  var review0=params.get("review");
  if(["all","unreviewed","reviewed"].indexOf(review0)!==-1) state.review=review0;
  if(params.get("fix")==="1") state.fix=true;
  sortCards(); apply(false);
  search.addEventListener("input",function(){clearTimeout(window.__vigilT);window.__vigilT=setTimeout(apply,80)});
  $$("[data-sev-filter]").forEach(function(b){
    b.addEventListener("click",function(){state.sev=b.getAttribute("data-sev-filter");apply()});
  });
  cap.addEventListener("change",function(){state.cap=cap.value;apply()});
  sort.addEventListener("change",function(){state.sort=sort.value;sortCards();apply()});
  var clearBtn=$("#clear");
  if(clearBtn) clearBtn.addEventListener("click",function(){
    search.value="";state.sev="all";state.cap="all";state.sort="worst";state.review="all";state.fix=false;
    cap.value="all";sort.value="worst";sortCards();apply();
  });
  var expandBtn=$("#expand");
  if(expandBtn) expandBtn.addEventListener("click",function(){
    var open=expandBtn.getAttribute("data-open")!=="1";
    $$(".finding details").forEach(function(d){d.open=open});
    expandBtn.setAttribute("data-open",open?"1":"0");
    expandBtn.textContent=open?"Collapse all":"Expand all";
  });
  function focusCard(dir){
    var v=visible(); if(!v.length) return;
    var cur=document.activeElement&&document.activeElement.closest?document.activeElement.closest(".finding"):null;
    var idx=cur?v.indexOf(cur):-1;
    var next=dir>0?((idx+1)%v.length):((idx<=0?v.length-1:idx-1));
    v[next].focus(); v[next].scrollIntoView({block:"nearest"});
  }
  document.addEventListener("click",function(e){
    $$("details.menu").forEach(function(d){if(d.open&&!d.contains(e.target)) d.open=false});
  },true);
  document.addEventListener("click",function(e){
    var reviewBtn=e.target.closest("[data-review]");
    if(reviewBtn){
      var card=reviewBtn.closest(".finding");
      if(card){var on=!isReviewed(card);mark(card,on,true);toast(on?"Marked reviewed":"Marked unreviewed")}
      return;
    }
    var btn=e.target.closest("[data-copy],[data-copy-finding]");
    if(btn){
      if(btn.hasAttribute("data-copy-finding")){
        var c=btn.closest(".finding");
        if(c){
          var msg=c.querySelector(".msg");
          var fix=c.getAttribute("data-fix")||"";
          copy(c.getAttribute("data-sev").toUpperCase()+" "+c.getAttribute("data-rule")+" — "+
               c.getAttribute("data-where")+"\n"+(msg?msg.textContent:"")+(fix?"\nfix: "+fix:""),btn);
        }
      }else{copy(btn.getAttribute("data-copy"),btn)}
      return;
    }
    var pf=e.target.closest("[data-path-filter]");
    if(pf&&search){
      e.preventDefault();
      search.value=pf.getAttribute("data-path-filter");
      apply();
      var target=$("#findings");
      if(target) target.scrollIntoView({block:"start"});
      toast("Filtered to "+search.value);
      return;
    }
    var close=e.target.closest("[data-close]");
    if(close){var d=close.closest("dialog"); if(d) d.close()}
  });
  document.addEventListener("keydown",function(e){
    if(e.defaultPrevented) return;
    var tag=(e.target.tagName||"").toLowerCase();
    var typing=tag==="input"||tag==="textarea"||tag==="select"||e.target.isContentEditable;
    if(e.key==="/"&&!typing){e.preventDefault();search.focus();search.select();return}
    if(e.key==="?"&&!typing){e.preventDefault();if(keys) keys.showModal();return}
    if(e.key==="Escape"){
      if(keys&&keys.open){keys.close();return}
      if(search.value){search.value="";apply()}
      return;
    }
    if(typing) return;
    if(e.key==="j"){e.preventDefault();focusCard(1);return}
    if(e.key==="k"){e.preventDefault();focusCard(-1);return}
    if(e.key==="r"){
      var focused=document.activeElement&&document.activeElement.closest?document.activeElement.closest(".finding"):null;
      if(focused){e.preventDefault();var on=!isReviewed(focused);mark(focused,on,true);toast(on?"Marked reviewed":"Marked unreviewed")}
      return;
    }
    if(e.key==="s"){e.preventDefault();copySummary();return}
    if(e.key==="d"&&densityBtn){e.preventDefault();densityBtn.click();return}
    if(e.key==="e"&&expandBtn){e.preventDefault();expandBtn.click();return}
    if(e.key==="c"){
      var f=document.activeElement&&document.activeElement.closest?document.activeElement.closest(".finding"):null;
      if(f){e.preventDefault();copy(f.getAttribute("data-where"),null)}
    }
  });
  list.addEventListener("keydown",function(e){
    if(e.key==="Enter"&&e.target.classList.contains("finding")){
      var d=e.target.querySelector("details");
      if(d){e.preventDefault();d.open=!d.open}
    }
  });
})();
"""


# ---------------------------------------------------------------------------
# CSP, icon, small helpers
# ---------------------------------------------------------------------------


def _b64(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def csp(theme: bool = False) -> str:
    """Content-Security-Policy for the report.

    The plain page uses hashes, not ``unsafe-inline``: the two scripts and the
    one stylesheet are constants, so the browser can verify exactly those.
    The Kiroween theme is a separate self-contained document and needs inline
    style attributes for its score meter, so it gets a style-only allowance.
    """
    base = (
        "default-src 'none'; img-src 'self' data:; connect-src 'none'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    if theme:
        return base + "; style-src 'unsafe-inline'; script-src 'none'"
    styles = "'sha256-" + _b64(CSS) + "'"
    scripts = " ".join("'sha256-" + _b64(s) + "'" for s in (_THEME_JS, _APP_JS))
    return base + "; style-src " + styles + "; script-src " + scripts


def favicon() -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">'
        '<rect width="32" height="32" rx="8" fill="#0d1117"/>'
        '<path d="M4 16s5-8 12-8 12 8 12 8-5 8-12 8S4 16 4 16Z" fill="none" '
        'stroke="#58a6ff" stroke-width="2"/>'
        '<circle cx="16" cy="16" r="4" fill="#f85149"/></svg>'
    )


_RING_C = 2 * math.pi * 52


def ring(value: int, grade: str, size: int = 132) -> str:
    value = max(0, min(100, int(value)))
    dash = _RING_C * value / 100.0
    return (
        f'<svg class="ring grade-{html_mod.escape(grade)}" width="{size}" height="{size}" '
        'viewBox="0 0 120 120" role="img" '
        f'aria-label="Trust score {value} out of 100, grade {html_mod.escape(grade)}">'
        '<circle class="ring-track" cx="60" cy="60" r="52" fill="none" stroke-width="9"/>'
        f'<circle class="ring-value" cx="60" cy="60" r="52" fill="none" stroke-width="9" '
        f'stroke-linecap="round" stroke-dasharray="{dash:.1f} {_RING_C:.1f}" '
        'transform="rotate(-90 60 60)"/>'
        f'<text class="ring-score" x="60" y="59" text-anchor="middle">{value}</text>'
        '<text class="ring-unit" x="60" y="77" text-anchor="middle">/ 100</text></svg>'
    )


def _esc(value: object) -> str:
    return html_mod.escape(str(value), quote=True)


def _human_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _search_blob(finding: Finding) -> str:
    blob = " ".join(
        (
            finding.severity.value,
            finding.rule_id,
            finding.path,
            finding.title,
            redact(finding.message),
            " ".join(finding.capabilities),
            finding.technique,
        )
    ).lower()
    return " ".join(blob.split())


def _review_key(finding: Finding) -> str:
    """Stable browser-scope key for a finding.

    Content is part of the key: if the rule, path, line or title changes, the
    finding is a new review item rather than silently inheriting a stale tick.
    """
    raw = "\x1f".join(
        (finding.rule_id, finding.path, str(finding.line), finding.title)
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _finding_card(index: int, finding: Finding) -> str:
    severity = finding.severity.value
    caps = [c for c in finding.capabilities if c]
    cap_pills = "".join(
        '<span class="cap" title="' + _esc(CAPABILITIES.get(c, "")) + '">' + _esc(c) + "</span>"
        for c in caps
    ) or '<span class="cap muted">no capability recorded</span>'
    evidence = redact(finding.evidence)[:800] if finding.evidence else ""
    evidence_block = (
        '<pre tabindex="0">' + _esc(evidence) + "</pre>"
        if evidence
        else '<p class="sub">No captured span.</p>'
    )
    decoded = ""
    if finding.decoded:
        decoded = (
            '<div class="decoded"><h4>Decoded payload (shown, never executed)</h4>'
            '<pre tabindex="0">' + _esc(redact(finding.decoded)[:1600]) + "</pre></div>"
        )
    remediation = (
        '<p class="sub">' + _esc(finding.remediation) + "</p>"
        if finding.remediation
        else '<p class="sub">No automated fix — review the instruction before granting this surface.</p>'
    )
    technique = finding.technique or "—"
    fix_attr = " ".join(redact(finding.remediation or "").split())[:240]
    return f"""
<article class="finding sev-{html_mod.escape(severity)}" id="f{index}" tabindex="-1"
  data-sev="{html_mod.escape(severity)}" data-rank="{finding.severity.rank}"
  data-rule="{_esc(finding.rule_id)}" data-path="{_esc(finding.path)}"
  data-line="{finding.line}" data-where="{_esc(finding.path)}:{finding.line}"
  data-caps="{_esc('|'.join(caps))}" data-fix="{_esc(fix_attr)}"
  data-key="{_review_key(finding)}" data-fixable="{1 if finding.remediation.strip() else 0}"
  data-reviewed="0" data-search="{_esc(_search_blob(finding))}">
  <div class="f-top">
    <span class="sev-label">{html_mod.escape(severity)}</span>
    <span class="review-state" aria-hidden="true">reviewed</span>
    <span class="rule">{_esc(finding.rule_id)}</span>
    <h3 class="title">{_esc(finding.title)}</h3>
    <button type="button" class="where" data-copy="{_esc(finding.path)}:{finding.line}"
      title="Copy path:line">{_esc(finding.path)}:{finding.line}</button>
  </div>
  <p class="msg">{_esc(redact(finding.message))}</p>
  <div class="f-meta">
    {cap_pills}
    <span class="tech">technique {_esc(technique)}</span>
    <span class="conf">{_esc(finding.confidence)} confidence</span>
  </div>
  <details class="detail">
    <summary>Evidence &amp; fix</summary>
    <div class="detail-body">
      <div><h4>Evidence</h4>{evidence_block}</div>
      <div><h4>Granted capability</h4><p class="sub">{_esc(
          "; ".join(CAPABILITIES.get(c, c) for c in caps) or "none recorded"
      )}</p></div>
      <div><h4>Remediation</h4>{remediation}</div>
      <div><h4>Detection</h4><p class="sub">{_esc(finding.detector)} ·
        {_esc(finding.confidence)} confidence · technique {_esc(technique)}</p></div>
    </div>
    {decoded}
  </details>
  <div class="card-actions">
    <button type="button" class="mini needs-js inline-flex" data-review aria-pressed="false"
      aria-label="{_esc('Mark ' + finding.path + ':' + str(finding.line) + ' as reviewed')}">Mark reviewed</button>
    <button type="button" class="mini" data-copy-finding>Copy finding</button>
    <a class="mini" href="#f{index}">Permalink</a>
  </div>
</article>"""


def _severity_chips(findings: Sequence[Finding]) -> str:
    counts = summarize(findings)
    urgent = counts["critical"] + counts["high"]
    chips = [
        f'<button type="button" class="chip" data-sev-filter="all" aria-pressed="true">'
        f"All<b>{len(findings)}</b></button>",
        f'<button type="button" class="chip sev-urgent" data-sev-filter="urgent" '
        f'aria-pressed="false">urgent<b>{urgent}</b></button>',
    ]
    for severity in Severity:
        n = counts[severity.value]
        chips.append(
            f'<button type="button" class="chip sev-{severity.value}" '
            f'data-sev-filter="{severity.value}" aria-pressed="false">'
            f"{severity.value}<b>{n}</b></button>"
        )
    return "".join(chips)


def _risk_strip(findings: Sequence[Finding]) -> str:
    """One block per finding, grouped by severity, with no inline styles."""
    counts = summarize(findings)
    if not findings:
        return ""
    spans = "".join(
        f'<span class="rb-{severity.value}" title="{counts[severity.value]} {severity.value}"></span>'
        for severity in Severity
        for _ in range(counts[severity.value])
    )
    label = ", ".join(
        f"{counts[severity.value]} {severity.value}"
        for severity in Severity
        if counts[severity.value]
    )
    return (
        '<div class="riskbar" role="img" aria-label="Severity distribution: '
        + _esc(label)
        + '">'
        + spans
        + "</div>"
    )


def _capability_options(findings: Sequence[Finding]) -> str:
    counts = Counter(c for f in findings for c in f.capabilities)
    options = ['<option value="all">All capabilities</option>']
    for cap, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        options.append(f'<option value="{_esc(cap)}">{_esc(cap)} ({counts[cap]})</option>')
    return "".join(options)


def _capability_panel(findings: Sequence[Finding]) -> str:
    penalties = breakdown(findings)
    if not penalties:
        return ""
    counts = Counter(c for f in findings for c in f.capabilities)
    maximum = max(penalties.values()) or 1
    rows: List[str] = []
    for cap, penalty in list(penalties.items())[:8]:
        rows.append(
            "<li><div><code>" + _esc(cap) + "</code>"
            '<span class="desc">' + _esc(CAPABILITIES.get(cap, "uncategorised")) + "</span></div>"
            '<div class="num"><meter min="0" max="' + str(maximum) + '" value="' + str(penalty)
            + '">' + str(penalty) + "</meter> "
            + str(counts.get(cap, 0)) + " finding(s)</div></li>"
        )
    return (
        '<section class="panel" aria-labelledby="caps-title">'
        '<h2 id="caps-title">What an agent can do here</h2>'
        '<p class="sub">Penalty weight per capability. This is the blast radius, not a count of alerts.</p>'
        '<ul class="cap-list">' + "".join(rows) + "</ul></section>"
    )


def _surface_table(files: Sequence[SurfaceFile], findings: Sequence[Finding]) -> str:
    counts = Counter(f.path for f in findings)
    rows = "".join(
        "<tr>"
        f'<td class="path"><button type="button" class="path-filter" '
        f'data-path-filter="{_esc(f.path)}" title="Show findings in this file">{_esc(f.path)}</button></td>'
        f"<td>{_esc(KIND_LABELS.get(f.kind, f.kind))}</td>"
        f"<td>{_human_size(f.size)}</td>"
        f"<td>{counts.get(f.path, 0)}</td>"
        f'<td class="mono">{_esc(f.sha256[:10])}</td>'
        "</tr>"
        for f in files
    )
    if not rows:
        rows = '<tr><td colspan="5">No instruction surface found under this root.</td></tr>'
    return (
        '<section class="panel" aria-labelledby="surface-title">'
        '<h2 id="surface-title">Surface inventory</h2>'
        '<p class="sub">Every file an agent may read as instructions. Click a path to filter the findings.</p>'
        '<div class="table-wrap"><table><thead><tr><th>file</th><th>kind</th><th>size</th>'
        "<th>findings</th><th>sha256</th></tr></thead><tbody>" + rows
        + "</tbody></table></div></section>"
    )


def _chains(findings: Sequence[Finding]) -> str:
    chains = [f for f in findings if f.rule_id.startswith("AV-CHAIN-")]
    if not chains:
        return (
            '<section class="panel" aria-labelledby="chains-title">'
            '<h2 id="chains-title">Kill chains</h2>'
            '<p class="sub">No chain fires. The findings above do not connect into an end-to-end path on this surface.</p>'
            "</section>"
        )
    rows = "".join(
        '<div class="chain"><div><span class="rule">' + _esc(c.rule_id) + "</span> "
        '<strong>' + _esc(c.title) + "</strong>"
        '<p class="msg">' + _esc(redact(c.message)) + "</p></div></div>"
        for c in chains
    )
    return (
        '<section class="panel" aria-labelledby="chains-title">'
        '<h2 id="chains-title">Kill chains</h2>'
        '<p class="sub">Findings that compose into a path from instruction to impact.</p>'
        + rows + "</section>"
    )


def _actions(clean: bool = False) -> str:
    commands = (
        ("Pin this surface", "vigil manifest . -o vigil.lock"),
        ("Gate the next change", "vigil diff --lock vigil.lock --fail-on high"),
    )
    if not clean:
        commands = (
            ("Strip invisible characters (dry run first)", "vigil fix ."),
            ("Apply the safe fix", "vigil fix . --apply"),
        ) + commands
    heading = "Keep it clean" if clean else "Make it stick"
    rows = "".join(
        '<div class="action"><code>' + _esc(cmd) + '</code>'
        f'<button type="button" class="mini" data-copy="{_esc(cmd)}">Copy</button></div>'
        for _, cmd in commands
    )
    return (
        '<section class="panel" aria-labelledby="actions-title">'
        '<h2 id="actions-title">' + heading + '</h2>'
        '<p class="sub">Run from the repository root. This page is read-only; nothing here writes to disk.</p>'
        '<div class="actions">' + rows + "</div></section>"
    )


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------


def page(
    files: Sequence[SurfaceFile],
    findings: Sequence[Finding],
    *,
    graph_svg: str = "",
    version: str = "",
    root_label: str = "",
    lock_present: bool = False,
    duration_ms: int | None = None,
) -> str:
    value, grade, verdict = score(findings)
    critical_high = sum(
        1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    caps = sorted({c for f in findings for c in f.capabilities})
    fixable = sum(1 for f in findings if f.remediation.strip())
    root_label = root_label or "this repository"
    review_kpi = (
        '<div class="kpi needs-js block" title="Review marks stay in this browser; nothing is sent to the server">'
        f'<b><span id="reviewed-n">0</span>/<span id="reviewed-total">{len(findings)}</span></b>'
        "<span>reviewed</span></div>"
        if findings
        else ""
    )
    counts = kinds_summary(files)
    kind_text = ", ".join(
        f"{n} {KIND_LABELS.get(k, k)}" for k, n in sorted(counts.items())
    )
    if value >= 90:
        advice = "Pin it, then review every change to the surface."
    elif value >= 75:
        advice = "Mostly clean — a few instructions deserve a second read."
    elif value >= 50:
        advice = "An agent reading this surface can do more than the task needs."
    else:
        advice = "Do not let an agent run here until the findings below are fixed."

    lock_pill = (
        '<span class="pill good" title="vigil.lock exists in this root">pinned</span>'
        if lock_present
        else '<span class="pill bad" title="No vigil.lock: nothing to diff against">unpinned</span>'
    )
    scanned = f'<span>scanned in {duration_ms} ms</span>' if duration_ms is not None else ""

    if findings:
        cards_html = "".join(_finding_card(i, f) for i, f in enumerate(findings, 1))
        findings_section = f"""
{_risk_strip(findings)}
<p class="result-line"><span id="result-count" role="status" aria-live="polite">Showing all {len(findings)} findings</span></p>
<div class="findings" id="findings-list">{cards_html}</div>
<div class="empty" id="no-matches" hidden>
  <h2>No findings match</h2>
  <p>Clear the search or choose another severity. Press <kbd>Esc</kbd> to reset the query.</p>
</div>"""
        toolbar = f"""
<div class="toolbar" role="search" aria-label="Filter findings">
  <label class="search">
    <span class="sr-only">Search findings</span>
    <input id="q" type="search" placeholder="Search rule, path, or text…" autocomplete="off" spellcheck="false">
    <kbd>/</kbd>
  </label>
  <div class="chips" role="group" aria-label="Filter by severity">{_severity_chips(findings)}</div>
  <label class="select"><span>Capability</span><select id="cap">{_capability_options(findings)}</select></label>
  <label class="select"><span>Sort</span><select id="sort">
    <option value="worst">Worst first</option>
    <option value="file">File A–Z</option>
    <option value="rule">Rule A–Z</option>
  </select></label>
  <button type="button" class="btn ghost" id="expand" data-open="0">Expand all</button>
  <button type="button" class="btn ghost" id="clear">Clear</button>
  <div class="toolbar-row needs-js flex">
    <div class="review-modes" role="group" aria-label="Filter by review state">
      <button type="button" class="chip" data-review-filter="all" aria-pressed="true">All</button>
      <button type="button" class="chip" data-review-filter="unreviewed" aria-pressed="false">Unreviewed</button>
      <button type="button" class="chip" data-review-filter="reviewed" aria-pressed="false">Reviewed</button>
    </div>
    <button type="button" class="chip" id="fix-only" data-fix-filter aria-pressed="false">Fix available <b>{fixable}</b></button>
    <span id="review-count" class="review-count" role="status" aria-live="polite">0 of {len(findings)} reviewed</span>
    <span class="spacer"></span>
    <button type="button" class="btn ghost" id="density" aria-pressed="false">Compact</button>
    <button type="button" class="btn ghost" id="copy-summary">Copy summary</button>
    <button type="button" class="mini" id="clear-reviews">Clear marks</button>
  </div>
</div>"""
    else:
        findings_section = """
<div class="empty">
  <div class="big">✓</div>
  <h2>Clean surface</h2>
  <p>No findings. Every instruction-bearing file passed the deterministic detectors.</p>
</div>"""
        toolbar = ""

    graph = (
        '<section aria-labelledby="graph-title"><div class="sec-head"><h2 id="graph-title">Attack path</h2>'
        '<span class="count">files → capabilities → chains</span></div>'
        '<div class="graph">' + graph_svg + "</div>"
        '<div class="legend"><span>— file grants capability</span>'
        '<span class="chain-edge">— capability feeds chain</span></div></section>'
        if graph_svg
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta name="description" content="Read-only instruction-surface report for {_esc(root_label)}: trust score, findings, evidence and fixes.">
<title>agentvigil — {value}/100 grade {grade}</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<script>{_THEME_JS}</script>
<style>{CSS}</style>
</head>
<body data-root="{_esc(root_label)}" data-score="{value}" data-grade="{_esc(grade)}">
<a class="skip" href="#findings">Skip to findings</a>
<header class="topbar">
  <div class="wrap topbar-in">
    <a class="brand" href="#top"><span class="dot"></span>agentvigil</a>
    <span class="tag">instruction-surface report</span>
    <span class="spacer"></span>
    <div class="top-actions">
      <span class="pill readonly">read-only</span>
      {lock_pill}
      <details class="menu">
        <summary class="btn ghost" aria-haspopup="menu">Export</summary>
        <div class="menu-pop" role="menu">
          <a role="menuitem" href="/report.md" download="agentvigil-report.md">Markdown summary</a>
          <a role="menuitem" href="/api/sarif" download="agentvigil.sarif">SARIF 2.1.0</a>
          <a role="menuitem" href="/api/scan" download="agentvigil.json">JSON findings</a>
          <a role="menuitem" href="/graph.svg" download="agentvigil-graph.svg">Attack-path SVG</a>
          <a role="menuitem" href="/badge.svg" download="agentvigil-badge.svg">Badge SVG</a>
          <span class="hint">Static files · no server state</span>
        </div>
      </details>
      <button type="button" class="btn ghost" id="theme">Theme: auto</button>
      <button type="button" class="btn ghost" id="print">Print</button>
      <button type="button" class="btn ghost" id="keys-open" aria-haspopup="dialog">Keys</button>
    </div>
  </div>
</header>
<main class="wrap" id="top">
  <section class="hero" aria-labelledby="hero-title">
    {ring(value, grade)}
    <div>
      <p class="eyebrow">{_esc(root_label)} · instruction surface</p>
      <h1 id="hero-title">Trust {value}/100 <span class="grade">{grade}</span></h1>
      <p class="verdict"><strong>{_esc(verdict)}</strong> — {_esc(advice)}</p>
      <p class="meta-line">
        <span>{len(files)} file(s)</span>
        <span>{len(findings)} finding(s)</span>
        {('<span>' + _esc(kind_text) + '</span>') if kind_text else ''}
        {scanned}
      </p>
      <div class="kpis">
        <div class="kpi {'bad' if critical_high else 'good'}"><b>{critical_high}</b><span>critical + high</span></div>
        <div class="kpi"><b>{len(caps)}</b><span>capabilities</span></div>
        <div class="kpi"><b>{len(files)}</b><span>surface files</span></div>
        <div class="kpi"><b>{value}</b><span>trust score</span></div>
        {review_kpi}
      </div>
    </div>
  </section>

  {toolbar}

  <section id="findings" aria-labelledby="findings-title">
    <div class="sec-head"><h2 id="findings-title">Findings</h2><span class="count">{len(findings)} total · worst first</span></div>
    {findings_section}
  </section>

  {graph}

  {_chains(findings)}
  {_capability_panel(findings)}
  {_surface_table(files, findings)}
  {_actions(clean=not findings)}

  <footer>
    <span>agentvigil {_esc(version)}</span>
    <span>zero dependencies · no daemon · no code executed</span>
    <span class="spacer"></span>
    <a href="/api/scan">/api/scan</a>
    <a href="/api/sarif">/api/sarif</a>
    <a href="/report.md">/report.md</a>
    <a href="/graph.svg">/graph.svg</a>
    <a href="/badge.svg">/badge.svg</a>
  </footer>
</main>
<dialog id="keys" aria-labelledby="keys-title">
  <div class="dialog-in">
    <h2 id="keys-title">Keyboard shortcuts</h2>
    <div class="keys">
      <kbd>/</kbd><span>Focus search</span>
      <kbd>j</kbd><span>Next finding</span>
      <kbd>k</kbd><span>Previous finding</span>
      <kbd>Enter</kbd><span>Toggle evidence on the focused finding</span>
      <kbd>e</kbd><span>Expand or collapse all evidence</span>
      <kbd>c</kbd><span>Copy the focused path:line</span>
      <kbd>r</kbd><span>Mark the focused finding reviewed</span>
      <kbd>s</kbd><span>Copy the visible triage summary</span>
      <kbd>d</kbd><span>Toggle compact density</span>
      <kbd>Esc</kbd><span>Clear the query or close this dialog</span>
      <kbd>?</kbd><span>This dialog</span>
    </div>
    <p class="sub dialog-note">Filters are stored in the URL, so a filtered view can be shared. Review marks stay in this browser only and are never sent to the server.</p>
    <p class="dialog-note"><button type="button" class="btn" data-close>Close</button></p>
  </div>
</dialog>
<div id="toast" role="status" aria-live="polite"></div>
<script>{_APP_JS}</script>
</body>
</html>
"""
