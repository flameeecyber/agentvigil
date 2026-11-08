"""Attack-path graph: files -> capabilities -> kill chains.

`vigil graph . -o graph.dot` emits Graphviz DOT (render with `dot -Tsvg`).
`--format svg` emits a self-contained, zero-dependency SVG attack-path diagram.
`--format html` wraps the live SVG diagram + kill-chain summary into a shareable page.
Pure function of (files, findings); no layout engine required.
"""

from __future__ import annotations

import html as html_mod
from typing import Dict, List, Sequence, Tuple

from . import chain as chain_engine
from .detectors import refs as refs_detector
from .findings import Finding
from .surface import SurfaceFile


def _non_chain(findings: Sequence[Finding]) -> List[Finding]:
    return [f for f in findings if not f.rule_id.startswith("AV-CHAIN-")]


def _chains_for(
    files: Sequence[SurfaceFile], findings: Sequence[Finding]
) -> List[Finding]:
    explicit = [f for f in findings if f.rule_id.startswith("AV-CHAIN-")]
    if explicit:
        return explicit
    return chain_engine.correlate(files, findings)


def to_dot(files: Sequence[SurfaceFile], findings: Sequence[Finding]) -> str:
    base_findings = _non_chain(findings)
    chains = _chains_for(files, base_findings)
    lines = ["digraph surface {", "  rankdir=LR; node [shape=box, fontsize=11];"]
    for f in files:
        lines.append(f'  "file:{f.path}" [label="{f.path}\\n{f.kind}"];')
        for target in refs_detector.extract_refs(f):
            lines.append(
                f'  "file:{f.path}" -> "ref:{target}" [style=dashed, label="ref"];'
            )
    caps = sorted({c for x in base_findings for c in x.capabilities})
    for c in caps:
        lines.append(f'  "cap:{c}" [shape=ellipse];')
    for x in base_findings:
        for c in x.capabilities:
            lines.append(f'  "file:{x.path}" -> "cap:{c}" [label="{x.rule_id}"];')
    for ch in chains:
        node = f"chain:{ch.rule_id}"
        lines.append(f'  "{node}" [shape=diamond, label="{ch.rule_id}"];')
        for c in ch.capabilities:
            lines.append(f'  "cap:{c}" -> "{node}";')
    lines.append("}")
    return "\n".join(lines) + "\n"


def to_svg(files: Sequence[SurfaceFile], findings: Sequence[Finding]) -> str:
    """Render a 3-column layered SVG attack-path diagram (files -> caps -> chains)."""
    base_findings = _non_chain(findings)
    chains = _chains_for(files, base_findings)
    caps = sorted({c for x in base_findings for c in x.capabilities})

    row_count = max(len(files), len(caps), len(chains), 1)
    height = max(220, 70 + row_count * 64)
    width = 880

    file_y: Dict[str, int] = {}
    cap_y: Dict[str, int] = {}
    chain_y: Dict[str, int] = {}

    elements: List[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" font-family="ui-monospace,SFMono-Regular,Menlo,monospace" '
        'role="img" aria-label="Attack path: surface files grant capabilities, capabilities feed kill chains">',
        f'<rect width="100%" height="100%" fill="#0d1117" rx="10"/>',
        '<text x="30" y="28" fill="#8b949e" font-size="12" font-weight="bold">SURFACE FILES</text>',
        '<text x="340" y="28" fill="#8b949e" font-size="12" font-weight="bold">CAPABILITIES GRANTED</text>',
        '<text x="630" y="28" fill="#8b949e" font-size="12" font-weight="bold">KILL CHAINS</text>',
    ]

    for idx, f in enumerate(files):
        cy = 68 + idx * 60
        file_y[f.path] = cy
    for idx, c in enumerate(caps):
        cy = 68 + idx * 56
        cap_y[c] = cy
    for idx, ch in enumerate(chains):
        cy = 68 + idx * 68
        chain_y[ch.rule_id] = cy

    # Edges: file -> capability
    seen_edges = set()
    for x in base_findings:
        y1 = file_y.get(x.path)
        if y1 is None:
            continue
        for c in x.capabilities:
            y2 = cap_y.get(c)
            if y2 is None or (x.path, c) in seen_edges:
                continue
            seen_edges.add((x.path, c))
            elements.append(
                f'<path d="M 240 {y1} C 285 {y1}, 295 {y2}, 340 {y2}" '
                f'stroke="#58a6ff" stroke-width="1.6" fill="none" opacity="0.75"/>'
            )

    # Edges: capability -> chain
    for ch in chains:
        y2 = chain_y.get(ch.rule_id)
        if y2 is None:
            continue
        for c in ch.capabilities:
            y1 = cap_y.get(c)
            if y1 is None:
                continue
            elements.append(
                f'<path d="M 530 {y1} C 575 {y1}, 585 {y2}, 630 {y2}" '
                f'stroke="#f85149" stroke-width="2" fill="none" opacity="0.85"/>'
            )

    # Nodes: files
    for f in files:
        cy = file_y[f.path]
        label = html_mod.escape(f.path[-26:])
        kind = html_mod.escape(f.kind)
        elements.append(
            f'<rect x="24" y="{cy - 20}" width="216" height="40" rx="6" fill="#161b22" stroke="#30363d"/>'
            f'<text x="34" y="{cy - 2}" fill="#e6edf3" font-size="12" font-weight="600">{label}</text>'
            f'<text x="34" y="{cy + 13}" fill="#8b949e" font-size="10">{kind}</text>'
        )

    # Nodes: capabilities
    for c in caps:
        cy = cap_y[c]
        label = html_mod.escape(c)
        elements.append(
            f'<rect x="340" y="{cy - 16}" width="190" height="32" rx="16" fill="#1f2937" stroke="#d29922"/>'
            f'<text x="435" y="{cy + 4}" fill="#f2cc60" font-size="12" text-anchor="middle">{label}</text>'
        )

    # Nodes: chains
    if chains:
        for ch in chains:
            cy = chain_y[ch.rule_id]
            rid = html_mod.escape(ch.rule_id)
            short = html_mod.escape(ch.title.replace("Kill chain: ", "")[:28])
            elements.append(
                f'<rect x="630" y="{cy - 22}" width="226" height="44" rx="6" fill="#3d1318" stroke="#f85149" stroke-width="1.5"/>'
                f'<text x="642" y="{cy - 4}" fill="#ff7b72" font-size="12" font-weight="bold">{rid}</text>'
                f'<text x="642" y="{cy + 12}" fill="#ffa198" font-size="10">{short}</text>'
            )
    else:
        elements.append(
            '<rect x="630" y="48" width="210" height="36" rx="6" fill="#12261e" stroke="#2ea043"/>'
            '<text x="735" y="70" fill="#3fb950" font-size="12" text-anchor="middle">0 kill chains triggered</text>'
        )

    elements.append("</svg>\n")
    return "\n".join(elements)


def to_html(files: Sequence[SurfaceFile], findings: Sequence[Finding]) -> str:
    base_findings = _non_chain(findings)
    chains = _chains_for(files, base_findings)
    svg = to_svg(files, base_findings)
    items = (
        "".join(
            f"<li><b>{html_mod.escape(c.rule_id)}</b> {html_mod.escape(c.title)} "
            f"<i>{html_mod.escape(', '.join(c.capabilities))}</i><br>"
            f"{html_mod.escape(c.message[:200])}</li>"
            for c in chains
        )
        or "<li>no kill chains</li>"
    )
    return (
        "<!doctype html><html><head><meta charset=utf-8><title>vigil graph</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem}</style>"
        "</head>"
        f"<body><h1>attack paths ({len(chains)})</h1>"
        f"{svg}"
        f"<ul>{items}</ul>"
        f"<p>{len(files)} files · {len(base_findings)} findings. DOT at <code>vigil graph --format dot</code>.</p>"
        "</body></html>\n"
    )
