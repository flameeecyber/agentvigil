"""Read-only demo server: the 'working deployed URL' for the submission.

`vigil serve . --port 8000` exposes read-only endpoints over stdlib
`http.server` — no code execution, no cloning, no writes:

* `GET /` — HTML triage report for the local repo (filters, evidence, fixes).
* `GET /api/scan` — JSON findings (for the hosted demo + CI badges).
* `GET /api/sarif` — SARIF 2.1.0 for code scanning upload.
* `GET /report.md` — one-comment Markdown summary.
* `GET /badge.svg`, `/graph.svg`, `/favicon.svg` — static renders.
* `GET /healthz` — liveness.

Binds to 127.0.0.1 by default; set --host explicitly to expose. Scans on
each request (repos in the demo are tiny); never serves file contents,
only findings + hashes. HTML is sent with a hash-based CSP, so the page
runs without `unsafe-inline` scripts.
"""

from __future__ import annotations

import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit

from . import __version__
from . import chain as chain_engine
from . import graph as graph_mod
from . import ui
from .detectors import scan_files
from .detectors.multimodal import scan_png_chunks
from .findings import Finding
from .redact import redact  # noqa: F401  (kept for backwards-compatible imports)
from .report import as_json, as_markdown, as_sarif
from .score import score
from .surface import SurfaceFile, discover, discover_assets

_SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
)


def collect(root: Path) -> tuple[Sequence[SurfaceFile], list[Finding]]:
    files = discover(root)
    findings: list[Finding] = scan_files(files)
    try:
        for asset in discover_assets(root):
            if asset.path.lower().endswith(".png"):
                findings.extend(scan_png_chunks(asset.data, asset.path))
    except OSError:
        pass
    findings.extend(chain_engine.correlate(files, findings))
    findings.sort(key=lambda f: f.sort_key())
    return files, findings


def as_html(files: Sequence[SurfaceFile], findings: Sequence[Finding]) -> str:
    """Backwards-compatible wrapper around :func:`vigil.ui.page`."""
    return ui.page(
        files,
        findings,
        graph_svg=graph_mod.to_svg(files, findings),
        version=__version__,
    )


def badge_svg(value: int, grade: str) -> str:
    color = "#4c1" if value >= 90 else ("#dfb317" if value >= 50 else "#e05d44")
    label = f"{value}/100 {grade}"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="160" height="20" role="img" '
        f'aria-label="agentvigil {label}">'
        f'<rect width="90" height="20" fill="#555"/>'
        f'<rect x="90" width="70" height="20" fill="{color}"/>'
        f'<text x="45" y="14" fill="#fff" font-size="11" text-anchor="middle"'
        f' font-family="sans-serif">agentvigil</text>'
        f'<text x="125" y="14" fill="#fff" font-size="11" text-anchor="middle"'
        f' font-family="sans-serif">{label}</text></svg>'
    )


def make_handler(root: Path, theme: str = "plain"):
    class Handler(BaseHTTPRequestHandler):
        server_version = "vigil"
        sys_version = ""

        def version_string(self) -> str:
            return "vigil"

        def log_message(self, *args):  # quiet by default
            pass

        def _send(
            self,
            body: bytes,
            ctype: str,
            *,
            csp: str | None = None,
            status: int = 200,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in _SECURITY_HEADERS:
                self.send_header(name, value)
            if csp:
                self.send_header("Content-Security-Policy", csp)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _scan(self) -> tuple[Sequence[SurfaceFile], list[Finding], int]:
            started = time.perf_counter()
            files, findings = collect(root)
            elapsed = int((time.perf_counter() - started) * 1000)
            return files, findings, elapsed

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/healthz":
                self._send(b"ok\n", "text/plain; charset=utf-8")
            elif path == "/favicon.svg":
                self._send(ui.favicon().encode(), "image/svg+xml")
            elif path == "/api/scan":
                files, findings, elapsed = self._scan()
                self._send(
                    as_json(findings, files, duration_ms=elapsed).encode(),
                    "application/json; charset=utf-8",
                )
            elif path == "/api/sarif":
                _, findings, _ = self._scan()
                self._send(
                    as_sarif(findings).encode(),
                    "application/sarif+json; charset=utf-8",
                )
            elif path == "/report.md":
                files, findings, _ = self._scan()
                self._send(
                    as_markdown(findings, files).encode(),
                    "text/markdown; charset=utf-8",
                )
            elif path == "/badge.svg":
                _, findings, _ = self._scan()
                value, grade, _ = score(findings)
                self._send(
                    badge_svg(value, grade).encode(),
                    "image/svg+xml",
                    csp="default-src 'none'; style-src 'none'",
                )
            elif path == "/graph.svg":
                files, findings, _ = self._scan()
                self._send(
                    graph_mod.to_svg(files, findings).encode(),
                    "image/svg+xml",
                    csp="default-src 'none'; style-src 'none'; img-src 'self' data:",
                )
            elif path in ("/", "/index.html"):
                files, findings, elapsed = self._scan()
                if theme == "kiroween":
                    from . import theme as theme_mod

                    body = theme_mod.page(
                        files,
                        findings,
                        graph_mod.to_svg(files, findings),
                        __version__,
                    )
                    policy = ui.csp(theme=True)
                else:
                    body = ui.page(
                        files,
                        findings,
                        graph_svg=graph_mod.to_svg(files, findings),
                        version=__version__,
                        root_label=root.name or "this repository",
                        lock_present=(root / "vigil.lock").exists(),
                        duration_ms=elapsed,
                    )
                    policy = ui.csp()
                self._send(
                    body.encode(),
                    "text/html; charset=utf-8",
                    csp=policy,
                )
            else:
                self._send(
                    b"not found\n",
                    "text/plain; charset=utf-8",
                    status=404,
                )

        def do_HEAD(self) -> None:
            self.do_GET()

        def _read_only(self) -> None:
            self._send(
                b"method not allowed: this server is read-only\n",
                "text/plain; charset=utf-8",
                status=405,
            )

        do_POST = _read_only
        do_PUT = _read_only
        do_PATCH = _read_only
        do_DELETE = _read_only

    return Handler


def run(root: Path, host: str = "127.0.0.1", port: int = 8000, theme: str = "plain") -> int:
    target = root.resolve()
    if not target.is_dir():
        print(f"vigil: no such directory: {target}", file=sys.stderr)
        return 2
    print(f"vigil: serving read-only report for {target}")
    print(f"       http://{host}:{port}/  (Ctrl-C to stop)")
    print("       /api/scan · /api/sarif · /report.md · /graph.svg · /badge.svg")
    httpd = HTTPServer((host, port), make_handler(target, theme=theme))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
