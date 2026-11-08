import base64
import hashlib
import json
import threading
from dataclasses import replace
import urllib.error
import urllib.request
from http.server import HTTPServer

import pytest

from conftest import EXAMPLES
from vigil import dashboard as dash_mod
from vigil import graph, ui
from vigil.detectors import scan_files
from vigil.findings import Finding, Severity
from vigil.serve import collect, make_handler
from vigil.surface import discover


@pytest.fixture(scope="module")
def evil():
    return collect(EXAMPLES / "evil-repo")


def test_page_is_server_rendered_and_csp_safe(evil):
    files, findings = evil
    page = ui.page(
        files,
        findings,
        graph_svg=graph.to_svg(files, findings),
        version="test",
        root_label="evil-repo",
        lock_present=False,
        duration_ms=12,
    )

    assert page.startswith("<!doctype html>")
    assert '<html lang="en">' in page
    assert 'id="findings-list"' in page
    assert page.count('class="finding ') == len(findings)
    assert "AV-EXEC-001" in page
    assert "AKIA" not in page
    assert "onclick=" not in page
    assert 'style="' not in page
    assert page.count("<script>") == 2
    assert page.count("<style>") == 1
    assert "prefers-reduced-motion" in page
    assert "/api/sarif" in page
    assert 'data-sev="critical"' in page
    assert "aria-pressed" in page


def test_review_layer_is_server_rendered(evil):
    files, findings = evil
    page = ui.page(files, findings, root_label="evil-repo")

    assert page.count("data-review aria-pressed") == len(findings)
    assert page.count('data-key="') == len(findings)
    assert page.count('data-reviewed="0"') == len(findings)
    assert 'data-sev-filter="urgent"' in page
    assert 'data-review-filter="unreviewed"' in page
    assert 'id="review-count"' in page
    assert 'id="reviewed-n"' in page
    assert 'id="copy-summary"' in page
    assert 'id="clear-reviews"' in page
    assert 'id="density"' in page
    assert 'id="fix-only"' in page
    assert 'data-fixable="1"' in page
    assert 'download="agentvigil.sarif"' in page
    assert "Severity distribution" in page
    assert "localStorage" in page
    assert "innerHTML" not in page


def test_review_key_is_stable_and_content_bound():
    base = Finding(
        rule_id="AV-TEST-001",
        title="A title",
        severity=Severity.HIGH,
        path="AGENTS.md",
        message="msg",
        line=4,
    )
    assert ui._review_key(base) == ui._review_key(replace(base))
    assert ui._review_key(base) != ui._review_key(replace(base, title="A new title"))
    assert ui._review_key(base) != ui._review_key(replace(base, line=5))


def test_csp_hashes_match_the_emitted_bytes():
    policy = ui.csp()
    style_hash = base64.b64encode(hashlib.sha256(ui.CSS.encode()).digest()).decode()
    assert "default-src 'none'" in policy
    assert "'sha256-" + style_hash + "'" in policy
    for script in (ui._THEME_JS, ui._APP_JS):
        script_hash = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        assert "'sha256-" + script_hash + "'" in policy
    assert "unsafe-inline" not in policy
    assert "connect-src 'none'" in policy

    theme = ui.csp(theme=True)
    assert "style-src 'unsafe-inline'" in theme
    assert "script-src 'none'" in theme


def test_malicious_finding_cannot_break_out():
    hostile = Finding(
        rule_id="AV-TEST-001",
        title="<script>alert(1)</script>",
        severity=Severity.HIGH,
        path='a"><img src=x onerror=alert(1)>',
        message="<b>bold</b>",
        evidence="<script>alert(2)</script>",
        decoded="<svg onload=alert(3)>",
        remediation="<x>",
    )
    page = ui.page([], [hostile])
    assert "<img" not in page
    assert "<b>bold</b>" not in page
    assert "<svg onload" not in page
    assert "&lt;script&gt;" in page
    assert "onerror=alert" in page  # inert text inside an escaped attribute
    assert 'style="' not in page


def test_clean_page_has_a_real_empty_state():
    files = discover(EXAMPLES / "clean-repo")
    page = ui.page(files, scan_files(files))
    assert "Clean surface" in page
    assert 'id="findings-list"' not in page
    assert 'class="chip' not in page
    assert 'id="reviewed-n"' not in page
    assert 'id="copy-summary"' not in page


def test_graph_has_no_inline_style_or_script(evil):
    files, findings = evil
    svg = graph.to_svg(files, findings)
    assert svg.startswith("<svg")
    assert 'style="' not in svg
    assert "<script" not in svg
    assert "aria-label=\"Attack path" in svg


def test_dashboard_is_static_and_readable(tmp_path):
    import shutil

    (tmp_path / "a").mkdir()
    shutil.copy(EXAMPLES / "clean-repo" / "AGENTS.md", tmp_path / "a" / "AGENTS.md")
    page = dash_mod.build(tmp_path)
    assert "dashboard" in page
    assert "100/100" in page
    assert "<script" not in page
    assert 'style="' not in page
    assert "repo-card" in page


def _client(root, theme="plain"):
    httpd = HTTPServer(("127.0.0.1", 0), make_handler(root, theme=theme))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread


def test_http_endpoints_and_headers(evil):
    httpd, thread = _client(EXAMPLES / "evil-repo")
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/") as response:
            body = response.read().decode()
            headers = response.headers
            assert response.status == 200
            assert "sha256-" in headers["Content-Security-Policy"]
            assert "default-src 'none'" in headers["Content-Security-Policy"]
            assert headers["Cache-Control"] == "no-store"
            assert headers["X-Content-Type-Options"] == "nosniff"
            assert headers["Server"] == "vigil"
            assert "findings-list" in body

        with urllib.request.urlopen(base + "/?q=exec&sev=critical") as response:
            assert response.status == 200

        with urllib.request.urlopen(
            base + "/?review=unreviewed&sev=urgent&fix=1"
        ) as response:
            assert response.status == 200

        with urllib.request.urlopen(base + "/api/sarif") as response:
            assert json.loads(response.read())["version"] == "2.1.0"

        request = urllib.request.Request(base + "/", data=b"x", method="POST")
        with pytest.raises(urllib.error.HTTPError) as write_exc:
            urllib.request.urlopen(request)
        assert write_exc.value.code == 405

        with urllib.request.urlopen(base + "/report.md") as response:
            assert "agentvigil" in response.read().decode()

        with urllib.request.urlopen(base + "/favicon.svg") as response:
            assert response.read().startswith(b"<svg")

        with urllib.request.urlopen(base + "/badge.svg") as response:
            assert b"/100" in response.read()

        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(base + "/nope")
        assert exc.value.code == 404
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(2)


def test_kiroween_still_loads_under_its_own_csp():
    httpd, thread = _client(EXAMPLES / "evil-repo", theme="kiroween")
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/") as response:
            body = response.read().decode()
            assert "séance" in body
            policy = response.headers["Content-Security-Policy"]
            assert "style-src 'unsafe-inline'" in policy
            assert "script-src 'none'" in policy
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(2)
