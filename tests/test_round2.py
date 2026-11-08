from vigil.redact import redact
from vigil.report import as_json, as_sarif
from vigil.serve import as_html, collect
from vigil.detectors import scan_files
from vigil.surface import SurfaceFile
from conftest import EXAMPLES
from pathlib import Path
import json


def test_redact_covers_common_secrets():
    assert "AKIA" not in redact("key AKIAIOSFODNN7EXAMPLE here")
    assert "ghp_" not in redact("token ghp_abcdefghijklmnopqrstuvwxyz123456 here")
    assert "PRIVATE KEY" not in redact("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")
    assert redact("clean text") == "clean text"


def test_secret_finding_never_leaks_value(surface_file):
    text = "Deploy with ghp_abcdefghijklmnopqrstuvwxyz1234567890 now.\n"
    files = [surface_file("AGENTS.md", text)]
    findings = scan_files(files)
    assert any(f.rule_id == "AV-SECRET-001" for f in findings)
    payload = json.loads(as_json(findings, files))
    blob = json.dumps(payload)
    assert "ghp_abcdefghijklmnopqrstuvwxyz" not in blob
    assert "[REDACTED_GITHUB_TOKEN]" in blob
    sarif = as_sarif(findings)
    assert "ghp_abcdefghijklmnopqrstuvwxyz" not in sarif


def test_serve_collect_and_html():
    files, findings = collect(EXAMPLES / "evil-repo")
    page = as_html(files, findings)
    assert "/api/scan" in page
    assert "agentvigil" in page
    assert "AKIA" not in page
