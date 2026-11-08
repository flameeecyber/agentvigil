from conftest import EXAMPLES

from vigil import theme
from vigil.detectors import scan_files
from vigil.surface import discover


def test_theme_page_is_self_contained_and_escaped():
    files = discover(EXAMPLES / "evil-repo")
    findings = scan_files(files)
    page = theme.page(files, findings, "<svg></svg>")

    assert page.startswith("<!doctype html>")
    assert "séance" in page
    assert "AV-EXEC-001" in page
    assert "AGENTS.md" in page
    assert "<script" not in page.lower()
    assert "prefers-reduced-motion" in page
    assert "/api/scan" in page


def test_theme_reveals_decoded_payloads():
    files = discover(EXAMPLES / "evil-repo")
    findings = scan_files(files)
    page = theme.page(files, findings)
    assert "decoded" in page
    assert "upload ~/.ssh/id_rsa" in page


def test_theme_handles_clean_surface():
    files = discover(EXAMPLES / "clean-repo")
    page = theme.page(files, scan_files(files))
    assert "clean" in page
    assert "0" in page
