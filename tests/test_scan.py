import json

from conftest import EXAMPLES

from vigil.detectors import scan_files
from vigil.findings import Severity
from vigil.report import as_json, as_sarif
from vigil.score import score
from vigil.surface import discover


def test_evil_repo_is_flagged():
    files = discover(EXAMPLES / "evil-repo")
    findings = scan_files(files)
    rules = {f.rule_id for f in findings}

    assert {"AV-EXEC-001", "AV-CRED-001", "AV-EXFIL-001", "AV-FETCH-001", "AV-OVR-002"} <= rules
    assert {"AV-MCP-001", "AV-MCP-003", "AV-MCP-004", "AV-MCP-005"} <= rules

    value, grade, verdict = score(findings)
    assert value < 50
    assert grade in {"D", "F"}
    assert verdict in {"untrusted", "hostile"}


def test_clean_repo_is_quiet():
    files = discover(EXAMPLES / "clean-repo")
    findings = scan_files(files)
    assert [f for f in findings if f.severity.rank >= Severity.HIGH.rank] == []
    value, grade, _ = score(findings)
    assert value >= 90 and grade == "A"


def test_discovery_covers_conventions(tmp_path):
    (tmp_path / ".cursor" / "rules").mkdir(parents=True)
    (tmp_path / ".cursor" / "rules" / "style.mdc").write_text("use tabs", encoding="utf-8")
    (tmp_path / ".kiro" / "steering").mkdir(parents=True)
    (tmp_path / ".kiro" / "steering" / "rules.md").write_text("be careful", encoding="utf-8")
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "copilot-instructions.md").write_text("be nice", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "AGENTS.md").write_text("ignored", encoding="utf-8")

    paths = {f.path for f in discover(tmp_path)}
    assert ".cursor/rules/style.mdc" in paths
    assert ".kiro/steering/rules.md" in paths
    assert ".github/copilot-instructions.md" in paths
    assert not any("node_modules" in p for p in paths)


def test_discovery_accepts_a_single_surface_file(tmp_path):
    path = tmp_path / "AGENTS.md"
    path.write_text("run the tests", encoding="utf-8")

    files = discover(path)

    assert [(f.path, f.kind) for f in files] == [("AGENTS.md", "agent_rules")]


def test_discovery_ignores_a_single_non_surface_file(tmp_path):
    path = tmp_path / "README.md"
    path.write_text("not an instruction surface", encoding="utf-8")

    assert discover(path) == []


def test_sarif_shape():
    files = discover(EXAMPLES / "evil-repo")
    findings = scan_files(files)
    doc = json.loads(as_sarif(findings))

    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "agentvigil"
    assert len(driver["rules"]) >= 5
    assert all(rule["defaultConfiguration"]["level"] for rule in driver["rules"])
    first = run["results"][0]
    assert first["level"] in {"error", "warning", "note"}
    region = first["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] >= 1


def test_json_report_roundtrip():
    files = discover(EXAMPLES / "evil-repo")
    findings = scan_files(files)
    payload = json.loads(as_json(findings, files))
    assert payload["tool"] == "agentvigil"
    assert payload["trust"]["score"] < 50
    assert len(payload["surface"]) == len(files)
    assert all(f["evidence"] for f in payload["findings"])
