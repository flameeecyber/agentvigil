"""Benchmark harness: reproducible coverage over a versioned, labeled corpus.

Layout:
    bench/payloads/<technique>/<slug>/file.md        # the instruction file
    bench/payloads/<technique>/<slug>/expected.json  # labels (see below)
    bench/benign/<slug>.<md|json|svg|txt>            # must stay quiet at high+

Labels are hand-authored; they are not derived from scanner output. A case is
valid only when its file exists, its labels parse, and every rule id is shaped
like an agentvigil rule. Missing or malformed cases are errors, never silent
skips.

`python -m bench.run` prints a per-case and per-technique table plus the benign
false-positive rate. No network, no LLM, stdlib only.

This corpus is an in-repository synthetic set. It is **not** an external or
held-out evaluation set; do not describe its numbers as general precision or
recall. See `bench/README.md` for the methodology and limitations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
import re

from vigil.detectors import scan_files
from vigil.findings import SEVERITIES_BY_NAME, Severity, severity_at_least
from vigil.surface import SurfaceFile

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "bench" / "payloads"
BENIGN = ROOT / "bench" / "benign"

RULE_ID_RE = re.compile(r"^AV-[A-Z]+-\d{3}$")
CASE_FILENAMES = ("file.md", "file.mcp.json", "file.svg", ".mcp.json", "file.txt", "file.json")
BENIGN_SUFFIXES = (".md", ".mcp.json", ".json", ".svg", ".txt")


@dataclass
class CaseResult:
    slug: str
    technique: str
    fired: List[str]
    expected: List[str]
    forbidden: List[str]
    passed: bool
    missing: List[str]
    forbidden_hits: List[str]
    unexpected: List[str]
    min_severity: str


@dataclass
class CorpusError:
    path: str
    message: str


@dataclass
class TechniqueResult:
    technique: str
    total: int = 0
    passed: int = 0
    required: int = 0
    found: int = 0
    cases: List[CaseResult] = field(default_factory=list)


def _kind_for(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".json"):
        return "mcp_config"
    if name.endswith(".svg"):
        return "agent_asset"
    return "agent_rules"


def _surface_for(path: Path) -> SurfaceFile:
    return SurfaceFile(path=path.name, kind=_kind_for(path), data=path.read_bytes())


def _case_files(directory: Path) -> List[Path]:
    return [directory / name for name in CASE_FILENAMES if (directory / name).is_file()]


def _parse_labels(path: Path, errors: List[CorpusError]) -> Optional[Dict[str, object]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(CorpusError(str(path), f"unreadable labels: {exc}"))
        return None
    if not isinstance(raw, dict):
        errors.append(CorpusError(str(path), "labels must be a JSON object"))
        return None

    must_fire = raw.get("must_fire")
    if not isinstance(must_fire, list) or not must_fire or not all(
        isinstance(rule, str) and RULE_ID_RE.match(rule) for rule in must_fire
    ):
        errors.append(CorpusError(str(path), "must_fire must be a non-empty list of AV-* rule ids"))
        return None

    forbidden = raw.get("must_not_fire", [])
    if not isinstance(forbidden, list) or not all(
        isinstance(rule, str) and RULE_ID_RE.match(rule) for rule in forbidden
    ):
        errors.append(CorpusError(str(path), "must_not_fire must be a list of AV-* rule ids"))
        return None

    overlap = sorted(set(must_fire) & set(forbidden))
    if overlap:
        errors.append(CorpusError(str(path), f"rules both required and forbidden: {', '.join(overlap)}"))
        return None

    severity_name = str(raw.get("min_severity", Severity.HIGH.value)).lower()
    if severity_name not in SEVERITIES_BY_NAME:
        errors.append(CorpusError(str(path), f"unknown min_severity: {severity_name}"))
        return None

    return {
        "must_fire": list(dict.fromkeys(must_fire)),
        "must_not_fire": list(dict.fromkeys(forbidden)),
        "min_severity": severity_name,
    }


def _evaluate_case(
    directory: Path,
    labels: Dict[str, object],
    errors: List[CorpusError],
) -> Optional[CaseResult]:
    files = _case_files(directory)
    technique = directory.parent.name
    slug = f"{technique}/{directory.name}"
    if len(files) != 1:
        errors.append(
            CorpusError(
                str(directory),
                f"expected exactly one case file ({', '.join(CASE_FILENAMES)}), found {len(files)}",
            )
        )
        return None

    min_severity = SEVERITIES_BY_NAME[str(labels["min_severity"])]
    findings = scan_files([_surface_for(files[0])])
    fired = sorted(
        {
            finding.rule_id
            for finding in findings
            if severity_at_least(finding.severity, min_severity)
        }
    )
    expected = list(labels["must_fire"])  # type: ignore[arg-type]
    forbidden = list(labels["must_not_fire"])  # type: ignore[arg-type]
    missing = [rule for rule in expected if rule not in fired]
    forbidden_hits = [rule for rule in forbidden if rule in fired]
    unexpected = [rule for rule in fired if rule not in expected and rule not in forbidden]

    return CaseResult(
        slug=slug,
        technique=technique,
        fired=fired,
        expected=expected,
        forbidden=forbidden,
        passed=not missing and not forbidden_hits,
        missing=missing,
        forbidden_hits=forbidden_hits,
        unexpected=unexpected,
        min_severity=min_severity.value,
    )


def _benign_files() -> List[Path]:
    if not BENIGN.is_dir():
        return []
    return sorted(
        path
        for path in BENIGN.iterdir()
        if path.is_file() and path.name.lower().endswith(BENIGN_SUFFIXES)
    )


def run_corpus(fail_on: Severity = Severity.HIGH) -> Dict[str, object]:
    """Run every labeled case and benign control; return metrics and errors."""
    errors: List[CorpusError] = []
    cases: List[CaseResult] = []
    seen_slugs: Dict[str, str] = {}

    if CORPUS.is_dir():
        for expected_path in sorted(CORPUS.rglob("expected.json")):
            directory = expected_path.parent
            slug = f"{directory.parent.name}/{directory.name}"
            if slug in seen_slugs:
                errors.append(CorpusError(str(expected_path), f"duplicate case slug: {slug}"))
                continue
            seen_slugs[slug] = str(expected_path)
            labels = _parse_labels(expected_path, errors)
            if labels is None:
                continue
            case = _evaluate_case(directory, labels, errors)
            if case is not None:
                cases.append(case)
    else:
        errors.append(CorpusError(str(CORPUS), "payload corpus directory is missing"))

    if not cases and not errors:
        errors.append(CorpusError(str(CORPUS), "corpus contains no labeled cases"))

    techniques: Dict[str, TechniqueResult] = {}
    for case in cases:
        bucket = techniques.setdefault(case.technique, TechniqueResult(case.technique))
        bucket.total += 1
        bucket.passed += 1 if case.passed else 0
        bucket.required += len(case.expected)
        bucket.found += len([rule for rule in case.expected if rule not in case.missing])
        bucket.cases.append(case)

    benign_fps: List[str] = []
    benign_total = 0
    for benign_path in _benign_files():
        benign_total += 1
        fired = [
            finding.rule_id
            for finding in scan_files([_surface_for(benign_path)])
            if severity_at_least(finding.severity, fail_on)
        ]
        if fired:
            benign_fps.append(f"{benign_path.name}: {','.join(sorted(set(fired)))}")

    passed = sum(1 for case in cases if case.passed)
    required_total = sum(len(case.expected) for case in cases)
    required_found = sum(
        1 for case in cases for rule in case.expected if rule not in case.missing
    )
    return {
        "cases": cases,
        "passed": passed,
        "total": len(cases),
        "required_found": required_found,
        "required_total": required_total,
        "techniques": [techniques[name] for name in sorted(techniques)],
        "benign_fps": benign_fps,
        "benign_total": benign_total,
        "errors": errors,
    }


def render_table(result: Dict[str, object]) -> str:
    lines = ["technique/slug | fired | expected | extra high+ | pass", "---|---|---|---|---"]
    for case in result["cases"]:  # type: ignore[union-attr]
        assert isinstance(case, CaseResult)
        verdict = "PASS" if case.passed else "FAIL"
        details = []
        if case.missing:
            details.append("missing:" + ",".join(case.missing))
        if case.forbidden_hits:
            details.append("forbidden:" + ",".join(case.forbidden_hits))
        if details:
            verdict += " (" + "; ".join(details) + ")"
        lines.append(
            f"{case.slug} | {','.join(case.fired) or '—'} | "
            f"{','.join(case.expected) or '—'} | "
            f"{','.join(case.unexpected) or '—'} | {verdict}"
        )

    lines.append("")
    total = int(result["total"])  # type: ignore[arg-type]
    passed = int(result["passed"])  # type: ignore[arg-type]
    required_total = int(result["required_total"])  # type: ignore[arg-type]
    required_found = int(result["required_found"])  # type: ignore[arg-type]
    unexpected_cases = sum(1 for case in result["cases"] if case.unexpected)  # type: ignore[union-attr]
    unexpected_rules = sum(len(case.unexpected) for case in result["cases"])  # type: ignore[union-attr]
    lines.append(f"cases: {passed}/{total} pass")
    lines.append(
        f"extra high+ rule hits: {unexpected_rules} across {unexpected_cases} case(s) "
        "(reported, not failed; cross-rule findings can be legitimate)"
    )
    if required_total:
        lines.append(
            f"required-rule coverage: {required_found}/{required_total} "
            f"({required_found / required_total:.2%})"
        )
    benign_total = int(result["benign_total"])  # type: ignore[arg-type]
    benign_fps = list(result["benign_fps"])  # type: ignore[arg-type]
    if benign_total:
        quiet = benign_total - len(benign_fps)
        lines.append(
            f"benign: {quiet}/{benign_total} quiet at high+ "
            f"(FP rate {len(benign_fps) / benign_total:.2%})"
        )
        for fp in benign_fps:
            lines.append(f"  FP: {fp}")

    techniques = list(result["techniques"])  # type: ignore[arg-type]
    if techniques:
        lines.extend(["", "technique | cases | required rules", "---|---|---"])
        for technique in techniques:
            assert isinstance(technique, TechniqueResult)
            lines.append(
                f"{technique.technique} | {technique.passed}/{technique.total} | "
                f"{technique.found}/{technique.required}"
            )

    errors = list(result["errors"])  # type: ignore[arg-type]
    if errors:
        lines.extend(["", "corpus errors:"])
        for error in errors:
            assert isinstance(error, CorpusError)
            lines.append(f"  {error.path}: {error.message}")

    lines.extend(
        [
            "",
            "Label set: hand-authored, in-repository synthetic cases.",
            "Not an external benchmark; numbers are corpus-specific.",
        ]
    )
    return "\n".join(lines) + "\n"
