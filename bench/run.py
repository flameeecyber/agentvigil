"""`python -m bench.run [--html out.html] [--json out.json]` — reproducible corpus report."""
from __future__ import annotations

import html as html_mod
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vigil.bench import CorpusError, TechniqueResult, render_table, run_corpus


def _summary(result: dict) -> dict:
    return {
        "cases": result["total"],
        "cases_passed": result["passed"],
        "required_rules": result["required_total"],
        "required_rules_found": result["required_found"],
        "benign": result["benign_total"],
        "benign_quiet": result["benign_total"] - len(result["benign_fps"]),
        "benign_false_positives": result["benign_fps"],
        "errors": [
            {"path": error.path, "message": error.message}
            for error in result["errors"]
            if isinstance(error, CorpusError)
        ],
        "label_set": "hand-authored, in-repository synthetic cases",
        "scope_note": "corpus-specific; not an external benchmark",
    }


def render_html(result: dict) -> str:
    rows = []
    for case in result["cases"]:
        verdict = "PASS" if case.passed else "FAIL"
        if case.missing:
            verdict += ": missing " + ",".join(case.missing)
        if case.forbidden_hits:
            verdict += ": forbidden " + ",".join(case.forbidden_hits)
        rows.append(
            f"<tr><td>{html_mod.escape(case.slug)}</td>"
            f"<td>{html_mod.escape(','.join(case.fired) or '—')}</td>"
            f"<td>{html_mod.escape(','.join(case.unexpected) or '—')}</td>"
            f"<td>{html_mod.escape(verdict)}</td></tr>"
        )

    technique_rows = []
    for technique in result["techniques"]:
        assert isinstance(technique, TechniqueResult)
        technique_rows.append(
            f"<tr><td>{html_mod.escape(technique.technique)}</td>"
            f"<td>{technique.passed}/{technique.total}</td>"
            f"<td>{technique.found}/{technique.required}</td></tr>"
        )

    fps = "".join(f"<li>{html_mod.escape(item)}</li>" for item in result["benign_fps"])
    errors = "".join(
        f"<li>{html_mod.escape(error.path)}: {html_mod.escape(error.message)}</li>"
        for error in result["errors"]
        if isinstance(error, CorpusError)
    )
    quiet = result["benign_total"] - len(result["benign_fps"])
    return (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>vigil-bench corpus report</title></head><body>"
        f"<h1>vigil-bench {result['passed']}/{result['total']} cases</h1>"
        f"<p>Required-rule coverage: {result['required_found']}/{result['required_total']}<br>"
        f"Benign quiet at high+: {quiet}/{result['benign_total']}</p>"
        "<table border=1 cellpadding=6><tr><th>case</th><th>fired</th>"
        "<th>extra high+</th><th>verdict</th></tr>"
        + "\n".join(rows)
        + "</table><h2>By technique</h2>"
        "<table border=1 cellpadding=6><tr><th>technique</th><th>cases</th>"
        "<th>required rules</th></tr>"
        + "\n".join(technique_rows)
        + "</table>"
        f"<h2>Benign false positives</h2><ul>{fps}</ul>"
        f"<h2>Corpus errors</h2><ul>{errors}</ul>"
        "<p><strong>Scope:</strong> hand-authored, in-repository synthetic cases. "
        "These numbers are corpus-specific, not an external benchmark.</p>"
        "</body></html>"
    )


def _write_json(result: dict, path: Path) -> None:
    payload = _summary(result)
    payload["cases"] = [
        {
            "slug": case.slug,
            "technique": case.technique,
            "fired": case.fired,
            "expected": case.expected,
            "forbidden": case.forbidden,
            "passed": case.passed,
            "missing": case.missing,
            "forbidden_hits": case.forbidden_hits,
            "unexpected": case.unexpected,
            "min_severity": case.min_severity,
        }
        for case in result["cases"]
    ]
    payload["techniques"] = [
        {
            "technique": technique.technique,
            "cases": technique.total,
            "passed": technique.passed,
            "required_rules": technique.required,
            "required_rules_found": technique.found,
        }
        for technique in result["techniques"]
    ]
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    result = run_corpus()

    html_out = None
    json_out = None
    while args:
        flag = args.pop(0)
        if flag in ("--html", "--json") and len(args) >= 2 and args[0] == "-o":
            destination = Path(args[1])
            args = args[2:]
            if flag == "--html":
                html_out = destination
            else:
                json_out = destination
            continue
        sys.stderr.write(f"usage: python -m bench.run [--html -o FILE] [--json -o FILE]\n")
        return 2

    if html_out:
        html_out.write_text(render_html(result), encoding="utf-8")
        sys.stdout.write(f"wrote {html_out} ({result['passed']}/{result['total']})\n")
    if json_out:
        _write_json(result, json_out)
        sys.stdout.write(f"wrote {json_out} ({result['passed']}/{result['total']})\n")
    if not html_out and not json_out:
        sys.stdout.write(render_table(result))

    if result["errors"]:
        return 2
    if result["passed"] != result["total"] or result["benign_fps"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
