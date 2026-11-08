# Contributing (add a payload in 5 minutes)

1. Pick a technique id (`D2.1`, `M1.3`, …) or propose one in `docs/decisions.md`.
2. Add `bench/payloads/<technique>/<slug>/file.md` + `expected.json` with hand-authored labels (`must_fire`, optional `must_not_fire`, optional `min_severity`). See `bench/README.md` for the schema.
3. Add a benign neighbor in `bench/benign/` if your rule risks FPs. Include realistic prose that describes the attack, not just clean docs.
4. Run `python -m pytest -q` and `python -m bench.run` — both must stay green. A missing/malformed case exits 2 instead of being skipped.
5. Open a PR with the `vigil diff --format markdown` body pasted in.

Rules are data (`vigil/detectors/patterns.py`); detectors are pure functions;
every finding needs evidence + remediation. Precision beats volume.
