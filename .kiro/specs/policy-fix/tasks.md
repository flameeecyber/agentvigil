# Tasks: policy, markdown and fix

- [x] 1. Load policy JSON strictly; reject malformed files loudly.
- [x] 2. Evaluate `allow_rules`, `deny`, `deny_paths`, `fail_on` in that order.
- [x] 3. Wire `--policy` into `scan` and `diff`; exit `2` on a bad file.
- [x] 4. Render `--format markdown` for both scan and diff with redacted evidence.
- [x] 5. `vigil fix` dry run with per-file counts; `--apply` strips only
      `STRIP_CODEPOINTS`.
- [x] 6. Ship `strict`/`balanced`/`permissive` presets and `policy-init`.
- [x] 7. Unit test for `deny_paths` blocking and non-matching paths passing.
- [x] 8. Unit test that malformed policy exits 2.
- [x] 9. Unit test for `fix` dry run vs `--apply` and visible-byte preservation.
- [x] 10. Property test: `allow_rules` always exempts.
