# Tasks: Unicode smuggling

- [x] 1. Decode surface bytes as UTF-8 with replacement (never raise).
- [x] 2. Detect tag characters, decode the ASCII payload, set `decoded` and span.
- [x] 3. Re-scan decoded payload with the pattern pack; merge capabilities and
      `metadata["inner_rules"]`.
- [x] 4. Detect bidi controls (`AV-UNI-002`) and zero-width characters
      (`AV-UNI-003`), exempting a single leading BOM.
- [x] 5. Detect variation-selector runs (`AV-UNI-005`) and decode direct, nibble
      and raw-byte steganography.
- [x] 6. Detect homoglyphs inside ASCII words (`AV-UNI-006`).
- [x] 7. Malicious and benign unit fixtures (tag, bidi, zero-width, homoglyph).
- [x] 8. Property test: tag encode/decode identity across printable ASCII.
- [x] 9. Regression test for `inner_rules` capability attribution.
- [x] 10. Regression test for the nibble and supplementary-VS decode paths.
