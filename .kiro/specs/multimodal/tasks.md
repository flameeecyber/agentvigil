# Tasks: multimodal smuggling

- [x] 1. Scan SVG for `<script>` and `<foreignObject>` (`AV-IMG-001`).
- [x] 2. Scan SVG/HTML image markup for `on*` handlers (`AV-IMG-002`).
- [x] 3. Detect invisible `<text>` via CSS properties (`AV-IMG-003`).
- [x] 4. Detect remote-image delegation with surrounding prose (`AV-IMG-004`),
      capabilities `net.egress`, `agent.deceive`, `agent.self_modify`.
- [x] 5. Decode and scan data-URI images (`AV-IMG-006`).
- [x] 6. Parse PNG `tEXt`/`zTXt`/`iTXt` with `struct` + `zlib` (`AV-IMG-010`).
- [x] 7. Benign PNG fixture stays quiet.
- [x] 8. Unit test for `AV-IMG-002` event handlers.
- [x] 9. Unit test for `AV-IMG-003` invisible SVG text.
- [x] 10. Property test: truncated/random PNG bytes never raise.
