# Tasks: kill chains and blame

- [x] 1. Emit `AV-CHAIN-001` for remote delegation + privileged execution.
- [x] 2. Emit `AV-CHAIN-002` for credential access + exfiltration, including
      rules decoded from tag/Base64 payloads.
- [x] 3. Emit `AV-CHAIN-003` for concealment + persistence/approval bypass.
- [x] 4. Emit `AV-CHAIN-004` for unpinned MCP + credential passthrough.
- [x] 5. Cite source rule ids in `metadata["sources"]` and contributing paths.
- [x] 6. `vigil blame PATH:LINE` and `vigil scan --blame` via read-only porcelain.
- [x] 7. Return `unknown` outside git (tested).
- [x] 8. `--no-chains` escape hatch.
- [x] 9. Unit test that `AV-CHAIN-003` fires on a crafted fixture.
- [x] 10. Unit test that a chain fires when the primitive is only in `inner_rules`.
