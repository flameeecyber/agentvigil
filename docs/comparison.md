# Comparison (honest)

| Tool | Answers | Provenance | Rug-pull | Runtime | Offline | Price |
|---|---|---|---|---|---|---|
| `mcp-scan` / MCP scanners | is this MCP evil now? | no | no | no | yes | free |
| `tirith`, `uncloak`, skill scanners | is this file evil now? | no | no | no | yes | free |
| Snyk agent-scan | inventory + posture | partial | no | observe | cloud | paid |
| IDE guardrails | block one action | no | no | yes | no | bundled |
| **agentvigil** | **what changed, what it grants, who approved** | **vigil.lock + sig** | **diff + proxy hash** | **sanitize** | **yes** | **free CLI** |

We complement scanners: use them for detection breadth, us for review workflow.
We do not claim sandboxing or model safety. See `threat-model.md`.
