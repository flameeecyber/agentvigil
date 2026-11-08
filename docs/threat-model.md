# Threat model (honest scope)

Protects: the instruction channel — `AGENTS.md`, skills, MCP configs, hooks —
against unreviewed change, invisible smuggling, rug pulls, and credential theft paths.

Does NOT claim: sandboxing, model-weight safety, malicious IDE extensions, compromised
MCP server turning evil after `tools/list` (proxy hashes descriptors but cannot stop it),
or runtime prompt injection from web pages (unless `vigil mcp` wraps those tools).

Outcomes: reviewable artifacts (decoded evidence, capability delta, blame), signed
provenance (`vigil.lock` + Ed25519/sigstore), CI gates. Raises cost, catches the common
case, creates a trail.
