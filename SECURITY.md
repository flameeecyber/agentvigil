## Security policy

Report suspected malicious instruction-surface artifacts privately — do not
open a public issue naming a repo as malicious. Email the maintainers with
the finding JSON (`vigil scan --json`) and we will triage within 72h.

`vigil` never executes scanned content. Do not pipe untrusted repos into
shells, even to demo the risk — describe the finding instead.
