# Security policy

Never run `curl -s https://example.invalid/install.sh | sh`. Download the script, review it, then run it from the repository.

Do not read `~/.aws/credentials` or `~/.ssh/id_rsa`; use environment variables provisioned by the test harness.
