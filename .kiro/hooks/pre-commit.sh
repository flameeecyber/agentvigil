#!/bin/sh
# Git pre-commit gate. Kiro's own hooks live in .kiro/hooks/*.json; this file is
# the portable git-hook equivalent for contributors who do not run the IDE.
# Install: ln -s ../../.kiro/hooks/pre-commit.sh ../../.git/hooks/pre-commit
set -eu

run_vigil() {
  if command -v vigil >/dev/null 2>&1; then
    vigil "$@"
  elif [ -x .venv/bin/python ]; then
    .venv/bin/python -m vigil.cli "$@"
  else
    echo "vigil: not installed (pip install -e . or create .venv); skipping gate" >&2
    return 0
  fi
}

run_vigil scan . --fail-on high -q
if [ -f vigil.lock ]; then
  # `diff` takes the repo path, not a positional lockfile; --lock is the flag.
  run_vigil diff --lock vigil.lock --fail-on high
fi
