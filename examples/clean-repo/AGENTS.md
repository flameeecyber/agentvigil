# Invoice service — agent conventions

This service renders invoices. Prefer editing modules under `src/invoices/` and
keep public function signatures stable.

## Commands

- `pytest -q` — run the test suite
- `ruff check .` — lint
- `python -m invoices.devserver` — run locally on port 8080

## Style

- Type hints on public functions.
- Money values are `Decimal`, never `float`.
- New endpoints need a test in `tests/`.

See `docs/architecture.md` for the data model.
