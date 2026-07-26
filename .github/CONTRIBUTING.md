# Contributing to Concordia DAO Council

Thanks for your interest in Concordia — a policy-governed DAO execution layer on
the Casper Network. This guide covers how to get set up and how to propose
changes.

## Development setup

The project uses [uv](https://docs.astral.sh/uv/) for Python dependency
management.

```bash
uv sync --frozen --python 3.12.11
uv run --frozen --isolated --python 3.12.11 python -m pytest -q
make smoke
```

The gateway, dashboard, agents, and Casper contract each have their own `make`
targets — see the [Makefile](../Makefile) and [README.md](../README.md).

## Making changes

1. Open an issue describing the bug or proposed change before large work.
2. Keep pull requests focused; one logical change per PR.
3. Add or update tests for any behavior change — the suite must stay green.
4. Run `uv run --frozen --isolated --python 3.12.11 python -m pytest -q`
   locally before pushing; CI runs the same pinned suite.
5. Do not commit generated artifacts, `.zip` archives, `__pycache__`, or local
   databases — these are covered by [.gitignore](../.gitignore).

## Security

Please do not open public issues for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for responsible disclosure.

## Code style

- Python: type hints on public functions, standard library `pathlib`/`json`.
- Keep new code consistent with the surrounding module.
