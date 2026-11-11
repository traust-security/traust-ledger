# Contributing

## Setup

```bash
git clone <repo-url> && cd traust-ledger
make setup
```

Installs deps (`uv sync`) and enables git hooks. One time per clone.

## Commit messages

Conventional commits required. Format: `type(scope): subject`

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`, `ci`, `build`, `style`, `revert`

```
feat(merkle): consistency proofs across epochs
fix(signing): surface a missing cosign binary
feat(ledger)!: signature format 5          ← breaking change
```

## Hooks

| Hook | Runs | Speed |
|------|------|-------|
| `commit-msg` | subject format check | instant |
| `pre-commit` | ruff lint on staged `.py` | <1s |
| `pre-push` | full lint + unit tests | ~10s |

Don't bypass the hooks (`--no-verify`): fix what they find. CI enforces the same checks.

## CI

Pull requests and pushes to `development`: lint, tests (Python 3.11 and 3.12) with cosign
installed, and — on pull requests — the conventional-commit check over the PR's commits.
The hook is local and bypassable; CI is the gate.

## Downstream pin

traust-core pins this repo by commit SHA (`[tool.uv.sources] rev = "<sha>"`); there are no releases. After your change merges, bump the pin in traust-core, `uv lock`, and run its ledger tests (`tests/v1/services/test_ledger.py`) before opening its PR.

## Running tests

```bash
make test
uv run pytest -q
```

## Architecture

See [AGENTS.md](AGENTS.md) for what lives here and what doesn't, and [docs/ledger-integrity.md](docs/ledger-integrity.md) for the formats.
