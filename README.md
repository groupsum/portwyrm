# Portwyrm

Portwyrm is a self-hosted reverse proxy control plane and operator UI designed to replace
Nginx Proxy Manager while remaining compatible with npmctl's current API contract.

The `1.0.0` MVP target is literal p100 coverage of the frozen compatibility envelope. Early
alpha, beta, and release-candidate versions are milestones toward that target, not claims of
partial MVP completion.

## Status

Portwyrm is in repository and contract bootstrap. Product, compatibility, architecture, UX,
and delivery artifacts live under [`docs/`](docs/).

## Development

```shell
uv sync --dev
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv run ssot-registry validate . --write-report
```

## Compatibility principles

- Preserve the NPM-shaped `/api` surface used by npmctl.
- Keep compatibility DTOs separate from native domain models.
- Preserve IDs and npmctl owner metadata during import and round trips.
- Compile deterministic Nginx generations, validate them, activate atomically, and retain a
  last-known-good rollback target.
- Support memory, SQLite, PostgreSQL, filesystem-only, and hybrid persistence with explicit
  consistency and high-availability boundaries.

Licensed under Apache-2.0.
