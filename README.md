# Portwyrm

Portwyrm is a self-hosted reverse proxy control plane and operator UI designed to replace
Nginx Proxy Manager while remaining compatible with npmctl's current API contract.

The `1.0.0` MVP target is literal p100 coverage of the frozen compatibility envelope. Early
alpha, beta, and release-candidate versions are milestones toward that target, not claims of
partial MVP completion.

## Status

Portwyrm is implementing its frozen T1 direct-behavior boundary. The repository includes a
Python control plane, NPM/npmctl compatibility API, persistence ports, deterministic Nginx
runtime, certificate services, migration tooling, and a packaged no-build operator console.
T2 robustness and release certification remain separate gates and are never inferred from
scaffold checks.

## Development

```shell
uv sync --dev
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv run ssot-registry validate . --write-report
```

Run the development control plane and open `http://localhost:81/ui/`:

```shell
uv run portwyrm --host 127.0.0.1 --port 81
```

The same package includes an operator CLI. It speaks the npmctl-compatible API, accepts a
token through `--token` or `PORTWYRM_TOKEN`, and prints stable JSON for automation:

```shell
uv run portwyrm setup --email admin@example.com --password 'change-me-now'
uv run portwyrm login --email admin@example.com --password 'change-me-now'
uv run portwyrm status
uv run portwyrm list proxy-hosts --token "$PORTWYRM_TOKEN"
uv run portwyrm create proxy-hosts --token "$PORTWYRM_TOKEN" --data proxy-host.json
```

`serve`, `status`, `schema`, `setup`, `login`, `list`, `get`, `create`, `update`, and
`delete` are available without Node.js or npm.

The UI is packaged as standards-based browser assets. Node.js and npm are not required to
build, install, deploy, or operate Portwyrm.

## Compatibility principles

- Preserve the NPM-shaped `/api` surface used by npmctl.
- Keep compatibility DTOs separate from native domain models.
- Preserve IDs and npmctl owner metadata during import and round trips.
- Compile deterministic Nginx generations, validate them, activate atomically, and retain a
  last-known-good rollback target.
- Support memory, SQLite, MySQL/MariaDB, PostgreSQL, filesystem-only, and hybrid persistence
  with explicit consistency and high-availability boundaries.

Licensed under Apache-2.0.
