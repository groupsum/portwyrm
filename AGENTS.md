# Repository agent guidance

- Use `uv` for Python dependency management and command execution.
- Use `pytest` for tests and Ruff for linting and formatting.
- Treat `.ssot/` as CLI-managed state; use `uv run ssot-registry` rather than editing registry state by hand.
- Preserve Nginx Proxy Manager compatibility behavior inside `portwyrm.api.compat`; do not leak compatibility quirks into domain models.
- Preserve npmctl ownership metadata exactly: `meta.managed_by`, `meta.owner`, and `meta.resource_id`.
- Never mutate or prune foreign-owned resources. Adoption and prune operations must be explicit and owner-scoped.
- Update the p100 matrix, SSOT records, compatibility profiles, tests, and evidence whenever observable behavior changes.
- A feature is not parity-complete until its acceptance tests and evidence are linked.

