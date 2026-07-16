# Tigrbl lifecycle refactor evidence

Date: 2026-07-16

## Contract

- Managed collections expose canonical single-row create, read, update, replace, delete, and list.
- Routing hosts and streams expose enable and disable as update aliases with payload hooks.
- Aggregate children are staged and projected by canonical CRUD hooks.
- Audit staging, authorization, ownership, visibility, and reconciliation are router-global hooks.
- Audit insertion occurs before commit in the resource transaction; reconciliation occurs after commit.
- Audit/history/lease/credential tables expose narrow operation profiles.
- No bulk CRUD, legacy compatibility CRUD operations, direct table flushes, or direct SQL/Pydantic imports remain in collection table modules.

## Verification

- `pytest -q`: 186 passed, 1 Docker-only test skipped.
- `pytest -q tests/runtime`: 71 passed.
- Ruff check of every changed Python file: passed.
- Initialized operation-surface probe confirmed no bulk operation aliases and no legacy `*_compat` CRUD aliases.
- Source scans confirmed all table columns use `acol` and table modules contain no direct `Column`, SQLAlchemy, or Pydantic imports.
- Atomicity test confirmed a failed audit foreign key rolls back its associated resource write.
- HTTP lifecycle test confirmed create, disable, enable, update, replace, read/list, and semantic audit actions.

The skipped test requires `PORTWYRM_RUN_DOCKER_TESTS=1` and exercises real container protocols; it is outside this table-kernel refactor.
