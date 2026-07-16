# Repository and package layout

Status: accepted and implemented

Decision date: 2026-07-14

Updated: 2026-07-15

Portwyrm ships one Python distribution and one OCI product image. Tigrbl tables and their
operations own persistent business state. API packages compose those tables and translate the
NPM/npmctl compatibility contract; they do not introduce repositories, units of work, or a
Portwyrm-facing kernel abstraction.

```text
portwyrm/
|-- deploy/                         container entry point and deployment assets
|-- docs/                           architecture, operations, and product contracts
|-- src/portwyrm/
|   |-- api/
|   |   |-- compat/                 NPM/npmctl HTTP facade and wire projections
|   |   |-- native/                 setup, health, metrics, and native routes
|   |   |-- app.py                  terse Tigrbl composition root
|   |   |-- security.py             session/PAT table-operation adapter
|   |   |-- mfa.py                  MFA table-operation adapter
|   |   `-- portability.py          portable bundle projection and validation
|   |-- certificates/               ACME/custom material workflows over certificate tables
|   |-- cli/                        local server and remote automation commands
|   |-- config/                     settings and public tigrbl_engine_* selection
|   |-- domain/                     Nginx render inputs and validation invariants
|   |-- identity/                   password, permission, MFA, and API identity types
|   |-- migration/                  NPM preflight and normalized import transformations
|   |-- runtime/                    render, validate, activate, reload, telemetry, and logs
|   |-- tables/                     canonical Tigrbl tables, schemas, hooks, and operations
|   `-- uix/
|       |-- static/                 packaged HTML, CSS, and JavaScript; no build step
|       `-- mount.py                ASGI mounting boundary
|-- tests/
|   |-- integration/                cross-component and protocol behavior
|   |-- robustness/                 security, failure, and T2 evidence
|   `-- runtime/                    table, API, UIX, and Nginx runtime behavior
`-- pyproject.toml                  distribution, dependencies, tools, and package data
```

The removed `application/`, `persistence/`, and `operations/` packages are intentionally absent.
Their repository/UoW wrappers duplicated Tigrbl engine sessions and transactions, while their
operational helpers now live under `runtime/`. Public request and response schemas are exported
from their owning tables whenever the schema is part of a table operation.

The public executable remains `portwyrm`. `portwyrm.api` composes compatibility and native
routers, `portwyrm.cli` provides automation, and `portwyrm.uix` owns browser delivery. The
executable layout test enforces these ownership decisions and verifies UIX wheel package data.
