# Repository and package layout

Status: accepted
Decision date: 2026-07-14

Portwyrm ships one Python distribution and one OCI product image. The CLI, API, UIX, domain,
application services, persistence adapters, certificate automation, and Nginx runtime are
capability packages inside that distribution. They are not independently versioned artifacts.
This keeps every interface on one compatibility version and preserves the no-Node/no-npm
installation contract.

```text
portwyrm/
|-- deploy/                         container entry point and deployment assets
|-- docs/                           architecture, operations, and product contracts
|-- src/portwyrm/
|   |-- api/
|   |   |-- compat/                 npmctl/NPM-compatible HTTP facade
|   |   `-- native/                 setup, health, metrics, and native product routes
|   |-- application/                use cases and persistent control-plane orchestration
|   |-- certificates/               ACME, custom certificate, renewal, and material handling
|   |-- cli/                        local server and remote automation commands
|   |-- domain/                     storage- and transport-neutral models
|   |-- identity/                   sessions, tokens, authentication, and authorization
|   |-- migration/                  NPM preflight and import workflows
|   |-- operations/                 health, upgrades, logs, and operational configuration
|   |-- persistence/                memory, SQL, filesystem, and hybrid repositories
|   |-- runtime/                    deterministic Nginx render, validate, activate, and rollback
|   `-- uix/
|       |-- static/                 packaged HTML, CSS, and JavaScript; no build step
|       `-- mount.py                ASGI mounting boundary
|-- tests/
|   |-- integration/                cross-component and protocol behavior
|   |-- robustness/                 security, failure, and T2 evidence
|   `-- runtime/                    unit and composed runtime behavior
`-- pyproject.toml                  distribution, dependencies, tools, and package data
```

The public executable remains `portwyrm`. `portwyrm.api` composes compatibility and native
routers, `portwyrm.cli` provides automation, and `portwyrm.uix` owns browser delivery. Root-level
`service`, `persistent`, `mfa`, and `ui` modules are forbidden because they obscure ownership and
can collide with package names. The executable layout test enforces these decisions and verifies
that UIX assets are declared as wheel package data.
