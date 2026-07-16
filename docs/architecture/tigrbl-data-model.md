# Tigrbl data model

Status: implemented

Updated: 2026-07-16

Portwyrm binds 31 normalized tables to one configured Tigrbl engine. Managed collections use
Tigrbl's builtin single-row `create`, `read`, `update`, `replace`, `delete`, and `list` plans.
Aggregate behavior is attached to those plans with hooks; it is not a second CRUD implementation.
Custom operations are reserved for named workflows and operational state transitions.

| Capability | Canonical tables | Custom operations |
|---|---|---|
| Identity | `principals`, `credentials`, `browser_sessions` | `register`, `authenticate`, `change_password`, `set_password`, `update_identity`, `set_authorization`, `authorization`, session `issue`, `verify`, `revoke` |
| RBAC | `roles`, `permissions`, `principal_roles`, `role_permissions`, `principal_permissions` | read/list inspection; mutation is owned by principal authorization operations |
| Personal access tokens | `personal_access_tokens` | `issue`, `verify`, `revoke`, `refresh`, `rotate`; no generic CRUD |
| MFA | `mfa_enrollments`, `mfa_recovery_codes` | `begin`, `enabled`, `confirm`, `verify`, `disable`, `regenerate_backup_codes` |
| Access policy | `access_lists`, `access_list_rules`, `access_list_credentials`, `access_list_principals` | canonical access-list CRUD with aggregate child hooks; private `runtime_list` projection |
| Certificates | `certificates`, `certificate_domains`, `certificate_challenges` | canonical CRUD plus `validate`, `upload`, `request`, `renew`, `download`, and `remove` |
| HTTP routing | `routing_hosts`, `routing_sources`, `routing_upstreams`, `routing_locations`, `routing_host_access_lists` | canonical aggregate CRUD, `enable`/`disable` update aliases, `validate`, and `preview` |
| Streams and history | `stream_routes`, `host_config_revisions` | stream CRUD and `enable`/`disable`; revisions are append-only history |
| Runtime | `config_generations`, `reconcile_attempts`, `runtime_leases` | `activate`, `clear_active`, `validate`, `reload`, `reconcile` |
| Settings and evidence | `settings`, `audit_events`, `system_migrations` | setting CRUD; audit and schema history are read-only externally with explicit record operations |

## Lifecycle policy

- A router-global `PRE_HANDLER` hook assigns owners and blocks foreign-owned mutation.
- `enable` and `disable` are aliases of canonical `update`; table hooks supply the boolean payload.
- Aggregate root hooks validate and stage child rows around canonical collection CRUD.
- A router-global `PRE_COMMIT` hook stages redacted audit events in the same transaction.
- A router-global `POST_COMMIT` hook reconciles Nginx only for configuration-affecting tables.
- Compatibility routes bind transport inputs to table operations and never select, flush, or commit.

## Engine ownership

`portwyrm.config.engine_from_settings` selects public Tigrbl engine factories:

- `mem` for ephemeral process-local state;
- `sqlitef` for the default durable single-node database;
- `pgs` or `pga` for synchronous/asynchronous PostgreSQL;
- the synchronous `mysql` engine specification when the separately released
  `tigrbl_engine_mysql` package is installed. Async MySQL is rejected explicitly.

Portwyrm never creates an engine session, transaction wrapper, repository, or unit of work.
Tigrbl opens the operation session and owns flush/commit/rollback. Operations and hooks use
`ctx["db"]` only inside the governed lifecycle and contain no explicit flush or commit calls.

## Secret persistence

- principal passwords, session tokens, PATs, access-list credentials, and MFA recovery codes are
  hashed at rest;
- TOTP seeds are encrypted with a durable Fernet key;
- certificate private keys remain in the protected material store and never enter API metadata;
- plaintext tokens and recovery values are returned only by their issue/rotation operation;
- compatibility metadata is scrubbed before it is stored or audited.

Normalized database rows are the authority for canonical fields and relationships. Compatibility
metadata retains only unknown NPM/npmctl extension fields. Certificate material and immutable Nginx generations are
filesystem/object artifacts. Export bundles are checksummed portability artifacts, not an
additional writable database.
