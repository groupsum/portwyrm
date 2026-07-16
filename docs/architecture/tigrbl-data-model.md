# Tigrbl data model

Status: implemented

Updated: 2026-07-15

Portwyrm binds 31 normalized tables to one configured Tigrbl engine. Ordinary resources use
Tigrbl builtin CRUD/bulk CRUD. Custom operations exist only for aggregate writes, credential
handling, or runtime state transitions that must remain atomic.

| Capability | Canonical tables | Custom operations |
|---|---|---|
| Identity | `principals`, `credentials`, `browser_sessions` | `register`, `authenticate`, `change_password`, `set_password`, `update_identity`, `set_authorization`, `authorization`, session `issue`, `verify`, `revoke` |
| RBAC | `roles`, `permissions`, `principal_roles`, `role_permissions`, `principal_permissions` | principal authorization replacement/projection; all role and permission entities retain CRUD |
| Personal access tokens | `personal_access_tokens` | `issue`, `verify`, `revoke`, `refresh`, `rotate` plus CRUD |
| MFA | `mfa_enrollments`, `mfa_recovery_codes` | `begin`, `enabled`, `confirm`, `verify`, `disable`, `regenerate_backup_codes` |
| Access policy | `access_lists`, `access_list_rules`, `access_list_credentials`, `access_list_principals` | aggregate `create_compat`, `update_compat`, `delete_compat`; private `runtime_list` projection |
| Certificates | `certificates`, `certificate_domains`, `certificate_challenges` | aggregate compatibility writes; ACME/custom workflows live in `certificates/` and invoke table operations |
| HTTP routing | `routing_hosts`, `routing_sources`, `routing_upstreams`, `routing_locations`, `routing_host_access_lists` | aggregate `create_compat`, `update_compat`, `delete_compat` |
| Streams and history | `stream_routes`, `host_config_revisions` | CRUD; revision rows are immutable applied-config history |
| Runtime | `config_generations`, `reconcile_attempts`, `runtime_leases` | `activate`, `clear_active`, `validate`, `reload`, `reconcile` |
| Settings and evidence | `settings`, `audit_events`, `system_migrations` | setting CRUD, audit `record`; migration `plan`, `apply`, `record_failure`, `read`, and `list` |

## Engine ownership

`portwyrm.config.engine_from_settings` selects public Tigrbl engine factories:

- `mem` for ephemeral process-local state;
- `sqlitef` for the default durable single-node database;
- `pgs` or `pga` for synchronous/asynchronous PostgreSQL;
- the synchronous `mysql` engine specification when the separately released
  `tigrbl_engine_mysql` package is installed. Async MySQL is rejected explicitly.

Portwyrm never creates an engine session, transaction wrapper, repository, or unit of work.
Tigrbl opens the operation session and owns commit/rollback. Custom operations use `ctx["db"]`
only inside their Tigrbl transaction.

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
