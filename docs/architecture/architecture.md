# Architecture

Status: accepted and implemented

Decision date: 2026-07-13

Updated: 2026-07-15

The canonical source tree is defined in [Repository and package layout](repository-layout.md).
The complete table inventory and operation ownership are defined in
[Tigrbl data model](tigrbl-data-model.md).

```text
NPM/npmctl API             Native API             Operator UIX
       \                       |                       /
                 terse Tigrbl app/router composition
                                |
       table schemas + builtin CRUD + narrow custom operations
                                |
             tigrbl_engine_* session and transaction boundary
                    /                           \
        normalized metadata              filesystem artifacts
     memory/sqlite/postgres/mysql       certs + immutable configs
                    \                           /
                  deterministic Nginx reconciler
                                |
                              nginx
```

## Boundaries

- `tables` is the sole metadata authority. Each table owns its columns, exported operation
  schemas, builtin CRUD profile, narrow custom operations, and lifecycle hooks.
- `api/compat` owns NPM/npmctl DTO quirks, authorization dependencies, error translation, and
  projections between normalized rows and the compatibility wire shape.
- `api/native` owns setup, health, metrics, token, portability, and native product routes.
- `config` selects public Tigrbl engine factories. Portwyrm does not wrap engine sessions or
  transactions.
- `identity` contains reusable security primitives and API identity types; durable identity,
  credential, PAT, session, MFA, role, permission, and membership state belongs to tables.
- `certificates` owns ACME/custom-certificate workflows and encrypted/private filesystem material.
- `runtime` owns deterministic templates, validation, immutable activation, reload, rollback,
  telemetry, logs, and drift detection.

There is no Portwyrm kernel, repository, unit of work, DBAPI transaction, SQLite transaction, or
application-service persistence layer. Downstream code invokes table operations through the
composed Tigrbl app; Tigrbl and the configured engine own session and transaction semantics.

## Canonical tables and operations

Tigrbl builtin CRUD and bulk CRUD are used for ordinary resources. Custom operations exist only
where an aggregate or security invariant requires one transaction:

- principals: `register`, `authenticate`, `change_password`, `set_password`,
  `set_authorization`, and `authorization`;
- PATs: `issue`, `revoke`, `refresh`, `rotate`, and `verify` in addition to CRUD;
- browser sessions: `issue`, `verify`, and `revoke`;
- MFA enrollments: `begin`, `enabled`, `confirm`, `verify`, `disable`, and
  `regenerate_backup_codes`;
- routing hosts, access lists, and certificates: compatibility aggregate create/update/delete
  operations that maintain their normalized child and join rows atomically;
- config generations: CRUD plus `activate`, `clear_active`, `validate`, `reload`, and `reconcile`;
- audit: append-oriented `record` operation.

The compatibility facade never stores plaintext passwords, PATs, MFA recovery codes, access-list
credentials, or private keys. Password-like values are write-only; opaque tokens are returned only
at issue/rotation time.

## Write and reconciliation model

An authorized table mutation commits desired state using the configured Tigrbl engine. Routing,
access, certificate, and setting changes enqueue reconciliation after commit. The reconciler
renders a complete immutable generation, validates it with `nginx -t`, atomically switches the
active generation, reloads Nginx, and persists the generation and reconcile result. A failed
candidate preserves desired state and the last-known-good active generation and records its
diagnostic.

Generated Nginx configuration is derived state, never metadata authority. Templates are
deterministic and covered by golden tests. Active files are never edited in place.

## Storage profiles

| Profile | Metadata engine | Artifact storage | Limits |
|---|---|---|---|
| Memory | `tigrbl_engine_mem` | temporary directory | process-local tests/demos |
| SQLite | `tigrbl_engine_sqlite` | durable filesystem | default single-node deployment |
| PostgreSQL | `tigrbl_engine_postgres` | durable filesystem/object mount | multi-node control plane |
| MySQL/MariaDB | `tigrbl_engine_mysql` | durable filesystem/object mount | available when the engine package is installed |

“Filesystem-only” is an import/export and disaster-recovery artifact profile, not a second live
metadata implementation. “Hybrid” means one Tigrbl database authority plus filesystem/object
certificate and generated-config artifacts. Every durable profile supports a backend-neutral,
checksummed export bundle and dry-run import.

## Security model

- Argon2id passwords; legacy bcrypt verifies once and upgrades on login.
- Compatibility sessions are short-lived. Native personal/service tokens are opaque, scoped,
  revocable, hashed at rest, and shown once.
- UI sessions use secure HttpOnly SameSite cookies and CSRF protection.
- TOTP secrets are encrypted; backup codes are individually hashed and one-use.
- Roles, permissions, role grants, direct grants/denials, and ACL membership are normalized rows.
- Access-list policy is data-plane authorization and remains distinct from operator RBAC.
- Secret, token, credential, and private-key values are redacted from compatibility metadata and
  audit records.

## Container topology

One immutable OCI image contains the Python application, UIX assets, Nginx, ACME tools, and a
minimal signal-forwarding supervisor. It exposes `80`, `443`, and compatibility admin port `81`;
database state and certificate material use separate durable mounts. Releases target amd64/arm64
and include Compose profiles, SBOM, provenance, vulnerability results, and signatures.
