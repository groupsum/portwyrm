# Architecture

Status: accepted and implemented
Decision date: 2026-07-13

The canonical source and package tree is defined in
[Repository and package layout](repository-layout.md).

```text
NPM-compatible /api       Native /api/v2       Operator UI
          \                    |                   /
                    Tigrbl ASGI control plane
                              |
       auth/policy -> commands/queries -> audit/outbox
                              |
       domain services + repositories + transactional UoW
          /                     |                       \
 persistence             certificate service       reconciler
 memory/sql/fs/pg         ACME + SecretStore        render/test/swap
                                                        |
                                                      nginx
```

## Boundaries

- `tables` owns the canonical normalized Tigrbl models, engine selection, builtin/custom
  operations, lifecycle hooks, and the temporary collection-to-table projector.
- `api/compat` owns profile DTOs, defaults, quirks, and error translation.
- `api/native` owns jobs, scoped tokens, health, import/export, and capabilities.
- `domain` owns entities and invariants without HTTP or storage concerns.
- `application` owns commands, queries, units of work, authorization, and orchestration.
- `persistence` implements `RepositorySet`, `UnitOfWork`, `BlobStore`,
  `SecretStore`, `LeaseStore`, `EventJournal`, `Outbox`, and `MigrationStore`.
- `certificates` owns custom certificates, ACME, renewal, and DNS provider adapters.
- `runtime` owns deterministic templates, validation, activation, reload, health, rollback,
  and drift detection.

## Tigrbl migration and compatibility

Tigrbl is the only application framework. Portwyrm does not depend on FastAPI or Starlette.
Compatibility and native HTTP routes are Tigrbl route operations, and canonical tables bind
Tigrbl builtin CRUD plus narrowly scoped custom operations and lifecycle hooks.

The migration is deliberately staged. The frozen NPM/npmctl collection repository remains the
write-side compatibility boundary while every committed mutation is projected transactionally into
24 normalized Tigrbl tables. That projection is idempotent and runs before Tigrbl opens a write
transaction, which avoids SQLite lock inversion. It preserves legacy IDs in metadata while using
distinct rows for principals, permissions, PAT digests, MFA recovery digests, access-list edges,
certificate domains, routing sources, upstreams, and immutable configuration revisions.

The final cutover reverses this dependency: Tigrbl tables become authoritative and the NPM shape
becomes a read/write projection. Until that cutover is certified, table routers remain unmounted
from public paths; the authenticated compatibility API is the supported external contract.

## Write and reconciliation model

An authorized command writes desired state and an outbox job in one transaction. The
reconciler acquires a lease, renders a complete immutable generation, runs `nginx -t`,
atomically switches the active generation, reloads Nginx, and probes health. Success advances
`applied_generation`; failure preserves desired state and the last-known-good active
generation while surfacing a recoverable degraded state.

Generated Nginx configuration is derived state, never authority. Templates are deterministic
and covered by golden tests. Active files are never edited in place.

## Persistence modes

| Mode | Canonical state | Limits |
|---|---|---|
| Memory | copy-on-write maps and temporary blobs | process-local; tests/demos only |
| SQLite | Legacy projection and normalized Tigrbl tables in one WAL database | default single node; one mutation writer |
| PostgreSQL | SQL metadata, row locks, advisory lease, transactional outbox | HA control plane |
| Filesystem | versioned snapshots plus a normalized SQLite table sidecar | single writer only |
| Hybrid | SQLite/PostgreSQL metadata plus filesystem/object blobs | recommended production form |

Every durable mode supports a backend-neutral, versioned export bundle with entities,
relationships, audit cursor, checksums, and encrypted secret references. Cross-backend moves
use export, validate, dry-run import, and reconcile.

## Security model

- Argon2id passwords; legacy bcrypt verifies once and upgrades on login.
- Compatibility JWTs are short-lived. Native personal/service tokens are opaque, scoped,
  revocable, hashed at rest, and shown once.
- UI sessions use secure HttpOnly SameSite cookies and CSRF protection.
- TOTP secrets are encrypted; backup codes are individually hashed.
- Admin bypass and NPM family `manage/view/hidden` plus `visibility=all/user` are preserved.
- Access-list policy is data-plane authorization and remains distinct from operator RBAC.
- Secret, token, credential, and private-key values are always redacted from audit records.
- Advanced Nginx configuration requires an explicit privileged capability and audit event.

## Container topology

One immutable OCI image contains the Python application, built UI assets, Nginx, ACME tools,
and a minimal signal-forwarding supervisor. It exposes `80`, `443`, and compatibility
admin port `81`; state and certificate material use separate durable mounts. The release
publishes amd64/arm64 images, Compose examples for every persistence mode, SBOM, provenance,
vulnerability results, and signatures to GHCR and Docker Hub.
