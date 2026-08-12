# Portwyrm 0.1.0a16 release operations

Status: release candidate
Release date: 2026-08-12
PyPI version: 0.1.0a16
Git tag: v0.1.0a16

## Approved release facts

- Includes the 0.1.0a15 concurrent QUIC connection-identity routing correction.
- Persistent schema migrations now run before entrypoint bootstrap and Nginx reconciliation writes any audit records.
- Existing databases missing the audit attribution columns can start, migrate, and reconcile without a restart loop.
- The ASGI lifespan keeps its idempotent migration gate for ordinary application startup.
- This is an alpha correction and does not claim general p100 compatibility or a production latency class until live verification passes.

## Upgrade

Pull the published `v0.1.0a16` multi-platform image, resolve its manifest digest, and update durable deployments to the immutable `ghcr.io/groupsum/portwyrm@sha256:...` reference.

## Compatibility and migration

On persistent deployments, startup applies the existing certificate-owner and audit-attribution schema migrations before seeding or reconciliation. The migrations are idempotent and retain the existing database, configuration, and route data.

## Rollback

Restore the previously verified Portwyrm manifest digest in the infrastructure workload declaration and reapply the reviewed deployment plan. A rollback does not remove columns already added by the forward migration.

## Verification gates

- Entrypoint ordering regression test proves migration precedes seed and reconcile.
- Focused migration tests, Ruff check, Ruff formatting, and the full Python suite pass.
- GHCR publishes and verifies a signed multi-platform manifest for the release commit.
- The infrastructure repository pins the reviewed immutable manifest digest.
- Production proves simultaneous presenter publishing, audience handshake/join, media delivery, control responsiveness, and the requested presentation latency class.