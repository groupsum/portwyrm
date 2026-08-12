# Portwyrm 0.1.0a15 release operations

Status: release candidate
Release date: 2026-08-12
PyPI version: 0.1.0a15
Git tag: v0.1.0a15

## Approved release facts

- QUIC passthrough affinity is scoped by client address and QUIC connection identity instead of client UDP address alone.
- Concurrent QUIC connections from one client UDP address retain independent upstream sockets, pending queues, and server connection-ID routing.
- An unknown short-header connection ID is dropped when multiple sessions share an address instead of being mixed into an arbitrary upstream connection.
- Existing same-connection Initial and Retry traffic retains its established upstream affinity.
- This is an alpha correction and does not claim general p100 compatibility or a production latency class until live verification passes.

## Upgrade

Pull the published `v0.1.0a15` multi-platform image, resolve its manifest digest, and update durable deployments to the immutable `ghcr.io/groupsum/portwyrm@sha256:...` reference.

## Compatibility and migration

No database or configuration migration is introduced. QUIC passthrough routes retain their existing API and rendered configuration. The runtime-only behavior change permits concurrent connection identities that share one observed client UDP address.

## Rollback

Restore the previously verified Portwyrm manifest digest in the infrastructure workload declaration and reapply the reviewed deployment plan. Database and certificate state are compatible in both directions for this release.

## Verification gates

- Ruff check and formatting pass.
- Full Python test suite passes.
- QUIC routing tests prove concurrent same-address connection isolation and server connection-ID demultiplexing.
- GHCR publishes a signed multi-platform manifest for the release commit.
- The infrastructure repository pins the reviewed immutable manifest digest.
- Production proves simultaneous presenter publishing, audience handshake/join, media delivery, control responsiveness, and the requested presentation latency class.
