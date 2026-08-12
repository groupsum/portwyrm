# Portwyrm 0.1.0a20 release operations

Release type: alpha patch
Package version: 0.1.0a20
Git tag: v0.1.0a20

The wheel is attached to the GitHub release but is not uploaded to PyPI while
Portwyrm depends on direct-source Tigrbl Auth packages that PyPI metadata does
not accept.

## Scope

- Record bounded route-open and upstream-first-response latency without packet payloads.
- Include queued datagram counts so production QUIC handshake delay can be localized.
- Preserve the a19 multiworker and receive-buffer behavior unchanged.

## Container promotion

Publish the `v0.1.0a20` multi-platform image, verify its signature and provenance,
then update deployments to its immutable `ghcr.io/groupsum/portwyrm@sha256:...`
reference before collecting a correlated live trace.
