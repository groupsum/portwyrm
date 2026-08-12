# Portwyrm 0.1.0a19 release operations

Release type: alpha patch
Package version: 0.1.0a19
Git tag: v0.1.0a19

The wheel is attached to the GitHub release but is not uploaded to PyPI while
Portwyrm depends on direct-source Tigrbl Auth packages that PyPI metadata does
not accept.

## Scope

- Run a bounded, configurable pool of QUIC forwarding workers.
- Use Linux `SO_REUSEPORT` to keep a busy media flow from starving a new QUIC handshake.
- Preserve one-worker compatibility and reject invalid worker counts.

## Container promotion

Publish the `v0.1.0a19` multi-platform image, verify its signature and provenance,
then update deployments to the immutable `ghcr.io/groupsum/portwyrm@sha256:...`
reference with `PORTWYRM_QUIC_WORKERS=4`.
