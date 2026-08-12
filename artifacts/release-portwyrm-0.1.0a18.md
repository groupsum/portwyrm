# Portwyrm 0.1.0a18 release operations

Release type: alpha patch
Package version: 0.1.0a18
Git tag: v0.1.0a18

The wheel is attached to the GitHub release but is not uploaded to PyPI while
Portwyrm depends on direct-source Tigrbl Auth packages that PyPI metadata does
not accept.

## Scope

- Request and report an explicitly sized UDP receive queue for the public QUIC listener.
- Move route-file polling out of the established-packet forwarding path.
- Route short-header packets through a constant-size connection-ID length index instead of rebuilding and sorting all active connection IDs per datagram.
- Log listener and upstream UDP socket errors.

## Container promotion

Publish the `v0.1.0a18` multi-platform image, verify its signature and provenance, then update deployments to the immutable `ghcr.io/groupsum/portwyrm@sha256:...` reference.
