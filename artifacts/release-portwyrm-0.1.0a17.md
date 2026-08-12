# Portwyrm 0.1.0a17 release operations

Release type: alpha patch
PyPI version: 0.1.0a17
Git tag: v0.1.0a17

## Scope

- Key opening QUIC sessions by client address plus original destination
  connection ID, which remains unique when Chromium uses an empty source CID.
- Preserve routing by server-issued destination connection IDs after the
  upstream handshake begins.
- Cover concurrent connections from one UDP address with empty client source
  connection IDs.

## Container promotion

Publish the `v0.1.0a17` multi-platform image, verify its signature and
provenance, then update deployments to the immutable
`ghcr.io/groupsum/portwyrm@sha256:...` reference.
