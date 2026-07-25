# Portwyrm 0.1.0a4 release operations

Status: release candidate
Release date: 2026-07-25
PyPI version: 0.1.0a4
OCI tag: 0.1.0-a4
Git tag: v0.1.0-a4

## Approved release facts

- Unmatched HTTP hosts default to Nginx 444, verified as an HTTP connection closed without a response.
- PyPI trusted publishing uses the shared cobycloud/actions trusted-publish action inside Portwyrm's authorized release workflow.
- GHCR publication uses the shared cobycloud/actions reusable GHCR workflow.
- Real protocol validation is bounded by a workflow timeout.
- PyPI 0.1.0a3 was published, but its GHCR run was canceled before publication because the raw-socket 444 probe hung. The a3 tag remains immutable.
- This is an alpha milestone, not a stable or p100 compatibility claim.

## Upgrade

    uv tool install --upgrade portwyrm==0.1.0a4
    docker pull ghcr.io/groupsum/portwyrm:0.1.0-a4

Use the verified OCI digest in durable deployments.

## Migration and rollback

No manual schema migration is introduced. Back up /data and /etc/letsencrypt before replacement. Roll back to the previously verified 0.1.0-a1 digest plus the corresponding backup when necessary.

## Verification

- Clean wheel import reports 0.1.0a4.
- PyPI exposes wheel and source distribution.
- GHCR exposes signed multi-platform 0.1.0-a4 with SBOM and provenance.
- Anonymous pull, Cosign signature, and GitHub attestation checks pass.
- No latest tag is assigned.

