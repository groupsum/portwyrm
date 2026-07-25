# Portwyrm 0.1.0a3 release operations

Status: release candidate
Release date: 2026-07-25
PyPI version: 0.1.0a3
OCI tag: 0.1.0-a3
Git tag: v0.1.0-a3

## Approved release facts

- Unmatched HTTP hosts now default to a silent Nginx 444 connection close.
- Unit and real-container protocol coverage verify that secure default.
- PyPI trusted publishing executes the shared cobycloud/actions/actions/pypi-trusted-publish@master action inside Portwyrm's authorized release.yml job. PyPI does not currently support reusable workflows as Trusted Publisher identities.
- GHCR publication continues through cobycloud/actions/.github/workflows/reusable-ghcr-publish.yml@master.
- The failed v0.1.0-a2 dispatch published neither PyPI nor GHCR artifacts and remains immutable for audit history.
- This is an alpha milestone, not a 1.0.0 compatibility claim.

## Upgrade

Python:

    uv tool install --upgrade portwyrm==0.1.0a3

Container:

    docker pull ghcr.io/groupsum/portwyrm:0.1.0-a3

Deploy the verified OCI digest rather than relying on the tag alone.

## Migration and downtime

No manual schema migration is introduced. Back up /data and /etc/letsencrypt before replacing a running container.

## Rollback

Restore the pre-upgrade data and certificate backup when required, then deploy the previously verified 0.1.0-a1 digest. Do not rewrite published artifacts or immutable tags.

## Post-publication verification

- A clean wheel installation reports 0.1.0a3.
- PyPI exposes wheel and source distribution.
- GHCR exposes 0.1.0-a3 as a signed multi-architecture digest with SBOM and provenance.
- Anonymous pull, Cosign verification, and GitHub attestation verification pass.
- No stable or latest tag is assigned.

