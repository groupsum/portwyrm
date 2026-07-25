# Portwyrm 0.1.0a2 release operations

Status: release candidate
Release date: 2026-07-25
PyPI version: 0.1.0a2
OCI tag: 0.1.0-a2
Git tag: v0.1.0-a2

## Approved release facts

- Unmatched HTTP hosts now default to a silent Nginx 444 response instead of serving the congratulations page.
- The default-site behavior and generated configuration have regression coverage.
- PyPI trusted publishing is delegated to cobycloud/actions/.github/workflows/reusable-pypi-publish.yml@master through the protected pypi environment.
- GHCR publication remains delegated to cobycloud/actions/.github/workflows/reusable-ghcr-publish.yml@master with multi-architecture build, SBOM, provenance, signing, anonymous pull, and verification gates.
- This remains an alpha milestone and is not a 1.0.0 compatibility claim.

## Affected audiences

- Operators receive the secure unmatched-host default on fresh/default configurations.
- Existing operators who explicitly selected another default-site mode retain that configured choice.
- Maintainers receive synchronized package/runtime versions and shared publishing workflows.

## Prerequisites and publication order

1. Verify Ruff, pytest, package build, SSOT validation, container protocols, PostgreSQL restart persistence, and vulnerability scanning.
2. Commit the version and release metadata.
3. Create and push v0.1.0-a2 from the verified commit.
4. Allow the tag-triggered Python and container workflows to publish.
5. Verify PyPI files and hashes, the GHCR multi-architecture digest, SBOM/provenance, Cosign signature, and anonymous pull.

## Upgrade

Python:

    uv tool install --upgrade portwyrm==0.1.0a2

Container:

    docker pull ghcr.io/groupsum/portwyrm:0.1.0-a2

Record and deploy the verified multi-architecture digest rather than relying on the tag alone.

## Migration and downtime

No manual schema migration is introduced by this release. Container replacement may cause the normal brief restart interval. Back up both /data and /etc/letsencrypt before an upgrade because the database alone is not a complete Portwyrm backup.

## Rollback

Rollback means restoring the pre-upgrade data/certificate backup when required and redeploying the previously verified 0.1.0-a1 image digest. Published PyPI files, OCI manifests, signatures, attestations, and tags are immutable release evidence and must not be rewritten.

## Post-publication verification

- python -c "import portwyrm; print(portwyrm.__version__)" prints 0.1.0a2 in a clean environment.
- PyPI exposes both wheel and source distribution for 0.1.0a2.
- GHCR exposes 0.1.0-a2 and resolves to the workflow-recorded multi-architecture digest.
- The image can be pulled anonymously and its Cosign/GitHub provenance identity verifies against the shared GHCR workflow.
- No stable or latest tag is assigned to this prerelease.

## Downstream handoffs

- Product: approve only the secure default-site behavior described above; do not infer full compatibility closure.
- DevRel: update alpha install examples after registry verification and use the immutable OCI digest.
- Technical Marketing and Copywriting: describe this as an alpha security-default correction, not a stable launch.
- Sales and Support: disclose alpha maturity and the changed fresh/default unmatched-host behavior; escalate unexpected routing with redacted configuration evidence.

