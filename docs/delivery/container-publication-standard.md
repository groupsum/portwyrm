# Container publication standard

Portwyrm publishes one canonical OCI repository: ghcr.io/groupsum/portwyrm. The image digest is the release identity. Tags are navigation aliases, never the security or deployment identity.

## Naming and tags

- A publication is allowed only from a protected vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-PRERELEASE Git tag.
- Human-facing tags are normalized semver MAJOR.MINOR.PATCH, MAJOR.MINOR, and MAJOR. Stable releases additionally receive latest.
- Prereleases never receive latest or stable aliases.
- Branch, arbitrary ref, short SHA, and edge tags are not published channels.
- Deployments and release notes MUST record the full multi-architecture digest, for example ghcr.io/groupsum/portwyrm@sha256:<digest>.
- Existing untagged manifests and legacy aliases are retained until an explicit, separately reviewed registry cleanup; this standard does not silently delete artifacts.

## Required gates

The workflow runs database persistence, protocol, and vulnerability gates before publication. The image is multi-architecture (linux/amd64 and linux/arm64) and carries OCI source, revision, version, and creation metadata.

Each published digest MUST have an SBOM, maximally detailed GitHub Actions build provenance, a keyless Sigstore/Cosign signature bound to the release workflow identity, a successful anonymous pull test, and successful Cosign and GitHub provenance-attestation verification.

Pull requests may build and scan images but MUST NOT publish, sign, attest, or write to GHCR. A failed gate blocks the release job. A rollback changes the deployment reference to a previously verified digest; it does not retag or rewrite an existing release.

## Registry hygiene

The registry is reviewed for tags and untagged manifests after each release. Cleanup of legacy or untagged manifests is an explicit maintenance operation with a manifest inventory, owner check, retention window, and post-delete verification.