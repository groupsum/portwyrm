# Deliverable and artifact set

Every planning and release artifact carries a stable ID, version, owner, status, review date,
sources, separated facts/assumptions/inferences, dependencies, risks, metrics, acceptance
criteria, and links to tests and evidence.

## Product and design

- product context and domain map
- p100 feature matrix and frozen compatibility envelope
- npmctl contract and wire fixtures
- architecture, persistence, security, and UI specifications
- migration and cutover plan
- decision records for compatibility, control/data plane, persistence ports, atomic Nginx
  generations, auth/tokens, and container topology

## Implementation and proof

- compatibility OpenAPI profiles for NPM 2.10.4 and 2.15.1
- native OpenAPI and export-bundle schema
- API wire and error fixtures
- deterministic Nginx golden configurations
- contract, persistence, migration, container, security, UI, and npmctl E2E tests
- raw test output, machine-readable summaries, and SSOT-linked evidence

## Operations and distribution

- OCI image and Compose examples for SQLite, PostgreSQL, filesystem, hybrid, and demo modes
- PyPI package plus reserved npm/crates coordinates where useful for ecosystem integrations
- installation, configuration, backup/restore, upgrade, import, renewal, rollback, and
  incident runbooks
- amd64/arm64 manifest, SBOM, provenance, vulnerability report, signatures, and checksums
- release notes, compatibility report, migration report, and known-exception register

The `1.0.0` release artifact freezes exact features, profiles, image digests, schema range,
gates, rollout/rollback, exceptions, claims, tests, evidence, and metrics.
