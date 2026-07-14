# Release train

Status: active
Channels: `edge`, `beta`, `stable`

Portwyrm uses SemVer and trunk development. Stabilization branches are immutable except for
release fixes. `1.0.0` is the p100 MVP. Delivery is governed by the dependency-ordered
[feature slice initiative](../product/delivery-slices.yaml); slices are capability and evidence
gates, not schedule estimates.

| Sequence | Release | Scope and exit gate |
|---|---|
| `S0` | `0.1.x-alpha` | composed CLI, API, no-build UIX, bootstrap, health, memory/SQLite, container baseline |
| `S1` | `0.2.x-alpha` | real proxy/redirect/dead/stream/access-list protocols and safe Nginx reconciliation |
| `S2` | `0.3.x-alpha` | durable passwords, users, permissions, tokens, logout, profiles, permission-aware UIX |
| `S3` | `0.4.x-alpha` | custom certificates, production ACME, DNS providers, TLS attachment, renewal and recovery |
| `S4` | `0.5.x-beta` | complete TOTP enrollment, challenge, recovery, backup-code, UIX, API, and audit flows |
| `S5` | `0.9.x-rc` | p100/NPM/npmctl conformance, all stores, migration, operations, OCI publication and rollback |
| `GA` | `1.0.0` | every in-scope p100 row certified; signed artifacts published; recovery drills passed |

`S0` and `S1` are delivered baselines. `S2` is next. Later slices may be developed on isolated
branches, but they cannot promote ahead of an unmet prerequisite gate.

## Scope dispositions

| Category | Items | Rule |
|---|---|---|
| In scope | NPM parity, npmctl compatibility, requested persistence modes, native CLI/API/UIX and access tokens | Assigned to exactly one of `S0`-`S5` |
| Out of bounds | mTLS; HTTP/3/QUIC; advanced durable preferences beyond the S2 baseline | Valid future ideas, but require an approved boundary change, ADR, spec, feature, tests, and release-plan update |
| Won't do | WebTransport on the current Nginx data plane; Node/npm runtime requirement; copied NPM branding/trade dress | Intentionally excluded; reconsideration requires a superseding architectural or product decision |

Every release follows:

`candidate -> validated -> certified -> promoted -> published -> deployed -> verified -> closed`

Each transition has an owner and linked evidence. Task completion alone never certifies a
release.

## Gates

- Ruff, pytest, type, migration, property, config-golden, API-wire, and security tests.
- E2E across every persistence adapter and frozen NPM profile.
- Real npmctl validate/schema/plan/apply/adopt/drift/audit execution.
- Backup/restore, failed migration, failed reload, renewal, and last-known-good drills.
- OCI vulnerability threshold, SBOM, provenance, and signature verification.
- Isolated canary host/certificate cohort before staged stable rollout.
- Expand/contract schema changes with an N-1 compatibility window and pre-migration backup.

Deployment rollback selects the prior signed image digest and compatible schema. Artifact
revocation is separate. Hotfixes branch from stable, run focused plus security gates,
release a patch version, and merge forward.
