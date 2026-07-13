# Release train

Status: proposed  
Channels: `edge`, `beta`, `stable`

Portwyrm uses SemVer and trunk development. Stabilization branches are immutable except for
release fixes. `1.0.0` is the p100 MVP; earlier milestones are pre-release delivery slices.

| Milestone | Scope and exit gate |
|---|---|
| `0.1.0a` | freeze NPM 2.10.4/2.15.1 profiles, npmctl captures, p100 matrix, ADRs |
| `0.2.0a` | auth, proxy CRUD, SQLite, render/test/reload/rollback, minimal UI |
| `0.3.0a` | all host families, WebSockets, cache, access lists, advanced config, streams |
| `0.4.0a` | custom/ACME TLS, provider framework, users, permissions, 2FA, tokens, audit |
| `0.5.0b` | memory/PostgreSQL/filesystem/hybrid, migration, backup/restore, containers |
| `0.9.0rc` | complete UI/import, all profiles, npmctl E2E, runbooks, recovery drills |
| `1.0.0` | every p100 row certified; signed artifacts published; rollback drill passed |

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
