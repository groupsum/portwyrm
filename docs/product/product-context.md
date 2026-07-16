# Product context

Status: bootstrap  
Owner: Groupsum  
Review date: 2026-07-13

## Outcome

Portwyrm replaces Nginx Proxy Manager with a self-hosted Python control plane whose built-in UI
is the operator interface, a separate Nginx data plane, and a published OCI image. It must
support a zero-touch npmctl cutover while providing a cleaner native API and extensible
persistence architecture.

The first MVP is the generally available `1.0.0`. Its boundary is p100 of the frozen NPM
compatibility profiles and the additional capabilities explicitly requested by Groupsum.
Pre-releases are implementation milestones, not reduced MVPs. The authoritative sequencing,
exit gates, and OOB/won't-do dispositions are in the
[feature slice initiative](delivery-slices.yaml).

## Primary actors and jobs

| Actor | Job |
|---|---|
| Platform admin | Operate hosts, certificates, identities, settings, health, and recovery |
| Scoped operator | Manage or view only authorized resource families and owned resources |
| npmctl automation | Reconcile desired proxy state through an NPM-compatible API |
| Service account | Use revocable, scoped native tokens without a human password |
| Auditor | Inspect immutable, redacted activity and release evidence |

## Product domains

| Domain | Authority and invariant |
|---|---|
| Identity and authorization | Users, admins, sessions, 2FA, roles, permissions, and tokens |
| Host inventory | Proxy, redirection, dead, and stream desired state with stable IDs |
| Access policy | Data-plane access lists; distinct from control-plane RBAC |
| Certificates | ACME/custom certificate lifecycle and protected secret material |
| Runtime reconciliation | Deterministic render, `nginx -t`, atomic activation, reload, rollback |
| Persistence | Backend-neutral repositories, UoW, blobs, secrets, leases, journal, and outbox |
| Compatibility | Versioned NPM wire profiles and error/default quirks |
| Audit and settings | Redacted event history, system configuration, reports, and health |
| Migration and operations | Import/export, backup/restore, upgrade, container, and recovery |

## Frozen baseline

- npmctl's current facade contract is the initial non-negotiable consumer contract.
- Named NPM conformance profiles: `2.10.4` for npmctl and `2.15.1` for the current upstream
  source snapshot inspected on 2026-07-13.
- Observable compatibility means routes, methods, status codes, DTOs, defaults, nullability,
  auth, permissions, errors, and side effects—not copied branding or trade dress.
- New upstream behavior discovered after profile freeze is triaged into the next profile; it
  does not silently mutate an already certified contract.

## Facts, assumptions, and evidence gaps

Facts are sourced in the feature matrix and compatibility contract. The architecture assumes
a single-node Docker deployment is the default and PostgreSQL enables an HA control plane.
The full DNS-01 provider catalog, every upstream UI-only behavior, migration fidelity against
real NPM databases, and wire-level differences between NPM versions remain evidence gates.

No tail exclusions are permitted for `1.0.0`: every discovered baseline capability must be
implemented, explicitly ruled outside the frozen envelope with approval, or block GA. mTLS,
HTTP/3/QUIC, and advanced preferences are currently out of bounds. WebTransport on the selected
Nginx data plane, a Node/npm runtime requirement, and copied NPM identity are explicitly won't-do.
