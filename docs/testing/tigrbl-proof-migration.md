# Tigrbl proof-surface migration

Status: executable replacement map

The former repository/kernel tests are not retained as tests of rejected abstractions. Their
observable contracts are mapped to table, API, runtime, and container proofs below. A deleted
test file is therefore either replaced by an executable contract or explicitly retired because
the named class must not exist in a downstream Tigrbl application.

| Former proof file | Replacement proof |
|---|---|
| `integration/test_postgresql_restart.py` | live PostgreSQL identity and routing persistence across app reconstruction; MySQL stays gated until its engine package is published |
| `robustness/test_api_security_ui_t2.py` | SSOT T2 identity/UI suites, `runtime/test_ui_assets.py`, `runtime/test_tigrbl_app_runtime.py` |
| `robustness/test_data_operations_distribution_t2.py` | `planned/test_distribution.py`, `planned/test_operations.py`, real container protocol test |
| `runtime/test_compat_api.py` | `runtime/test_tigrbl_app_runtime.py`, npm compatibility SSOT suites, converted `planned/test_npm_wire.py` and `planned/test_npmctl_e2e.py` |
| `runtime/test_composed_product.py` | `runtime/test_tigrbl_app_runtime.py`, `runtime/test_tigrbl_native_composition.py`, real container protocol test |
| `runtime/test_demo_bootstrap.py` | setup/login assertions in `runtime/test_tigrbl_app_runtime.py` and native-router tests |
| `runtime/test_identity.py` | principal, password, session, PAT, RBAC, and MFA lifecycles in `runtime/test_tigrbl_table_stores.py` |
| `runtime/test_kernel_control_plane.py` | retired: `KernelControlPlane` is prohibited; compatibility resources call table operations directly |
| `runtime/test_kernel_mfa_store.py` | retired: `KernelMFAStore` is prohibited; MFA table lifecycle proof replaces it |
| `runtime/test_kernel_token_store.py` | retired: kernel token wrappers are prohibited; `PATStore` lifecycle proof replaces them |
| `runtime/test_kernel_unit_of_work.py` | retired: downstream kernel/UoW wrappers are prohibited; every custom table operation is executed by Tigrbl transaction ownership |
| `runtime/test_operations_distribution.py` | runtime telemetry, audit table, settings table, Docker build, and real protocol proofs |
| `runtime/test_persistence_runtime.py` | engine factory contract, legacy SQLite upgrade, PostgreSQL live restart proof |
| `runtime/test_service.py` | table-backed compatibility CRUD, portability, and audit proofs |
| `runtime/test_tigrbl_native_schema.py` | table inventory, exported table schemas, custom-op aliases, and app composition proofs |

The eleven files under `tests/planned/` are retained by name but no longer skip. They now execute
capability-presence contracts and keep future regressions visible in the normal test run.

## Current backend evidence

On 2026-07-16, `portwyrm:npmctl-current` was run against a disposable PostgreSQL 17
container. An administrator and npmctl-owned proxy host were created, the Portwyrm container
was destroyed and recreated without bootstrap credentials, and the persisted administrator
authenticated successfully with `doctor ok=true` while npmctl reported `drift_count=0`.

The same current image fails closed before MySQL application startup with
`Unknown or unavailable engine kind 'mysql'`. The image contains Tigrbl 0.4.4; the local
`tigrbl_engine_mysql` source requires Tigrbl 0.4.5.dev4 and is not available from the package
index. MySQL/MariaDB restart conformance therefore remains an external engine-publication gate,
not a passing Portwyrm persistence claim.

The real Docker protocol suite passed against the same image for HTTP proxying, WebSocket
upgrade, cache behavior, redirects, dead hosts, TCP, and UDP. A separate cross-instance test
exports a checksummed configuration bundle, previews and restores it into a fresh SQLite
instance, and verifies stable IDs, aggregate references, and npmctl ownership metadata. Bundle
tampering is rejected. Identities and secret-bearing filesystem material are deliberately
excluded; this is configuration portability evidence, not the still-open encrypted full-backup
claim.

## Certificate and privileged configuration evidence

The focused certificate and lifecycle suite passes 22 tests covering custom material,
ACME orchestration and cleanup, provider credential boundaries, canonical CRUD hooks,
global auditing, and administrator-only raw Nginx configuration. The 86-entry DNS provider
catalog no longer implies executable support: the compatibility endpoint reports package
installation and support tier, while DNS-01 fails before invoking Certbot when the selected
plugin is absent.

Raw host and location Nginx directives are an administrator-only parity escape hatch.
Non-admin editors with otherwise sufficient host permissions are rejected by the global
table hook. Administrator changes still use canonical CRUD and the post-commit reconciler;
an invalid candidate leaves the durable desired state visible while the runtime retains its
last-known-good generation and diagnostic attempt.

Live ACME staging issuance, renewal, and DNS-01 issuance remain credentialed external tests:
they require a controlled public domain and provider account. Simulated success, failure,
cleanup, wildcard admission, renewal-window, and material-publication behavior is covered,
but is not described as live issuance evidence.
## Current npmctl lifecycle replay

The fresh 2026-07-19 `portwyrm:npmctl-verify` image passed the real npmctl suite with 7 selected tests passing and 2 deselected. This closes the routing-host deletion/prune foreign-key gap; the canonical evidence artifact is `.ssot/evidence/compat.npmctl/live-replay-2026-07-19.json`. Broader backend and resource-matrix coverage remains a p100 gate.