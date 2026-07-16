# Tigrbl proof-surface migration

Status: executable replacement map

The former repository/kernel tests are not retained as tests of rejected abstractions. Their
observable contracts are mapped to table, API, runtime, and container proofs below. A deleted
test file is therefore either replaced by an executable contract or explicitly retired because
the named class must not exist in a downstream Tigrbl application.

| Former proof file | Replacement proof |
|---|---|
| `integration/test_database_backends.py` | `runtime/test_tigrbl_native_composition.py`; live PostgreSQL CRUD/restart evidence; MySQL stays gated until its engine package is published |
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
