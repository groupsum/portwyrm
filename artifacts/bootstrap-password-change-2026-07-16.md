# Bootstrap password-change evidence

Date: 2026-07-16

Portwyrm now exposes one control-plane UI on port 81; ports 80 and 443 remain exclusively the
Nginx data plane. A fresh OCI deployment automatically creates `admin@example.com` with a
deployment-specific one-time password generated at first start. No universal administrator
password is embedded in the image.

The durable `principals.must_change_password` state is returned by authentication and resolved
for every session. Normal security dependencies reject a flagged principal. The browser's thin
password-change endpoint invokes `CredentialStore.change_password`; its Tigrbl post-handler hook
clears the flag in the same transaction. `CredentialStore.set_password` has the inverse hook so an
administrator reset forces the recipient to choose a private password. A global post-commit hook
removes the plaintext bootstrap credential file only after the change commits.

Verified checks:

- Ruff passed for `src` and `tests`.
- Focused lifecycle, application, UI asset, and distribution suite: 15 passed.
- Full Python regression suite: 210 passed and 2 skipped.
- Browser accessibility suite: 2 passed, including the forced-change ceremony and all
  authenticated console surfaces.
- Docker protocol suite: 1 passed against `portwyrm:bootstrap-current`; port 81 served the
  control-plane UI and ports 80 and 443 remained data-plane-only.
- SSOT test `tst:pytest.identity.bootstrap-password-change.t1` is passing and linked to both
  `feat:identity.users-rbac` and `feat:experience.operator-ui` with their T1 claims and evidence.
- SSOT validation passed with no failures or warnings.
- A fresh local deployment became healthy. Its generated administrator authenticated with
  `must_change_password=true`, and a normal control-plane request was rejected with HTTP 403 and
  `password change required`.

The local deployment uses `PORTWYRM_SECURE_COOKIES=0` solely because it is exposed over plain HTTP
on loopback. The image retains secure-cookie defaults for HTTPS deployments.
