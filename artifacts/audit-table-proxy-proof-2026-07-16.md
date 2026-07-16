# Audit table and live proxy proof

Date: 2026-07-16

The operator UI audit table now presents `Resource` before `Action` and omits the redundant
`Summary` column. Event summaries remain available to search and inspect through the details
disclosure. The empty state spans the resulting six-column table.

Verified UI evidence:

- The production frontend build and TypeScript check passed.
- Three Playwright accessibility and authentication tests passed.
- `tests/runtime/test_ui_assets.py` passed and enforces the exact column contract.
- The deployed audit table exposed: Time, Actor, Resource, Action, Outcome, Details.
- SSOT test `tst:pytest.experience.operator-ui.audit-columns.t1` is passing and linked
  bidirectionally to the Operator UI T1 feature, claim, and evidence.

The local deployment also uses a deterministic forward-proxy proof. Portwyrm and
`portwyrm-proof-upstream` share `portwyrm-proof-network`. The managed proxy host
`proof.portwyrm.local` targets `http://portwyrm-proof-upstream:9000` and is left enabled.

Verified routing evidence:

- Portwyrm resolved and reached the upstream service by its Docker name with HTTP 200.
- The proxy host was created through the live operator UI and reconciled to generation
  `258180d8`.
- A request to port 38080 with `Host: proof.portwyrm.local` returned HTTP 200.
- The returned body contained the upstream's `Directory listing for /` marker.
- `nginx -t` reported successful syntax and configuration validation.
- The global audit lifecycle recorded successful `proxy_hosts created`, generation record and
  activation, and reconcile-attempt events.
