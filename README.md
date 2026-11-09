# Portwyrm

Portwyrm is a self-hosted reverse proxy control plane with a built-in web UI, designed to
replace Nginx Proxy Manager while remaining compatible with npmctl's current API contract.

The `1.0.0` MVP target is literal p100 coverage of the frozen compatibility envelope. Early
alpha, beta, and release-candidate versions are milestones toward that target, not claims of
partial MVP completion.

## Status

The frozen S0-S5 runtime scope is under active implementation on `master`: composed Python
CLI/API/UIX, deterministic Nginx protocols, durable identity and MFA, certificate lifecycle,
portable configuration, NPM migration, npmctl-compatible plan/apply/drift/audit behavior, and live
PostgreSQL restart persistence have executable coverage. External ACME and MySQL restart
conformance remain fail-closed release gates; implementation does not imply a published `1.0.0`.

## Development

```shell
uv sync --dev
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv run ssot-registry validate . --write-report
```

### UI accessibility tests

From the repository root, set up the Python development environment, then install
and build the frontend from `frontend/`:

```shell
uv sync --dev --locked
cd frontend
npm ci
npm run build
npx playwright install chromium
npm run test:a11y
```

Use Node.js 22 as in CI. On Linux, use `npx playwright install --with-deps chromium`
if Chromium's system dependencies are missing. Set `PORTWYRM_BROWSER_PATH` to
use a specific Chromium or Chrome executable. Without an override, Windows uses
`C:\Program Files\Google\Chrome\Application\chrome.exe`, and other platforms use
Playwright's Chromium.

Playwright starts a local Portwyrm instance on `127.0.0.1:18182` with a separate
SQLite database and test data under `.a11y-runtime`.

### Local control plane

Start the server, then open `http://localhost:81/ui/`:

```shell
uv run portwyrm --host 127.0.0.1 --port 81
```

The container exposes two deliberately separate network surfaces:

- port `81` is the control plane: its built-in UI lives at `/ui/`, alongside the administration
  APIs and health endpoints;
- ports `80` and `443` are the Nginx data plane for configured proxy traffic and do not serve a
  second administration UI.

Check the control plane on port `81`:

```shell
curl --fail --silent --show-error http://127.0.0.1:81/health/live
curl --fail --silent --show-error http://127.0.0.1:81/health/ready
```

Liveness reports that the API is responding and does not query the database.
Readiness reads the settings collection and reports the database backend on
success. If the settings read raises an unexpected error, readiness returns
HTTP 500 with an error detail.

On a fresh container data volume, Portwyrm creates the initial superuser as
`admin@example.com` with a deployment-specific one-time password. Read that password from the
first-start container log. The account cannot access control-plane resources until the UI's
mandatory password-change ceremony succeeds. The plaintext bootstrap file is removed after the
change commits. Set `PORTWYRM_INITIAL_ADMIN_EMAIL` and `PORTWYRM_INITIAL_ADMIN_PASSWORD` to supply
your own bootstrap credentials; automatic bootstrap credentials are never embedded in the image.

The same package includes an operator CLI. It speaks the npmctl-compatible API, accepts a
token through `--token` or `PORTWYRM_TOKEN`, and prints stable JSON for automation:

```shell
uv run portwyrm setup --email admin@example.com --password 'change-me-now'
uv run portwyrm login --email admin@example.com --password 'change-me-now'
uv run portwyrm status
uv run portwyrm list proxy-hosts --token "$PORTWYRM_TOKEN"
uv run portwyrm create proxy-hosts --token "$PORTWYRM_TOKEN" --data proxy-host.json
```

`serve`, `status`, `schema`, `setup`, `login`, `list`, `get`, `create`, `update`, `delete`,
`export`, `import`, `npm-preflight`, and `npm-import` are available without Node.js or npm.

The UI is packaged as standards-based browser assets. Node.js and npm are not required to
build, install, deploy, or operate Portwyrm.

## Preview an Nginx Proxy Manager migration

Save this example as `npm-tables.json`. The keys are NPM table names and each
value is an array of rows.

```json
{
  "proxy_host": [
    {
      "id": 7,
      "domain_names": "[\"app.example.test\"]",
      "forward_scheme": "http",
      "forward_host": "upstream.example.test",
      "forward_port": 8080,
      "enabled": 1
    }
  ]
}
```

With a Portwyrm administrator token set in `PORTWYRM_TOKEN`, run preflight to
validate and normalize the source rows and report any quarantined records.
Then run the import preview to see what would be created, replaced, left
unchanged, or quarantined. Routing hosts keep their source integer IDs.
Preview and apply quarantine conflicting routing hosts, including hostnames
already assigned to a different ID. Replaying an unchanged routing host
reports it as unchanged. Preflight and preview leave the target unchanged.

```shell
uv run portwyrm npm-preflight --data npm-tables.json
uv run portwyrm npm-import --data npm-tables.json
```

Review the preview before writing to the target with `--apply`.

```shell
uv run portwyrm npm-import --data npm-tables.json --apply
```

## Compatibility principles

- Preserve the NPM-shaped `/api` surface used by npmctl.
- Keep compatibility DTOs separate from native domain models.
- Preserve IDs and npmctl owner metadata during import and round trips.
- Compile deterministic Nginx generations, validate them, activate atomically, and retain a
  last-known-good rollback target.
- Use Tigrbl engines for memory, SQLite, and PostgreSQL metadata. MySQL/MariaDB requires the
  separately published synchronous `tigrbl_engine_mysql` plugin; filesystem/object
  storage holds certificate and immutable generated-config artifacts
  with explicit consistency and high-availability boundaries.

## Deliberate boundaries

- mTLS and HTTP/3 termination remain out of the frozen NPM-compatible `1.0.0` scope.
- WebTransport termination is not provided by Nginx. The optional QUIC gateway performs opaque hostname routing and leaves TLS/QUIC/WebTransport termination to the backend.
- Portwyrm never requires Node.js or npm to install, build, deploy, or operate.

Licensed under Apache-2.0.

## Opaque QUIC hostname passthrough

`compose.quic-gateway.yaml` runs Portwyrm as the sole host UDP/443 publisher while Nginx Proxy Manager continues to own TCP/443. The gateway decrypts only the QUIC Initial metadata needed to read SNI and ALPN, chooses an enabled `quic_passthrough_host`, and forwards every datagram without terminating TLS. The backend therefore presents its own certificate and owns the HTTP/3/WebTransport session.

The native API exposes authenticated capability discovery at `/api/v2/capabilities` and owner-scoped CRUD at `/api/v2/quic-passthrough-hosts`. Wyrmctl is the supported declarative controller for these resources. Unknown SNI, unsupported ALPN, malformed Initial packets, and direct-IP traffic have no route. Application Compose stacks expose container UDP ports only; they never publish host UDP ports.

The gateway requests an 8 MiB UDP receive queue by default and logs both the requested and effective kernel values at startup. Set `PORTWYRM_QUIC_RCVBUF_BYTES` to tune the request between 64 KiB and 128 MiB. Set `PORTWYRM_QUIC_WORKERS` from 1 to 32; values above 1 use Linux `SO_REUSEPORT` to distribute independent QUIC flows across worker processes. Route-file checks run once per second outside the packet-forwarding path, so media traffic cannot turn configuration polling into per-datagram filesystem work.
