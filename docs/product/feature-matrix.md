# Portwyrm p100 feature matrix — Nginx Proxy Manager 2.15.1 baseline

Observed: **2026-07-13** (America/Chicago)  
Upstream snapshot: `NginxProxyManager/nginx-proxy-manager` `master` at commit [`76f09db610cfcaecf6d608a8947d6f75aa028870`](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/76f09db610cfcaecf6d608a8947d6f75aa028870), repository version `2.15.1`; commit date 2026-06-03.  
Research method: official website, official repository source, schemas, migrations, Nginx templates, UI, tests/release metadata. Facts below are direct unless explicitly marked **Inference**, **Gap**, or **Extension**.

## Scope and product boundary

Nginx Proxy Manager (NPM) is a self-hosted reverse-proxy control plane and UI packaged with Nginx/OpenResty and Certbot. Its authoritative metadata is in SQLite, MySQL/MariaDB, or PostgreSQL, while generated Nginx configuration, JWT keys, logs, custom certificates, and ACME material live on mounted filesystems. NPM is therefore already a **DB + filesystem hybrid**, but does not expose an in-memory or file-only metadata backend. [S1][S4][S8]

For replacement work, **p100 parity** should mean: every confirmed behavior in the matrix is implemented, contract-tested, and migration-tested against NPM 2.15.1. Requested capabilities that NPM does not have (revocable personal access tokens, in-memory metadata, file-only metadata, richer RBAC) are tracked as extensions and must not weaken NPM compatibility.

## Feature and capability matrix

Legend: `P` = direct NPM parity; `E` = requested extension beyond NPM; `C` = compatibility/migration obligation.

| ID | Type | Domain | NPM 2.15.1 observed behavior | p100 acceptance target | Evidence |
|---|---|---|---|---|---|
| ID-01 | P | First run | Setup wizard creates the first active user; unauthenticated user creation is allowed only while no active user exists, and the first user is forced admin. Optional `INITIAL_ADMIN_EMAIL`/`INITIAL_ADMIN_PASSWORD` skips the wizard. | Fresh install has exactly these two bootstrap paths; post-bootstrap unauthenticated creation is denied. | [S4][S6] |
| ID-02 | P | Users | User CRUD supports email, name, nickname, Gravatar-derived avatar, admin role, disabled flag, soft deletion, password setting, and self profile edits. A user cannot delete self. | UI/API and state transitions match; disabled/deleted users cannot authenticate. | [S6][S10] |
| ID-03 | P | Roles | Roles are effectively `admin` and implicit `user`; admin bypasses section permissions and can manage users, settings, audit logs, and impersonation. | Admin/user semantics and privilege checks are contract-tested. | [S6][S7] |
| ID-04 | P | Permissions | Per-user sections: proxy hosts, redirection hosts, 404/dead hosts, streams, access lists, certificates. Each is `hidden`, `view`, or `manage`. | All six section gates apply consistently in UI and API. `hidden` cannot list/get; `view` cannot mutate; `manage` can CRUD/toggle. | [S7] |
| ID-05 | P | Visibility | Per-user visibility is `user` (owned objects) or `all`; applies to hosts, streams, access lists, certificates, and dashboard counts. | Ownership filters cannot be bypassed by object ID, expansion, search, toggle, or mutation. | [S7][S10] |
| ID-06 | P | Admin-only | User list/create/delete/permission changes/login-as, settings, and audit log are admin-only. | Negative tests prove ordinary users cannot reach these operations or UI routes. | [S7][S10] |
| ID-07 | P | Impersonation | Admin can “login as” another active user and receives a one-day user-scoped JWT plus user payload. | Impersonated token has target permissions/visibility and no inherited admin privilege. | [S6] |
| ID-08 | P | Password auth | Email/password login; emails normalized lower-case/trimmed; password secrets bcrypt-hashed (cost 13 on writes); current password required for self password change, while admins can reset another user. | Existing imported bcrypt hashes authenticate; password lifecycle and duplicate-email checks match. | [S6][S10] |
| ID-09 | P | JWT sessions | RS256 JWTs with generated persisted key pair at `/data/keys.json`, `jti`, issuer, scopes, user id, and configurable duration syntax; default one day. Bearer auth protects API. | Accept NPM-compatible bearer flow and expiry; preserve signing keys only when explicit token continuity is requested. | [S5][S6] |
| ID-10 | P | Token refresh/scopes | Authenticated `GET /tokens` refreshes a token; admins may request another scope. Tokens are stateless and no persisted token registry/revocation endpoint exists. | Compatibility endpoint behaves the same; document lack of NPM token revocation. | [S5][S6] |
| ID-11 | E | Access tokens | NPM has no named, revocable, hashed personal/service access tokens with scopes, rotation, last-used data, or expiry policy. | Add PAT/service-token CRUD, one-time reveal, hash-at-rest, fine scopes, expiry, revoke/rotate, last-used/audit, and admin policy without changing JWT compatibility. | **Gap**, [S5][S6] |
| ID-12 | P | 2FA | TOTP setup/status/enable/disable, five-minute challenge JWT, eight one-use backup codes stored bcrypt-hashed, backup-code regeneration, and login verification. | Full setup/login/recovery lifecycle, one-use enforcement, and secret non-disclosure after setup. | [S6] |
| PH-01 | P | Proxy host CRUD | Create/list/get/update/soft-delete and explicit enable/disable. Each row has owner, timestamps, domains, enabled flag, and Nginx online/error metadata. | API, UI, ownership, audit, toggle idempotency/error semantics, and generated state match. | [S2][S10] |
| PH-02 | P | Domains | 1–100 unique domain names; wildcard accepted in host UI; domain cannot be active in another proxy, redirection, or dead host (case-insensitive). | Duplicate/cross-type collision tests; preserve all domains and order on import. | [S2][S11] |
| PH-03 | P | Upstream | Forward scheme `http`/`https`, host (DNS/IP/string), and port 1–65535. Default proxy passes original request URI and standard Host/X-Forwarded/Real-IP headers. | Generated Nginx behavior verified with HTTP echo upstreams. | [S2][S9] |
| PH-04 | P | WebSockets | Optional upgrade sets `Upgrade`, `Connection`, and proxy HTTP/1.1 at server/default/custom-location contexts. | Real WebSocket handshake and bidirectional traffic pass when enabled and fail/behave normally when disabled. | [S2][S9] |
| PH-05 | P | Asset cache | Optional extension-based cache for css/js/images/fonts/maps/ico; public cache keyed by host+URI, normal responses 30m, 404 1m, stale on selected errors, 5s connect/45s read, headers stripped, client expiry 30m. It is not general full-response caching. | Exact static-asset matching, cache key/status, TTL, stale, header, and non-asset bypass behavior tested. | [S9] |
| PH-06 | P | Block exploits | Optional include of NPM’s block-exploits rules. | Maintain a versioned equivalent rule file and golden request tests for every directive/pattern. | [S9] |
| PH-07 | P | Access list binding | A proxy host may bind one access list by id; no list means unrestricted at this layer. | Authorization and IP-policy composition matches for default and custom locations. | [S2][S9] |
| PH-08 | P | Custom locations | Zero or more path routes, each with path, scheme, host, port, optional forwarded path parsed from host, and per-location raw Nginx config. A `/` custom location suppresses generated default location. | Multiple locations, `/` override, path forwarding, SSL/access/cache/exploit/WebSocket inheritance, and advanced config tested. | [S2][S9][S11] |
| PH-09 | P | Advanced config | Raw Nginx server-level configuration with syntax highlighting; if it contains a `location /` block, generated default location is suppressed. | Preserve exact text; invalid config makes host offline rather than poisoning global Nginx. | [S9][S11] |
| PH-10 | P | SSL options | Select existing certificate or request new; force SSL, HTTP/2, HSTS, include subdomains. Proxy hosts also have `trust_forwarded_proto` when force SSL is active. Invalid combinations are normalized off. | Field dependency rules and generated redirects/listeners/headers match. | [S2][S11] |
| PH-11 | P | Safe apply | Nginx config is tested before and after generation; invalid new config records `nginx_online=false` and error text, removes active config, retains `.err` debug artifact, and reloads only valid aggregate config. | Atomic/safe apply under syntax errors, port conflicts, missing certs, and concurrent edits; no unrelated host outage. | [S11] |
| RH-01 | P | Redirection hosts | CRUD/toggle/ownership/audit; source domains redirect to target domain using `auto` (incoming scheme), `http`, or `https`; preserve-path option. | Browser and raw HTTP tests for query/path preservation and scheme behavior. | [S2][S9] |
| RH-02 | P | Status codes | UI offers 300, 301, 302, 303, 307, 308; schema accepts integer 300–308. | API preserves accepted codes; UI offers NPM choices; semantics contract-tested. | [S2][S11] |
| RH-03 | P | Redirect security | Certificate/force SSL/HTTP2/HSTS/subdomains, block exploits, and raw advanced Nginx config. | Same dependency normalization and safe-apply behavior as proxy hosts. | [S2][S9] |
| DH-01 | P | 404/dead hosts | CRUD/toggle/ownership/audit for one or more domains; returns 404; supports certificate, force SSL, HTTP2, HSTS/subdomains, and raw advanced config. | HTTP/HTTPS response and certificate behavior match. | [S2][S9] |
| ST-01 | P | Streams | CRUD/toggle/ownership/audit; incoming port 1–65535, forwarding host and port, TCP and/or UDP flags. Stream ports must be separately published from the container. | TCP, UDP, dual-protocol, IPv4/IPv6/DNS upstream, enable/disable, and exposed-port tests. | [S2][S4][S9] |
| ST-02 | P | Stream TLS | Optional certificate enables TLS termination for TCP streams; UDP has no TLS certificate behavior. | TLS handshake/certificate and plain backend forwarding verified; certificate association preserved on import. | [S2][S9] |
| AL-01 | P | Access list CRUD | Named, owned access lists with ordered Basic Auth entries and ordered IP clients; list includes proxy-host usage count. | CRUD, ordering, ownership, usage count, and regeneration of every bound proxy host. | [S3][S10] |
| AL-02 | P | Basic Auth | Multiple username/password entries rendered to per-list htpasswd file. | Imported credentials remain usable; passwords never returned in clear text after creation. | [S3][S9] |
| AL-03 | P | IP policy | Ordered `allow`/`deny` IPv4, IPv6/CIDR, or `all`; generated policy ends with `deny all` when clients exist. | Boundary/IP-family/order tests from real source addresses. | [S3][S9] |
| AL-04 | P | Composition | `satisfy_any=true` means auth OR IP policy; false means both. `pass_auth=false` strips Authorization before upstream; true preserves it. | Four-way auth/IP truth table and upstream header tests. | [S3][S9] |
| CE-01 | P | Custom certs | Create named custom certificate record, upload certificate, private key, optional intermediate; OpenSSL validation extracts CN, dates, verifies key, rejects expired/mismatch; files at `/data/custom_ssl/npm-{id}`. | PEM upload/replace validation, chain assembly, expiry/domain metadata, permissions, and safe storage. | [S3][S12] |
| CE-02 | P | ACME HTTP-01 | Request Let’s Encrypt certificates for up to 100 domains using HTTP challenge; temporary Nginx challenge config; connectivity test endpoint; staging/server override. | Issue against test ACME, clean temporary config on success/failure, and restore affected hosts. | [S3][S12] |
| CE-03 | P | ACME DNS-01 | DNS challenge with provider, credentials text, propagation seconds (UI max 7200), RSA or ECDSA key type; wildcard supported via DNS. | Provider contract, secret handling, wildcard issuance, propagation control, and key algorithm tests. | [S3][S11][S12] |
| CE-04 | P | DNS providers | Current source catalog has 86 Certbot DNS provider definitions, installed on demand. Official docs warn plugins may conflict and multiple providers in one instance can cause Python dependency conflicts. | Freeze catalog/version snapshot; test plugin installation in isolated environments; surface provider failures without breaking proxy service. | [S12][S13] |
| CE-05 | P | Lifecycle | List/get with expiry and ownership; manual renew (Let’s Encrypt only); automatic renewal when within 30 days; download Let’s Encrypt material as zip; delete/soft-delete; host relations across proxy/redirection/dead/stream. | Timer and manual renewal tests, relation/in-use behavior, audit, regenerated referencing configs. | [S3][S12] |
| CE-06 | P | Secret redaction | Host expansions clear certificate `meta`; certificate operations remain permission/visibility gated. | DNS credentials, PEM private keys, TOTP secrets, hashes, and JWT private key never leak through ordinary list/get/audit/error responses. | [S7][S10][S12] |
| NG-01 | P | Global custom Nginx | Optional includes at root/http/events/stream and every proxy/redirect/stream TCP/stream UDP/dead server block under `/data/nginx/custom`. | Every documented include point loads, survives regeneration, and causes safe diagnostic failure if invalid. | [S8] |
| NG-02 | P | Default site | Unknown Host behavior: congratulations page, 404, Nginx 444, redirect, or custom HTML. Admin-only setting. | All five modes, redirect destination, custom HTML persistence, and safe reload. | [S8][S10] |
| NG-03 | P | IPv6/resolver | IPv6 enabled unless `DISABLE_IPV6`; resolver can be suppressed with `DISABLE_RESOLVER`; generated configs respect flags. | Startup and generated listener/resolver tests in IPv4-only and dual-stack environments. | [S8] |
| NG-04 | P | Trusted proxy ranges | Fetch CloudFront and Cloudflare IPv4/IPv6 at startup and every six hours unless `IP_RANGES_FETCH_ENABLED=false`; startup continues on fetch failure. | Deterministic cached/offline behavior and nonfatal failures; generated real-IP ranges equivalent. | [S8][S11] |
| LG-01 | P | Traffic logs | Per-object access/error logs for proxy, redirection, dead, and stream hosts; proxy log includes upstream cache/status details. | Stable file naming, structured-equivalent content, and correlation to object id. | [S9] |
| LG-02 | P | Rotation | Logrotate runs at startup and every two days; access and error logs rotate weekly, retain 4 and 10 respectively, compress, and signal Nginx. Mount can override config. | Rotation/retention/compression/reopen test and custom-config mount. | [S8][S11] |
| AU-01 | P | Audit | Admin-only audit event list/get; events store actor, object type/id, action, timestamp, metadata; expandable user; searchable UI/API surface. | Create/update/delete/toggle/password/permission/cert actions emit redacted, immutable events. | [S3][S6][S10] |
| UI-01 | P | Surfaces | Setup, login/2FA, dashboard counts, proxy/redirection/stream/dead tables, access lists, certificates, users, audit log, settings, profile/password/2FA. | Responsive UI exposes every permitted operation and hides disallowed sections/actions. | [S14] |
| UI-02 | P | UX | React/Tabler interface, light/dark theme, sortable tables, search, modals, validation/errors, code syntax highlighting, locale picker and many bundled translations. | Accessibility baseline, mobile/desktop layouts, theme persistence, full keyboard forms, localization extraction/fallback. | [S14][S15] |
| UI-03 | E | Native CLI | Installed `portwyrm` command provides serve, setup, login, status, schema, and JSON CRUD for every compatible resource collection. | Installed-wheel and container smoke tests prove command routing, authentication, stable JSON, error exits, and API/UI/runtime composition without Node.js. | **Portwyrm extension** |
| API-01 | P | API surface | Official OpenAPI 3.1 schema served at `/api/schema`; health/setup/version at `/api`; 68 documented GET/POST/PUT/DELETE method/path operations covering tokens, users/2FA, audit, reports, settings, all hosts, access lists, and certificates. | Publish schema; every NPM operation has a contract test and compatible status/body/error shape where npmctl depends on it. | [S5] |
| API-02 | P | Collections | Collection endpoints support optional `query` search and `expand` relationships where implemented; current routes return full arrays and do not use the present but unused pagination middleware. | Preserve existing NPM/npmctl calls; add versioned pagination only as a nonbreaking extension. | [S5][S10] |
| API-03 | P | Transport | Gzip, strict routes, CORS middleware, no-store API headers, XSS/content-type/frame headers; `X_FRAME_OPTIONS` configurable. | Security-header/CORS compatibility tests and production-safe errors. | [S8][S10] |
| DP-01 | P | Docker | Official all-in-one container exposes 80, 81, 443; `/data` volume plus `/etc/letsencrypt` mount in compose; s6 manages processes. Public image tags include `latest`, `2`, and version. | Reproducible multi-arch image, health check, non-root option, immutable version tags, SBOM/signing, and upgrade test. | [S1][S4][S16] |
| DP-02 | P | Architectures | Current docs support amd64 and arm64; armv7 stopped at 2.13.7. | Publish amd64/arm64 manifests and smoke-test both. | [S4] |
| DP-03 | P | Runtime identity | `PUID`/`PGID` may run services as another user/group and chown data/cert folders; low-port permission failures are documented. | Root and configured uid/gid startup, ownership, bind-port diagnostics. | [S8] |
| PS-01 | P | SQLite | Default DB is `better-sqlite3` at `/data/database.sqlite`; `DB_SQLITE_FILE` overrides. | SQLite is zero-config default; migrations, backup/restore, concurrency limits documented/tested. | [S4] |
| PS-02 | P | MySQL/MariaDB | External DB via `DB_MYSQL_*`; takes precedence over SQLite; optional TLS validation/identity controls. | Same deployment contract and migration tests, including secrets-as-files if compatibility requires it. | [S4] |
| PS-03 | P | PostgreSQL | External DB via `DB_POSTGRES_*`; custom schema unsupported upstream (`public`). | PostgreSQL parity, transactional migrations, and documented volume/upgrade path. | [S4] |
| PS-04 | P | Filesystem half | `/data` contains JWT keys, generated configs, logs, htpasswd, custom SSL; `/etc/letsencrypt` contains ACME state/credentials. DB alone is not a complete backup. | Backup/export is consistent across DB + files; restore validates paths, permissions, and referential integrity. | [S4][S8][S12] |
| PS-05 | E | In-memory | NPM has no in-memory metadata backend. | Use the ephemeral Tigrbl memory engine for tests/demo with a clear non-persistence warning and the same table-operation contract. | **Gap**, [S4] |
| PS-06 | E | File-only | NPM has no file-only metadata store beyond generated/runtime artifacts. | Support checksummed export/import snapshots for portability and recovery; do not create a second writable metadata authority. | **Gap**, [S4] |
| PS-07 | E | Hybrid | NPM’s native hybrid is DB metadata + filesystem runtime material; it does not offer configurable per-domain placement. | Define supported hybrid profiles explicitly; never allow two writable authorities for the same entity. | **Inference/extension**, [S4][S8] |
| OP-01 | P | Upgrades | Startup runs ordered DB migrations; official upgrade is image pull/recreate; release-specific notes may apply. | Forward-only, idempotent migrations; backup gate; rollback image/data procedure; compatibility across all supported stores. | [S4][S17] |
| OP-02 | P | Versioning | Health returns semantic version; version-check endpoint queries current release with a short cache. Latest stable alone receives security updates. | Health/readiness/version endpoints and explicit support policy. | [S5][S16] |
| OP-03 | E | Live runtime status | NPM does not define Portwyrm's authenticated live data-plane telemetry or content-addressed configuration generations. | A loopback-only Nginx status source feeds authenticated active/reading/writing/waiting counters; unavailable telemetry is shown as unavailable rather than zero. The control plane reports and the UI exposes the full active immutable generation hash. | **Portwyrm extension** |
| ED-01 | P | Domain collision | Same hostname cannot coexist across proxy/redirection/dead types; stream ports are a separate namespace. | Case-insensitive exact-name collision tests and clear errors. | [S11] |
| ED-02 | P | State normalization | No cert disables force SSL/HTTP2; no force SSL disables HSTS; no HSTS disables HSTS subdomains. | Normalize server-side regardless of client. | [S11] |
| ED-03 | P | Invalid Nginx | A bad host config is marked offline and removed from active config; `.err` and diagnostic metadata remain. | Never reload invalid aggregate config or take unrelated routes down. | [S11] |
| ED-04 | P | ACME disruption | HTTP-01 issuance temporarily manipulates configs for hosts using requested domains and must restore them on both success and failure. | Fault-injection proves restoration and no orphan challenge files. | [S12] |
| ED-05 | P | DNS plugin conflict | Multiple DNS plugins can have incompatible Python dependencies; availability in catalog does not prove issuance works. | Isolate plugins or provide deterministic conflict diagnostics; CI installs every supported plugin and selected providers perform issuance tests. | [S13] |
| ED-06 | P | Offline startup | IP-range fetch can be disabled and failure is nonfatal; ACME and remote version naturally require network. | Existing proxy service starts and routes without external control-plane network. | [S8][S11] |

## Compatibility API inventory

The replacement should initially mount a compatibility API under `/api` with the NPM operation set, then expose richer native APIs separately/versioned. The observed operation groups are:

- Health/schema/version: health/setup/version, OpenAPI schema, version check.
- Authentication/users: login, JWT refresh, 2FA challenge; user CRUD; password, permissions, impersonation; TOTP setup/status/enable/disable/backup codes.
- Control-plane objects: proxy hosts, redirection hosts, dead hosts, streams — list/create/get/update/delete/enable/disable.
- Security: access-list CRUD; certificate list/create/get/delete/upload/renew/download; DNS-provider list, certificate validation, HTTP challenge test.
- Operations: host-count report, settings list/get/update, audit list/get.

Exact method/path inventory is in [S5]. Compatibility must be driven by recorded npmctl traffic and contract fixtures, because a source-visible endpoint is not proof that npmctl currently uses it.

## Migration contract

1. **Discovery/read-only preflight:** detect NPM version, DB engine, schema, mounts, active records, soft-deleted records, referenced files, custom includes, port publications, permissions, and available disk. Produce a redacted report and deterministic migration id.
2. **Supported inputs:** direct SQLite file; MySQL/MariaDB connection; PostgreSQL connection; optional live NPM API for nonsecret entities; `/data` and `/etc/letsencrypt` filesystem roots. API-only import cannot recover password hashes, private key material, raw certificate/DNS credentials, htpasswd state, or global custom snippets.
3. **Entity order:** users → password/TOTP auth → permissions → certificates/files → access lists/auth/clients → proxy/redirection/dead/stream hosts → settings → audit history (optional) → generated config. Preserve legacy ids in `source_id` mapping, not necessarily native primary keys.
4. **Secret handling:** import bcrypt password hashes without rehashing; import TOTP secret/hashed backup codes if policy allows; import custom private keys, ACME account/live/archive/renewal material, DNS credentials, and JWT key pair only when explicitly requested. Never write secrets to reports/logs.
5. **Referential integrity:** every owner, access-list, and certificate reference must resolve; missing references become blocking errors or explicit quarantined records, never silent `0` coercions.
6. **Behavioral validation:** render each object in an isolated Nginx config tree; run config test; run domain collision and port checks; validate cert/key pairs and expiry; compare source/target canonical object snapshots.
7. **Cutover:** quiesce NPM writes, take consistent DB+filesystem backup, repeat delta import, bind replacement to alternate ports, run HTTP/HTTPS/WebSocket/TCP/UDP probes, then switch published ports atomically.
8. **Rollback:** retain untouched NPM DB/files/image and original port mapping; rollback is a routing/container switch, not a reverse migration.
9. **Post-cutover:** renewal dry run/test ACME, log rotation, access control truth table, admin/user sessions, npmctl read/write smoke suite, and backup/restore rehearsal.

## Suggested p100 acceptance gates

1. **Traceability:** every `P` matrix row maps to at least one automated test and source link; no unresolved `missing` evidence is counted complete.
2. **Golden config parity:** canonical fixtures for every host/access/certificate option render semantically equivalent Nginx behavior; raw custom snippets remain byte-preserved.
3. **Protocol suite:** HTTP/1.1, HTTPS, HTTP/2, WebSocket, TCP, UDP, stream TLS, redirects, 404, cache hit/miss/stale, and auth/IP combinations run in containers.
4. **RBAC matrix:** admin and every `hidden/view/manage × user/all` combination tested through both UI and direct API, including guessed ids.
5. **Authentication:** bcrypt import, password reset/change, disabled/deleted users, JWT login/refresh/expiry/scope, impersonation, TOTP and one-use backup codes.
6. **Certificate suite:** custom PEM validation, HTTP-01 and DNS-01 against test ACME, wildcard/RSA/ECDSA, auto/manual renew, download, deletion/in-use, restore after injected failures.
7. **Engine contract:** identical table-operation conformance on SQLite and PostgreSQL at minimum; MySQL/MariaDB when its Tigrbl engine package is installed; memory is an ephemeral extension and file-only is a portable artifact profile.
8. **Crash consistency:** kill processes during DB commit, config write, Nginx test/reload, certificate issue, and migration; target recovers without split authority or unrelated outage.
9. **Migration fixtures:** sanitized NPM 2.13.x, 2.14.x, and 2.15.1 snapshots for each DB, including custom locations, all host types, 2FA, access lists, certificates, invalid configs, and soft deletes.
10. **npmctl compatibility:** replay captured current npmctl calls against NPM and replacement; compare status, JSON shape, errors, side effects, and eventual Nginx behavior. No npmctl code change for the compatibility release unless explicitly approved.
11. **Docker release:** versioned amd64/arm64 image, reproducible build, health/readiness, persistent-volume upgrade, uid/gid mode, SBOM, vulnerability policy, signatures/provenance, and public registry pull test.
12. **Backup/restore:** one command/API exports a consistent encrypted bundle of database plus required files; restore into an empty host passes the full protocol and renewal smoke suite.

## Evidence gaps and decisions needed

- **NPM compatibility target:** exact API compatibility should be limited to operations actually used by current npmctl plus documented NPM operations; capturing npmctl traffic/contracts is a required downstream handoff.
- **Access tokens:** requested PAT/service tokens are an extension. Decide whether npmctl migrates to them immediately or retains JWT login/refresh compatibility first.
- **Persistence promise:** each deployment has one Tigrbl metadata engine. Filesystem/object storage owns certificate and generated-runtime artifacts; “hybrid” never means multiple writable metadata authorities.
- **MySQL:** the request names SQLite/PostgreSQL, while p100 NPM parity includes MySQL/MariaDB. Dropping it must be an explicit scope exception.
- **Raw Nginx config:** exact parity permits privileged arbitrary Nginx directives. Decide whether to preserve unrestricted admin-only behavior or add policy/sandbox modes while retaining an escape hatch.
- **DNS providers:** catalog parity (86 definitions) is not operational proof. Decide the supported/tested provider tier versus best-effort compatibility tier.
- **Licensing:** upstream is MIT, but a clean replacement should still retain provenance for copied code/assets and avoid confusing product identity/trademarks. [S1][S18]

## Primary sources

- [S1 — Official repository README](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/76f09db610cfcaecf6d608a8947d6f75aa028870/README.md)
- [S2 — Host/stream component schemas](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/76f09db610cfcaecf6d608a8947d6f75aa028870/backend/schema/components)
- [S3 — Access-list, certificate, user, permission, and audit schemas](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/76f09db610cfcaecf6d608a8947d6f75aa028870/backend/schema/components)
- [S4 — Official setup documentation](https://nginxproxymanager.com/setup/)
- [S5 — Official OpenAPI source](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/76f09db610cfcaecf6d608a8947d6f75aa028870/backend/schema/swagger.json)
- [S6 — Token, 2FA, and user implementation](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/76f09db610cfcaecf6d608a8947d6f75aa028870/backend/internal)
- [S7 — Permission policy implementation](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/76f09db610cfcaecf6d608a8947d6f75aa028870/backend/lib/access)
- [S8 — Official advanced configuration](https://nginxproxymanager.com/advanced-config/)
- [S9 — Nginx templates and includes](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/76f09db610cfcaecf6d608a8947d6f75aa028870/backend/templates)
- [S10 — API routes and domain services](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/76f09db610cfcaecf6d608a8947d6f75aa028870/backend/routes)
- [S11 — Nginx/domain safety implementation](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/76f09db610cfcaecf6d608a8947d6f75aa028870/backend/internal/nginx.js)
- [S12 — Certificate implementation](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/76f09db610cfcaecf6d608a8947d6f75aa028870/backend/internal/certificate.js)
- [S13 — Official Certbot plugin documentation](https://nginxproxymanager.com/certbot/)
- [S14 — Current frontend routes and UI source](https://github.com/NginxProxyManager/nginx-proxy-manager/tree/76f09db610cfcaecf6d608a8947d6f75aa028870/frontend/src)
- [S15 — v2.13.0 React/UI release notes](https://github.com/NginxProxyManager/nginx-proxy-manager/releases/tag/v2.13.0)
- [S16 — Security/support policy](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/76f09db610cfcaecf6d608a8947d6f75aa028870/SECURITY.md)
- [S17 — Official upgrading documentation](https://nginxproxymanager.com/upgrading/)
- [S18 — MIT license](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/76f09db610cfcaecf6d608a8947d6f75aa028870/LICENSE)
