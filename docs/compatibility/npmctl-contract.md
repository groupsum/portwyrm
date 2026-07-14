# npmctl compatibility contract

Status: direct repository evidence, observed 2026-07-13

Portwyrm exposes a compatibility facade at `/api`; native features live under a separately
versioned API. npmctl is coupled to the facade, not to NPM's database or Nginx internals.

## Connection and authentication

- Existing `NPM_BASE_URL`, `NPM_IDENTITY`, `NPM_SECRET`, and optional
  `NPM_TIMEOUT_S` remain valid.
- `POST /tokens` accepts `identity`, `secret`, and `scope: user`; the response contains
  a non-empty token and numeric epoch or ISO-8601 expiry, directly or under `result`.
- `GET /tokens` refreshes a bearer token. Authenticated calls use
  `Authorization: Bearer <token>`.
- `GET /api/` returns JSON and `GET /api/schema` returns OpenAPI with `paths`.

## Required resources

| Collection | Compatibility behavior |
|---|---|
| `/nginx/proxy-hosts` | list/create and item update/delete; complete proxy behavior fields |
| `/nginx/certificates` | pass through provider/ACME fields and preserve unknown keys |
| `/nginx/access-lists` | pass through items, clients, satisfy-any, metadata, and unknown keys |
| `/nginx/redirection-hosts` | generic round-trip with domain natural key |
| `/nginx/dead-hosts` | generic round-trip with domain natural key |
| `/nginx/streams` | incoming port, upstream, and TCP/UDP protocol |
| `/users` | email natural key; list `403` is tolerated by npmctl |
| `/settings` | string or positive-integer IDs and name/value behavior |
| `/audit-log` | read-only list and verbatim `since` query |

List operations return raw arrays. Creates and updates return objects containing IDs and
identifying fields. Delete may return `true`, an empty object, or an empty body. Non-2xx
responses are failures; error information must not be hidden in a 2xx envelope.

## Proxy payload and ownership

The facade supports domains, upstream scheme/host/port, access-list and certificate links,
forced SSL, cache, exploit blocking, WebSocket upgrade, HTTP/2, enabled state, HSTS,
advanced configuration, custom locations, and metadata. It accepts integer- and
boolean-compatible flag values where NPM does.

Every object has a stable positive integer ID, except settings may also use non-empty string
IDs. Import must preserve IDs because current desired state includes hard-coded certificate
references `161`, `187`, and `7`.

The exact metadata keys `meta.managed_by="npmctl"`, `meta.owner`, and
`meta.resource_id` survive every storage backend and round trip. Foreign or invalid
ownership is conflict-safe. Adoption and pruning remain explicit and owner-scoped.

## Zero-touch cutover acceptance

1. Preserve the existing base URL secret names and ports `80`, `81`, and `443`.
2. Inventory live resources and certificate files; export stable IDs and metadata.
3. Shadow-render all configurations and pass syntax validation.
4. Quiesce writes, apply the final delta, import or deliberately reissue certificates.
5. Swap the container endpoint.
6. Run current npmctl `doctor`, `schema check`, `plan`, `apply`, `adopt`, `drift`,
   and `audit-log`; the initial plan must show no unintended drift.
7. Verify HTTPS, HTTP-to-HTTPS, HSTS, cache semantics, and WebSocket upgrades.

## Local evidence

- `groupsum/npmctl/packages/npmctl/src/npmctl/client/base.py`
- `groupsum/npmctl/packages/npmctl/src/npmctl/client/contracts.py`
- `groupsum/npmctl/packages/npmctl/src/npmctl/models.py`
- `groupsum/npmctl/packages/npmctl/src/npmctl/planner.py`
- `groupsum/npmctl/packages/npmctl/src/npmctl/schema.py`
- `groupsum/npmctl/packages/npmctl/tests/conftest.py`
- `groupsum/npmctl/docs/specs/npmctl-openapi-subset.md`
