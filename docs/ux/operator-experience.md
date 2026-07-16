# Operator experience specification

Status: implementation-ready direction  
Review date: 2026-07-13

Portwyrm is a dense, calm operator console. It retains familiar workflows without copying
NPM branding or trade dress.

The console, compatibility API, native health endpoints, and `portwyrm` CLI are views over
one persistent control plane. A successful routing mutation is not complete until its
desired state has produced a validated active Nginx generation. The CLI emits JSON so the
same workflows remain usable in terminals and automation without requiring npm.

## Navigation

1. Dashboard
2. Hosts: Proxy Hosts, Redirection Hosts, Dead Hosts, Streams
3. Certificates
4. Access Control: Access Lists, Users, Access Tokens
5. Activity
6. Settings
7. System Health

The critical flow is:

`Domains -> Upstream -> Behaviors -> Access -> TLS -> Advanced -> Review/test -> Save and activate`

Common fields remain in the main path. WebSockets, cache, exploit blocking, HTTP/2, forced
SSL, and HSTS are outcome-oriented switches. Validation and runtime activation are distinct
states so failure is visible and recoverable.

## Required state behavior

| State | Behavior |
|---|---|
| Loading | skeleton matching final geometry; preserve filters and table shape |
| Empty | explain the resource and show the permitted primary action |
| Error | specific cause, retry, correlation ID, and retained input |
| Read-only | show fields; explain unavailable actions |
| Hidden | deny navigation and direct routes without count/metadata leakage |
| Password change required | show only current/new/confirmation fields; deny every other authenticated control-plane operation until the change commits |
| Saving | prevent duplicates and announce progress |
| Saved/pending | show desired generation and reconciliation job |
| Success | show resource ID, applied generation, and next action |
| Validation failure | focused summary plus inline field errors |
| Activation failure | preserve desired state and expose last-known-good recovery |
| Degraded runtime | identify affected hosts and show retry/rollback controls |
| Certificate risk | expiry, last attempt, provider error, and permitted recovery |
| Destructive action | named confirmation and dependency impact |

## Responsive and accessible behavior

- Wide layouts use a persistent sidebar, full tables, and split-pane detail.
- Medium layouts collapse navigation and move details into a drawer.
- Narrow layouts use cards, a single-column stepped form, and sticky primary action.
- Diagnostics may scroll horizontally; ordinary management content reflows.
- Touch targets are at least 44px. Keyboard order, focus visibility/restoration, semantic
  forms/tables, live announcements, 200% zoom, reduced motion, and WCAG 2.2 AA contrast are
  release requirements.

Use neutral surfaces, restrained elevation, and strong semantic status colors. Reserve
monospace typography for domains, addresses, identifiers, and generated configuration.

The browser gate runs installed Chrome with axe rules tagged for WCAG 2 A/AA, WCAG 2.1 AA,
and WCAG 2.2 AA. It scans setup/login plus the authenticated overview, hosts, certificates,
access lists, users, audit, and settings surfaces, and separately verifies the login form's
keyboard focus sequence. The current gate passes with no automated violations; manual zoom,
screen-reader, reduced-motion, and mobile assistive-technology review remain release checks.
