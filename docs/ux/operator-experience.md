# Operator experience specification

Status: implementation-ready direction  
Review date: 2026-07-13

Portwyrm is a dense, calm operator console. It retains familiar workflows without copying
NPM branding or trade dress.

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
