# UI error message verification

Verified 2026-10-28: API validation details prefixed with a Python exception
class display only the message in the operator UI. For example,
`<class 'ValueError'>: current password is invalid` displays as
`current password is invalid`. Ordinary string details remain unchanged;
empty or non-string details use the HTTP status fallback.

The password-change regression in `frontend/tests/accessibility.spec.mjs`
intercepts a failed password request and asserts the exact alert text, then
completes a real password change and sign-in.

Validation: `npm.cmd run build` passed. `npm.cmd run test:a11y -- --grep
"login and authenticated"` passed (1 test, 13.7 seconds), including automated
WCAG checks on login, forced password change, and operator surfaces.

This changes presentation only; API responses and NPM compatibility contracts
retain their existing behavior.
