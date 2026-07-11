# Secure Local PyEZ Bridge Design

## Scope

This design resolves GitHub issue #7 by securing the existing Flask/PyEZ bridge and its browser client. The bridge remains a single-user, localhost-only process. Remote or shared deployment is deliberately unsupported; a future remote service must provide its own TLS, identity, and authorization design.

The change does not replace PyEZ, change NETCONF behavior, or address configuration-injection and device host-key verification findings tracked in separate issues.

## Security invariants

- The bridge listens only on an IPv4 or IPv6 loopback address.
- Every route except `GET /health` requires a bearer token. Browser preflight requests are exempt from authentication but remain constrained by CORS.
- Tokens contain at least 256 bits of generated entropy or are user-provided values of at least 32 characters.
- Tokens are compared with a constant-time comparison and are never returned by an API response or written to browser persistent storage.
- Browser access is allowed only from exact configured origins. Wildcards, reflected origins, credentialed CORS, and the opaque `null` origin are rejected.
- Request bodies are limited to 10 MiB.
- Authenticated requests are rate-limited per source address: 120 read requests per minute and 30 mutation requests per minute.
- Bridge responses containing operational or inventory data use `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

## Bridge architecture

`tools/pyez-bridge/security.py` will own security policy that is independent of device operations:

- validate loopback bind addresses;
- obtain `PYEZ_BRIDGE_TOKEN` or generate a URL-safe token at startup;
- validate the exact-origin allowlist supplied through `PYEZ_BRIDGE_ALLOWED_ORIGINS` and repeatable `--allow-origin` arguments;
- authenticate bearer tokens;
- apply a small in-memory, thread-safe rate limiter; and
- install CORS and response-hardening hooks on a Flask application.

`tools/pyez-bridge/app.py` will retain device inventory and PyEZ endpoint behavior. It will create the Flask application through `create_app(config=None)` so security behavior can be exercised with Flask's real test client. CLI startup will reject any non-loopback `--bind` value before opening a socket. The public health route will report liveness without disclosing the token; all device routes will pass through authentication and rate limiting.

The bridge will not accept a token through a command-line argument because process arguments are commonly visible to other users. If `PYEZ_BRIDGE_TOKEN` is absent, startup will generate a fresh token and print it once to the controlling terminal. A restart therefore invalidates the previous generated token.

## Browser architecture and data flow

`public/utils/bridge-client.js` will be the only module that knows how bridge authentication works. It will:

- normalize and validate HTTP(S) bridge URLs;
- store only the normalized URL in `localStorage`;
- keep the bearer token in `sessionStorage` so it is removed when the browser session ends;
- add `Authorization: Bearer ...` to every authenticated request;
- preserve caller headers such as `Content-Type`;
- provide unauthenticated health checks; and
- surface `401`, `403`, and `429` responses as actionable connection errors.

`usePush`, `useDay2Ops`, `LLMSettings`, `PullModal`, `SRXOutput`, and workflow connection checks will call this shared client instead of calling `fetch` directly. The settings dialog will add a masked Bridge Access Token field. Saving settings persists the URL and places the token in session storage; the token is never included in project data.

The normal connection flow is:

1. The browser calls public `GET /health` to verify that the URL is a PyEZ bridge.
2. The browser calls authenticated `GET /devices` to verify the token and load inventory.
3. Every later read or mutation uses the same authenticated client.
4. A missing or rejected token marks the bridge disconnected and tells the user to enter the token printed by the bridge.

## CORS and origin configuration

The default allowlist contains only `http://localhost:5173` and `http://127.0.0.1:5173`, matching the local Vite development server. Operators serving the UI from another origin must explicitly add that exact origin with `--allow-origin` or `PYEZ_BRIDGE_ALLOWED_ORIGINS`.

Origins must use HTTP or HTTPS, contain no credentials, path, query, or fragment, and cannot be `*` or `null`. Requests without an `Origin` header remain usable by local CLI tools but still require bearer authentication for sensitive routes. Preflight responses allow only the configured origin, required methods, `Authorization`, and `Content-Type`.

## Errors and operational behavior

- Missing or malformed authorization returns `401` with a generic JSON error.
- A well-formed but incorrect token also returns `401`; responses do not reveal whether token parsing or comparison failed.
- Disallowed browser origins receive no permissive CORS headers. The underlying request still requires authentication.
- Rate-limit exhaustion returns `429` with `Retry-After` and does not invoke a PyEZ operation.
- Oversized request bodies return `413` before parsing or device access.
- Invalid bind addresses or insecure origin configuration stop bridge startup with a concise error.
- Authentication failures, tokens, device credentials, and authorization headers are not logged.

## Testing and CI

Python tests will use Flask's test client against the application factory and cover:

- public health and protected device routes;
- missing, malformed, correct, and incorrect bearer tokens;
- approved and unapproved CORS preflights;
- no wildcard or opaque origins;
- loopback acceptance and non-loopback rejection;
- request-size rejection;
- separate read and mutation rate limits; and
- security response headers.

JavaScript tests will exercise the real shared bridge client with stubbed Web Storage and fetch implementations. They will prove that the token is session-scoped, never copied into local storage, added to protected requests, omitted from health checks, and preserved alongside content headers.

Because the repository currently has no GitHub Actions workflow, this change will add CI that installs the Node and Python dependencies, runs all JavaScript tests, runs the bridge security tests, and builds the Vite application. The PR cannot merge until these checks pass.

## Documentation and migration

The bridge README will document token startup, allowed origins, localhost-only binding, curl examples with the authorization header, storage lifetime, and common `401`/CORS errors. The prior `--bind 0.0.0.0` example will be removed.

Existing users must copy the startup token into Settings after upgrading. Existing saved bridge URLs continue to migrate from the old `mcp-settings` key, but no token will be invented or persisted on their behalf.

## Out of scope

- Remote bridge access, TLS termination, multi-user identity, and per-role authorization.
- Replacing PyEZ with RustEZ.
- SSH host-key verification and device credential-at-rest changes tracked by issue #9.
- Configuration validation and injection defenses tracked by issue #12.
