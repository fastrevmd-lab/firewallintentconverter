# Secure Local PyEZ Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve GitHub issue #7 by making the PyEZ bridge an authenticated, exact-origin, rate-limited, localhost-only service and updating every browser consumer to use it securely.

**Architecture:** A focused Python security module installs authentication, CORS, limits, and response headers on a Flask application factory while the existing device routes move unchanged into a blueprint. A shared browser bridge client owns URL persistence, session-scoped bearer tokens, authenticated fetches, and actionable HTTP errors; every UI caller uses that client. GitHub Actions provides the CI gate required before merge.

**Tech Stack:** Python 3.9+, Flask 3, flask-cors, Juniper PyEZ, JavaScript ES modules, React 18, Vite 8, Node 22, Python `unittest`, GitHub Actions.

## Global Constraints

- The bridge must reject every non-loopback bind address.
- `GET /health` and CORS `OPTIONS` preflights are the only unauthenticated requests.
- User-provided tokens must contain at least 32 characters; generated tokens use `secrets.token_urlsafe(32)`.
- Browser tokens must use `sessionStorage`, never `localStorage` or project data.
- Allowed origins must be exact HTTP(S) origins; reject `*`, `null`, credentials, paths, queries, and fragments.
- Request bodies are capped at 10 MiB.
- Per-source limits are 120 read requests/minute and 30 mutation requests/minute.
- No token, authorization header, or device credential may appear in an API response or log.
- Preserve all existing PyEZ device-operation behavior except where a request is rejected before device access.

---

### Task 0: Restore the existing JavaScript test baseline

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Modify: `public/utils/llm-client.js`

**Interfaces:**
- Produces: declared `vitest` 4.1.10 test-runner dependency compatible with Vite 8 and Node 20, 22, or 24+

- [x] **Step 1: Reproduce the missing-runner failure**

Run: `node tests/context-reducers.test.js`

Expected: `ERR_MODULE_NOT_FOUND` for `vitest`. This existing test is the failing reproduction; no new test is necessary for a missing test-runner dependency.

- [x] **Step 2: Declare the exact compatible dependency**

Run: `npm install --save-dev --save-exact vitest@4.1.10`

This also synchronizes the root package license in `package-lock.json` from the previous MIT relicensing commit.

- [x] **Step 3: Verify every existing Vitest suite**

Run:

```bash
npx vitest run tests/context-reducers.test.js tests/triage.test.js tests/workflow-steps.test.js
```

Expected: all three files pass.

- [x] **Step 4: Verify the self-running JavaScript baseline**

Run every remaining self-running JavaScript test. If direct Node execution reaches Vite-only development logging, guard `import.meta.env` with optional chaining so non-Vite test execution disables the log without changing application behavior:

```javascript
if (import.meta.env?.DEV) {
  console.log('[translate] Raw LLM response length:', response.length, 'chars');
}
```

Run: `node tests/llm-translate.test.js`

Expected: 113 passed, 0 failed.

- [x] **Step 5: Commit the baseline repair**

```bash
git add package.json package-lock.json public/utils/llm-client.js docs/superpowers/plans/2026-07-10-secure-pyez-bridge.md
git commit -m "test: declare existing Vitest runner"
```

---

### Task 1: Python security policy

**Files:**
- Create: `tools/pyez-bridge/security.py`
- Create: `tools/pyez-bridge/tests/__init__.py`
- Create: `tools/pyez-bridge/tests/test_security.py`

**Interfaces:**
- Produces: `validate_loopback_bind(host: str) -> str`
- Produces: `parse_allowed_origins(cli_origins: list[str] | None, env_value: str | None) -> list[str]`
- Produces: `resolve_token(configured: str | None) -> tuple[str, bool]`
- Produces: `WindowRateLimiter(read_limit=120, mutation_limit=30, window_seconds=60, clock=time.monotonic)` with `check(key, method) -> tuple[bool, int]`
- Produces: `install_security(app, token, allowed_origins, limiter=None) -> None`

- [x] **Step 1: Write failing unit tests for configuration validation**

Add tests that assert:

```python
self.assertEqual(validate_loopback_bind("127.0.0.1"), "127.0.0.1")
self.assertEqual(validate_loopback_bind("::1"), "::1")
for value in ("0.0.0.0", "192.0.2.10", "localhost", "example.com"):
    with self.assertRaises(ValueError):
        validate_loopback_bind(value)

self.assertEqual(
    parse_allowed_origins(["https://ui.example.test"], None),
    ["https://ui.example.test"],
)
for value in ("*", "null", "https://user@example.test", "https://example.test/path"):
    with self.assertRaises(ValueError):
        parse_allowed_origins([value], None)

with self.assertRaises(ValueError):
    resolve_token("short")
token, generated = resolve_token(None)
self.assertTrue(generated)
self.assertGreaterEqual(len(token), 32)
```

- [x] **Step 2: Run the configuration tests and verify RED**

Run: `python -m unittest tools/pyez-bridge/tests/test_security.py -v`

Expected: import failure because `tools/pyez-bridge/security.py` does not exist.

- [x] **Step 3: Implement configuration validation**

Implement `validate_loopback_bind` with `ipaddress.ip_address(host).is_loopback`. Implement origin validation with `urllib.parse.urlsplit`, requiring scheme `http` or `https`, a hostname, no username/password/path/query/fragment, and exact serialized origin equality. Merge repeatable CLI values with comma-separated environment values, de-duplicate without reordering, and default to:

```python
DEFAULT_ALLOWED_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)
```

Implement `resolve_token` with a 32-character minimum and `secrets.token_urlsafe(32)`.

- [x] **Step 4: Run configuration tests and verify GREEN**

Run: `python -m unittest tools/pyez-bridge/tests/test_security.py -v`

Expected: configuration-validation tests pass.

- [x] **Step 5: Write failing tests for real Flask request security**

Create a small Flask application in the test with `/health`, `/devices`, and `/devices/demo/load` routes, install security, and assert:

```python
self.assertEqual(client.get("/health").status_code, 200)
self.assertEqual(client.get("/devices").status_code, 401)
self.assertEqual(
    client.get("/devices", headers={"Authorization": f"Bearer {TOKEN}"}).status_code,
    200,
)

preflight = client.options("/devices", headers={
    "Origin": "http://localhost:5173",
    "Access-Control-Request-Method": "GET",
    "Access-Control-Request-Headers": "Authorization",
})
self.assertEqual(preflight.headers["Access-Control-Allow-Origin"], "http://localhost:5173")

denied = client.options("/devices", headers={
    "Origin": "https://evil.example",
    "Access-Control-Request-Method": "GET",
})
self.assertNotIn("Access-Control-Allow-Origin", denied.headers)
```

Also test constant external behavior for malformed/wrong tokens, `413` above 10 MiB, `429` at both thresholds with `Retry-After`, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`.

- [x] **Step 6: Run request-security tests and verify RED**

Run: `python -m unittest tools/pyez-bridge/tests/test_security.py -v`

Expected: failures because the request hooks and limiter are not implemented.

- [x] **Step 7: Implement the limiter and Flask hooks**

Use `threading.Lock`, monotonic window timestamps, and a dictionary keyed by `(remote_addr, "read"|"mutation")`. Treat `GET`, `HEAD`, and `OPTIONS` as reads, but exempt `OPTIONS` and `GET /health` before authentication and limiting. Authenticate with exact `Authorization: Bearer <token>` parsing and `hmac.compare_digest`.

Configure Flask and Flask-CORS with:

```python
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
CORS(
    app,
    origins=allowed_origins,
    methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    supports_credentials=False,
    send_wildcard=False,
    vary_header=True,
)
```

Return generic JSON `401` and `429` responses. Add `Retry-After` to rate-limit responses and security headers to every response.

- [x] **Step 8: Run all Python security tests and commit**

Run: `python -m unittest tools/pyez-bridge/tests/test_security.py -v`

Expected: all tests pass.

Commit:

```bash
git add tools/pyez-bridge/security.py tools/pyez-bridge/tests
git commit -m "security: add PyEZ bridge request controls"
```

---

### Task 2: Secure the actual Flask bridge

**Files:**
- Modify: `tools/pyez-bridge/app.py`
- Create: `tools/pyez-bridge/tests/test_app_security.py`

**Interfaces:**
- Consumes: all interfaces from `security.py`
- Produces: `bridge = Blueprint("bridge", __name__)`
- Produces: `create_app(config: dict | None = None) -> Flask`

- [x] **Step 1: Write failing integration tests against `create_app`**

Patch `DEVICES_FILE` to a temporary empty YAML file and create the application with:

```python
app = create_app({
    "TESTING": True,
    "BRIDGE_TOKEN": "t" * 32,
    "BRIDGE_ALLOWED_ORIGINS": ["http://localhost:5173"],
    "BRIDGE_RATE_LIMITER": WindowRateLimiter(read_limit=100, mutation_limit=100),
})
```

Assert public health, protected inventory, authorized inventory, allowed and denied preflights, oversized device JSON rejection, and that a rejected request never calls `_connect`.

- [x] **Step 2: Run integration tests and verify RED**

Run: `python -m unittest tools/pyez-bridge/tests/test_app_security.py -v`

Expected: import or attribute failure because `create_app` does not exist.

- [x] **Step 3: Convert routes to a blueprint and add the factory**

Replace `app = Flask(__name__)`, unrestricted `CORS(app)`, and every `@app.route` with a `Blueprint` registered by `create_app`. The factory resolves the token and allowed origins unless explicitly injected by tests, installs security, registers the blueprint, and records only these non-response configuration values:

```python
app.config["BRIDGE_TOKEN"] = token
app.config["BRIDGE_TOKEN_GENERATED"] = generated
app.config["BRIDGE_ALLOWED_ORIGINS"] = allowed_origins
```

Do not change endpoint bodies or PyEZ calls.

- [x] **Step 4: Make CLI startup fail closed**

Add repeatable `--allow-origin`. Validate `--bind` before creating the runnable app. Build allowed origins from CLI arguments and `PYEZ_BRIDGE_ALLOWED_ORIGINS`; build the token from `PYEZ_BRIDGE_TOKEN`. Print a generated token once, but never print an environment-provided token. Remove support for non-loopback binding.

For module/WSGI import, expose `app = create_app()` only when `__name__ != "__main__"`; WSGI deployments must set `PYEZ_BRIDGE_TOKEN` to know the token.

- [x] **Step 5: Run bridge integration and security suites**

Run: `python -m unittest discover tools/pyez-bridge/tests -v`

Expected: all tests pass and no NETCONF connection is attempted.

- [x] **Step 6: Commit the secured application**

```bash
git add tools/pyez-bridge/app.py tools/pyez-bridge/tests/test_app_security.py
git commit -m "security: enforce authenticated local bridge"
```

---

### Task 3: Shared authenticated browser client

**Files:**
- Create: `public/utils/bridge-client.js`
- Create: `tests/bridge-client.test.js`

**Interfaces:**
- Produces: `normalizeBridgeUrl(raw: string) -> string`
- Produces: `loadBridgeSettings() -> {url: string, token: string}`
- Produces: `saveBridgeSettings({url, token}) -> {url: string, token: string}`
- Produces: `bridgeFetch(url: string, options?: RequestInit, requestOptions?: {timeout?: number, authenticated?: boolean}) -> Promise<Response>`
- Produces: `bridgeResponseError(response: Response) -> Promise<Error>`

- [ ] **Step 1: Write failing browser-client tests**

Stub `localStorage`, `sessionStorage`, and `fetch`. Assert that `saveBridgeSettings` stores JSON containing only `url` in `pyez-bridge-settings`, stores the token under `pyez-bridge-token` in session storage, and never writes the token to local storage. Assert URL migration from `mcp-settings` still works.

Assert an authenticated request receives:

```javascript
{
  headers: {
    Authorization: 'Bearer session-token-value-1234567890',
    'Content-Type': 'application/json',
  },
  mode: 'cors',
}
```

Assert `{ authenticated: false }` omits `Authorization`; missing tokens reject before fetch; caller headers are preserved; `401`, `403`, and `429` map to actionable messages; and timeout aborts the request.

- [ ] **Step 2: Run client tests and verify RED**

Run: `node tests/bridge-client.test.js`

Expected: module-not-found failure.

- [ ] **Step 3: Implement the shared client**

Use the existing strict URL rules from `usePush`: only HTTP(S), no embedded username/password, and no trailing slash. Persist the URL in local storage and the token in session storage. Clone headers through `new Headers(options.headers || {})`, set but do not overwrite `Authorization`, and always set `mode: "cors"`. Use `AbortController` and clear the timer in `finally`.

`bridgeResponseError` must parse a JSON `error` when available and otherwise return:

```javascript
401: 'Bridge access token is missing or invalid.'
403: 'This browser origin is not allowed by the bridge.'
429: 'Bridge request limit reached. Wait and try again.'
```

- [ ] **Step 4: Run client tests and commit**

Run: `node tests/bridge-client.test.js`

Expected: all tests pass.

```bash
git add public/utils/bridge-client.js tests/bridge-client.test.js
git commit -m "security: add authenticated bridge client"
```

---

### Task 4: Migrate every browser bridge caller

**Files:**
- Modify: `public/hooks/usePush.js`
- Modify: `public/hooks/useDay2Ops.js`
- Modify: `public/components/LLMSettings.jsx`
- Modify: `public/components/PullModal.jsx`
- Modify: `public/components/SRXOutput.jsx`
- Modify: `public/components/layout/WorkflowStepper.jsx`
- Modify: `tests/day2-ops.test.js`

**Interfaces:**
- Consumes: `loadBridgeSettings`, `saveBridgeSettings`, `bridgeFetch`, and `bridgeResponseError`
- Preserves: existing hook return values and component props outside bridge settings

- [ ] **Step 1: Add failing regression assertions for frontend callers**

Extend browser-client coverage with an exported fetch spy and add source-contract assertions that protected bridge calls do not use raw `fetch`. The test must inspect the six caller source files and fail if a protected `/devices` request is made through raw `fetch(` rather than `bridgeFetch(`.

- [ ] **Step 2: Run frontend tests and verify RED**

Run: `node tests/bridge-client.test.js`

Expected: failure listing the remaining raw protected bridge calls.

- [ ] **Step 3: Migrate hooks**

In `usePush`, remove duplicate URL/storage/fetch helpers, initialize from `loadBridgeSettings()`, save URL through `saveBridgeSettings`, use unauthenticated `bridgeFetch(..., {}, {authenticated: false})` only for `/health`, and use authenticated `bridgeFetch` everywhere else.

In `useDay2Ops`, load the URL from the shared settings module and replace its local timeout fetch helper with `bridgeFetch`. Preserve the existing 30-second request timeout and 60-second probe timeout behavior.

- [ ] **Step 4: Migrate settings and add token input**

Initialize `bridgeUrl` and new `bridgeToken` state from `loadBridgeSettings`. Save both through `saveBridgeSettings`. Add a masked input labelled `Bridge Access Token` with autocomplete disabled and helper text stating that it is kept only for the browser session.

Connection testing must call `/health` without authentication and `/devices` with authentication. Treat successful health plus `401` inventory as a token error rather than a connected bridge. Add/remove/probe calls must use `bridgeFetch`.

- [ ] **Step 5: Migrate pull, output, and workflow checks**

Replace protected raw calls in `PullModal`, `SRXOutput`, and `WorkflowStepper` with `bridgeFetch`; keep `/health` explicitly unauthenticated. Use `bridgeResponseError` so `401`, `403`, and `429` are shown rather than discarded.

- [ ] **Step 6: Run focused and existing frontend tests**

Run each command and require zero failures:

```bash
node tests/bridge-client.test.js
node tests/day2-ops.test.js
npm run build
```

- [ ] **Step 7: Commit the migration**

```bash
git add public/hooks/usePush.js public/hooks/useDay2Ops.js public/components/LLMSettings.jsx public/components/PullModal.jsx public/components/SRXOutput.jsx public/components/layout/WorkflowStepper.jsx tests/bridge-client.test.js tests/day2-ops.test.js
git commit -m "security: authenticate browser bridge requests"
```

---

### Task 5: Documentation and mandatory CI

**Files:**
- Modify: `tools/pyez-bridge/README.md`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: GitHub checks `Web` and `PyEZ bridge`

- [ ] **Step 1: Update operator documentation**

Document these exact launch patterns:

```bash
# Generated one-session token printed at startup
python app.py --allow-origin http://localhost:5173

# Stable token for repeated launches
export PYEZ_BRIDGE_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python app.py --allow-origin https://converter.example.test

curl -H "Authorization: Bearer $PYEZ_BRIDGE_TOKEN" \
  http://127.0.0.1:8830/devices
```

Remove the `0.0.0.0` example. Document exact origins, the UI token field, session lifetime, `401`, CORS failure, `429`, and that remote access is unsupported.

- [ ] **Step 2: Add GitHub Actions CI**

Create `.github/workflows/ci.yml` with read-only repository permissions, cancellation of superseded runs, Node 22 and Python 3.12. The `Web` job runs `npm ci`, the three declared Vitest suites, every remaining self-running `tests/*.test.js` file in lexical order, and `npm run build`. The `PyEZ bridge` job installs `tools/pyez-bridge/requirements.txt` and runs:

```bash
python -m unittest discover tools/pyez-bridge/tests -v
```

- [ ] **Step 3: Run the complete local verification suite**

Run:

```bash
npx vitest run tests/context-reducers.test.js tests/triage.test.js tests/workflow-steps.test.js
for test_file in tests/*.test.js; do
  if grep -q "from 'vitest'" "$test_file"; then continue; fi
  node "$test_file"
done
python -m unittest discover tools/pyez-bridge/tests -v
npm run build
git diff --check
```

Expected: every JavaScript and Python test passes, Vite builds successfully, and `git diff --check` produces no output.

- [ ] **Step 4: Commit documentation and CI**

```bash
git add tools/pyez-bridge/README.md .github/workflows/ci.yml
git commit -m "ci: verify web and PyEZ bridge security"
```

---

### Task 6: Publish, review, CI, and merge issue #7

**Files:**
- Verify only; no planned source changes unless CI or review identifies a defect

**Interfaces:**
- Produces: pushed branch, ready PR linked to issue #7, green required checks, merged PR, closed issue

- [ ] **Step 1: Perform the pre-publish audit**

Confirm `git status --short` is empty, review `git diff origin/main...HEAD`, and map every issue #7 acceptance criterion to a passing test or documented startup behavior.

- [ ] **Step 2: Push and open the PR**

Push `agent/issue-7-secure-pyez-bridge` to `origin`. Open a draft PR targeting `main` with `Fixes #7`, the root cause, security behavior, migration note, and exact local checks. Mark it ready only after the diff and check list are complete.

- [ ] **Step 3: Wait for and inspect CI**

Use `gh pr checks --watch`. If any check fails, inspect the actual GitHub Actions log, reproduce locally, add a failing regression test when behavior is wrong, fix test-first, commit, push, and wait again.

- [ ] **Step 4: Merge and verify external state**

Squash-merge only when all checks pass and the PR is mergeable. Verify the PR reports `MERGED`, issue #7 reports `CLOSED`, `origin/main` contains the merge commit, and the local checkout returns to an updated `main` before beginning issue #12.
