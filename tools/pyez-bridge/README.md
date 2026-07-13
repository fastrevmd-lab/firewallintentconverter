# PyEZ Bridge

The PyEZ Bridge is a localhost-only REST API that lets firewallintentconverter · a mechub project load, validate, commit, pull, and inspect Juniper SRX configurations over NETCONF.

```text
Browser (React SPA) ── authenticated HTTP ──> PyEZ Bridge (loopback:8830) ── NETCONF ──> SRX
```

## Security model

- The service accepts only numeric IPv4 or IPv6 loopback bind addresses.
- Every endpoint except `GET /health` requires a bearer access token.
- Browser access is limited to exact configured HTTP(S) origins.
- Request bodies are limited to 10 MiB.
- Reads are limited to 120 requests/minute and mutations to 30 requests/minute per source address.
- The browser keeps the access token in `sessionStorage`; closing the browser session removes it.
- The device inventory contains connection metadata and credential references only; passwords and private-key material are rejected.
- NETCONF SSH host keys are verified against the operator's OpenSSH known-hosts data by default.
- Remote/shared deployment and wildcard CORS are not supported. Do not place this development server directly on a network.

## Prerequisites

- Python 3.9+
- Network access from the workstation to each SRX NETCONF port, normally TCP/830
- NETCONF enabled on the SRX: `set system services netconf ssh`

## Install

```bash
cd tools/pyez-bridge
python -m venv venv
venv/bin/pip install -r requirements.txt
```

## Configure devices

Create the runtime inventory with owner-only permissions before editing it:

```bash
cp devices.example.yaml devices.yaml
chmod 600 devices.yaml
```

The inventory supports SSH-agent authentication and references to password environment variables. It never stores passwords or private-key paths:

```yaml
devices:
  - name: srx-lab-01
    host: 192.0.2.10
    port: 830
    username: netops
    auth_method: agent

  - name: srx-prod-01
    host: 198.51.100.10
    port: 830
    username: automation
    auth_method: password-env
    password_env: FIC_SRX_PROD_PASSWORD
```

For agent authentication, start an agent and load the key before starting the bridge:

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/pyez_rsa
```

For password-environment authentication, define the referenced variable in the bridge process environment:

```bash
export FIC_SRX_PROD_PASSWORD='set this in the bridge process environment'
```

An OpenSSH host entry can select an identity outside the project inventory:

```sshconfig
Host srx-lab-01
  HostName 192.0.2.10
  Port 830
  User netops
  IdentityFile ~/.ssh/pyez_rsa
  IdentitiesOnly yes
```

### Enroll verified NETCONF host keys

Collect a candidate host key and display its fingerprint:

```bash
ssh-keyscan -p 830 192.0.2.10 > /tmp/srx-lab-01.hostkey
ssh-keygen -lf /tmp/srx-lab-01.hostkey
```

The key returned by `ssh-keyscan` is untrusted. Compare its fingerprint through an independent channel, such as the device console or an authoritative asset-management record. Only after the fingerprint matches may you append the collected entry to `~/.ssh/known_hosts`. OpenSSH stores a nonstandard-port entry using bracket notation, for example `[192.0.2.10]:830`.

Unknown or changed keys fail with `DEVICE_IDENTITY_FAILED`. Investigate that failure; do not delete and re-enroll the known-host entry automatically.

### Legacy inventory migration

A runtime inventory containing `password`, `passwd`, `ssh_key`, `ssh_private_key_file`, or private-key material is rejected with `INVENTORY_UNSAFE`. Load private keys into `ssh-agent` or select them in `~/.ssh/config`. Replace stored passwords with `auth_method: password-env` and a `password_env` reference, then remove every secret field and restore the runtime file to mode `0600`.

The bridge refuses an unsafe inventory without silently changing its permissions. It does not silently repair an already-unsafe file because that file may already have been exposed; review the exposure and rotate affected credentials as needed before completing the migration.

## Start with a generated token

The default command binds to `127.0.0.1:8830`, permits the local Vite development origin, and prints a fresh access token. That generated token is valid only until the bridge restarts.

```bash
venv/bin/python app.py --allow-origin http://localhost:5173
```

Copy the printed token into **Settings → SRX Device Connection → Bridge Access Token**.

## Start with a stable token

Use an environment variable when repeated restarts should retain the same token. The token must contain at least 32 characters and is not accepted as a command-line argument because command arguments can be visible to other users.

Set `PYEZ_BRIDGE_TOKEN` before importing `app` from a WSGI server as well. Only direct `python app.py` startup can display an automatically generated token on its controlling terminal.

```bash
export PYEZ_BRIDGE_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
venv/bin/python app.py --allow-origin https://converter.example.test
```

Configure multiple exact origins by repeating `--allow-origin`:

```bash
venv/bin/python app.py \
  --allow-origin http://localhost:5173 \
  --allow-origin https://converter.example.test
```

Or use a comma-separated environment variable:

```bash
export PYEZ_BRIDGE_ALLOWED_ORIGINS="http://localhost:5173,https://converter.example.test"
venv/bin/python app.py
```

Origins cannot contain credentials, paths, queries, fragments, wildcard `*`, or opaque `null` values. The standalone `file://` origin is intentionally unsupported; serve the UI over local HTTP instead.

## Development-only override

For an isolated development environment only, `--insecure-allow-unknown-hosts` disables NETCONF SSH host-key verification:

```bash
venv/bin/python app.py \
  --allow-origin http://localhost:5173 \
  --insecure-allow-unknown-hosts
```

Startup prints a prominent warning that a network attacker can impersonate managed devices. `GET /health` reports `host_key_verification: disabled-development`, and the connected UI keeps the same warning visible. The override never disables bridge-token authentication or the localhost bind and origin controls. It must not be used for production device access.

## API examples

The health endpoint is public so the UI can identify the service:

```bash
curl http://127.0.0.1:8830/health
```

All device endpoints require the token:

```bash
curl -H "Authorization: Bearer $PYEZ_BRIDGE_TOKEN" \
  http://127.0.0.1:8830/devices
```

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Public liveness check |
| `GET` | `/devices` | List devices; optional `?probe=true` |
| `POST` | `/devices` | Add a device |
| `DELETE` | `/devices/<name>` | Remove a device |
| `GET` | `/devices/<name>/facts` | Fetch device facts |
| `POST` | `/devices/<name>/unlock` | Clear a stale candidate lock |
| `POST` | `/devices/<name>/load` | Load candidate configuration |
| `GET` | `/devices/<name>/diff` | Show candidate versus active diff |
| `POST` | `/devices/<name>/commit-check` | Validate the candidate |
| `POST` | `/devices/<name>/commit` | Commit, optionally with a confirmation timer |
| `POST` | `/devices/<name>/confirm` | Confirm a pending commit-confirm |
| `POST` | `/devices/<name>/rollback` | Roll back configuration |
| `GET` | `/devices/<name>/pull-config` | Pull running configuration |
| `GET` | `/devices/<name>/policy-stats` | Fetch policy statistics |
| `GET` | `/devices/<name>/app-usage` | Fetch application usage |

### Configuration load validation

`POST /devices/<name>/load` accepts only the converter's supported `set` and XML subset. Before opening NETCONF, the bridge rejects control characters, malformed quoting or XML, unsupported command verbs and top-level hierarchies, DTDs/entities/processing instructions, clear-text management services, scripts/event automation, and credential-changing paths. Validation errors report only a safe line number or XML path and reason.

Brace-format `text` loads are disabled because they cannot be structurally validated to the same standard. The read-only pull endpoint may still return hierarchical text for inspection.

## Troubleshooting

- **401 Authentication required:** paste the current startup token into the Bridge Access Token field. Generated tokens change after every restart.
- **Browser CORS error:** add the UI's exact origin with `--allow-origin`; do not add a wildcard.
- **429 Request rate limit exceeded:** wait for the `Retry-After` interval before retrying.
- **Startup rejects the bind address:** only numeric loopback addresses such as `127.0.0.1` and `::1` are supported.
- **Health works but devices do not:** `/health` is public; `/devices` verifies the access token.
- **DEVICE_IDENTITY_FAILED:** independently verify the device fingerprint and investigate unknown or changed keys; do not automatically delete the known-host entry.
- **INVENTORY_UNSAFE:** migrate legacy secret fields and manually restore owner-only mode after reviewing possible exposure; the bridge intentionally does not repair the file for you.
- **400 Configuration validation failed:** use converter-generated set or XML output. Text/brace-format loads and arbitrary Junos hierarchies are intentionally unsupported.
