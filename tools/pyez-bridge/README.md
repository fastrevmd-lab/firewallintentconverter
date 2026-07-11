# PyEZ Bridge

The PyEZ Bridge is a localhost-only REST API that lets Firewall Intent Converter load, validate, commit, pull, and inspect Juniper SRX configurations over NETCONF.

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

Edit `devices.yaml`:

```yaml
devices:
  - name: srx-lab-01
    host: 192.168.1.1
    port: 830
    username: admin
    password: replace-me

  - name: srx-prod-fw
    host: 10.0.0.1
    port: 830
    username: netops
    ssh_key: ~/.ssh/id_rsa
```

The UI can also add and remove devices. The file currently contains credentials, so restrict it to its owner:

```bash
chmod 600 devices.yaml
```

Credential-at-rest and NETCONF host-key improvements are tracked separately in GitHub issue #9.

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

## Troubleshooting

- **401 Authentication required:** paste the current startup token into the Bridge Access Token field. Generated tokens change after every restart.
- **Browser CORS error:** add the UI's exact origin with `--allow-origin`; do not add a wildcard.
- **429 Request rate limit exceeded:** wait for the `Retry-After` interval before retrying.
- **Startup rejects the bind address:** only numeric loopback addresses such as `127.0.0.1` and `::1` are supported.
- **Health works but devices do not:** `/health` is public; `/devices` verifies the access token.
