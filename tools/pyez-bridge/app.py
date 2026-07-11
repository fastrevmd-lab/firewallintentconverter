"""
PyEZ Bridge — Lightweight REST API for pushing SRX configurations via NETCONF.

Wraps Juniper PyEZ (junos-eznc) behind Flask endpoints so the browser-based
Firewall Intent Converter can push configs, run commit checks, and manage
commits on live SRX devices.

Usage:
    pip install -r requirements.txt
    python app.py                     # starts on 127.0.0.1:8830
    python app.py --port 9000         # custom port
    python app.py --allow-origin http://localhost:5173
"""

import argparse
import os
import time
from pathlib import Path

import yaml
from flask import Blueprint, Flask, jsonify, request

from security import (
    install_security,
    parse_allowed_origins,
    resolve_token,
    validate_loopback_bind,
)

# PyEZ imports
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import (
    ConnectError,
    ConnectAuthError,
    ConnectRefusedError,
    ConnectTimeoutError,
    CommitError,
    ConfigLoadError,
    LockError,
    UnlockError,
    RpcError,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DEVICES_FILE = Path(__file__).parent / "devices.yaml"
CONNECT_TIMEOUT = 10   # seconds
OPERATION_TIMEOUT = 30  # seconds

bridge = Blueprint("bridge", __name__)


def create_app(config=None):
    """Create a secured bridge application."""
    supplied = dict(config or {})
    app = Flask(__name__)
    app.config.update(supplied)

    configured_token = (
        supplied["BRIDGE_TOKEN"]
        if "BRIDGE_TOKEN" in supplied
        else os.environ.get("PYEZ_BRIDGE_TOKEN")
    )
    token, generated = resolve_token(configured_token)

    if "BRIDGE_ALLOWED_ORIGINS" in supplied:
        allowed_origins = parse_allowed_origins(
            supplied["BRIDGE_ALLOWED_ORIGINS"], None
        )
    else:
        allowed_origins = parse_allowed_origins(
            None, os.environ.get("PYEZ_BRIDGE_ALLOWED_ORIGINS")
        )

    app.config["BRIDGE_TOKEN"] = token
    app.config["BRIDGE_TOKEN_GENERATED"] = generated
    app.config["BRIDGE_ALLOWED_ORIGINS"] = allowed_origins

    app.register_blueprint(bridge)
    install_security(
        app,
        token,
        allowed_origins,
        limiter=supplied.get("BRIDGE_RATE_LIMITER"),
    )
    return app


# ---------------------------------------------------------------------------
# Device store helpers
# ---------------------------------------------------------------------------
def _load_devices():
    """Read devices.yaml and return the list of device dicts."""
    if not DEVICES_FILE.exists():
        return []
    with open(DEVICES_FILE, "r") as f:
        data = yaml.safe_load(f) or {}
    return data.get("devices", []) or []


def _save_devices(devices):
    """Write devices list back to devices.yaml."""
    with open(DEVICES_FILE, "w") as f:
        yaml.dump({"devices": devices}, f, default_flow_style=False)


def _find_device(name):
    """Look up a device by name. Returns (device_dict, index) or (None, -1)."""
    devices = _load_devices()
    for i, d in enumerate(devices):
        if d.get("name") == name:
            return d, i
    return None, -1


def _safe_device_info(dev_dict):
    """Return device info without sensitive fields (password, ssh_key)."""
    return {
        "name": dev_dict.get("name", ""),
        "host": dev_dict.get("host", ""),
        "port": dev_dict.get("port", 830),
        "username": dev_dict.get("username", ""),
        "has_password": bool(dev_dict.get("password")),
        "has_ssh_key": bool(dev_dict.get("ssh_key")),
    }


def _connect(dev_dict):
    """Open a PyEZ Device connection. Caller must close it."""
    kwargs = {
        "host": dev_dict["host"],
        "user": dev_dict.get("username", "root"),
        "port": dev_dict.get("port", 830),
        "conn_open_timeout": CONNECT_TIMEOUT,
    }
    if dev_dict.get("ssh_key"):
        key_path = os.path.expanduser(dev_dict["ssh_key"])
        kwargs["ssh_private_key_file"] = key_path
    elif dev_dict.get("password"):
        kwargs["passwd"] = dev_dict["password"]

    dev = Device(**kwargs)
    dev.open()
    dev.timeout = OPERATION_TIMEOUT
    return dev


def _error_response(message, status=400, details=None):
    """Build a standard error JSON response."""
    body = {"ok": False, "error": message}
    if details:
        body["details"] = details
    return jsonify(body), status


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@bridge.route("/health", methods=["GET"])
def health():
    """Liveness check — matches the existing UI expectation."""
    return jsonify({"status": "ok", "version": "1.0.0", "service": "pyez-bridge"})


@bridge.route("/devices", methods=["GET"])
def list_devices():
    """List configured devices. Use ?probe=true to test connectivity (slower)."""
    devices = _load_devices()
    probe = request.args.get("probe", "false").lower() in ("true", "1", "yes")
    result = []
    for dev_dict in devices:
        info = _safe_device_info(dev_dict)
        info["status"] = "unknown"
        if probe:
            try:
                dev = _connect(dev_dict)
                facts = dev.facts or {}
                info["hostname"] = facts.get("hostname", "")
                info["model"] = facts.get("model", "")
                info["version"] = facts.get("version", "")
                info["serial"] = facts.get("serialnumber", "")
                info["status"] = "connected"
                dev.close()
            except Exception:
                info["status"] = "unreachable"
        result.append(info)
    return jsonify({"devices": result})


@bridge.route("/devices", methods=["POST"])
def add_device():
    """Add a new device to devices.yaml."""
    data = request.get_json(silent=True)
    if not data:
        return _error_response("Request body must be JSON.")

    name = (data.get("name") or "").strip()
    host = (data.get("host") or "").strip()
    username = (data.get("username") or "").strip()

    if not name:
        return _error_response("Device name is required.")
    if not host:
        return _error_response("Device host/IP is required.")
    if not username:
        return _error_response("Username is required.")

    devices = _load_devices()
    # Check duplicate name
    if any(d.get("name") == name for d in devices):
        return _error_response(f"Device '{name}' already exists.", 409)

    entry = {
        "name": name,
        "host": host,
        "port": data.get("port", 830),
        "username": username,
    }
    if data.get("password"):
        entry["password"] = data["password"]
    if data.get("ssh_key"):
        entry["ssh_key"] = data["ssh_key"]

    devices.append(entry)
    _save_devices(devices)
    return jsonify({"ok": True, "device": _safe_device_info(entry)}), 201


@bridge.route("/devices/<name>", methods=["DELETE"])
def remove_device(name):
    """Remove a device from devices.yaml."""
    devices = _load_devices()
    filtered = [d for d in devices if d.get("name") != name]
    if len(filtered) == len(devices):
        return _error_response(f"Device '{name}' not found.", 404)
    _save_devices(filtered)
    return jsonify({"ok": True})


@bridge.route("/devices/<name>/facts", methods=["GET"])
def device_facts(name):
    """Fetch device facts via PyEZ."""
    dev_dict, _ = _find_device(name)
    if not dev_dict:
        return _error_response(f"Device '{name}' not found.", 404)

    try:
        dev = _connect(dev_dict)
        facts = dev.facts or {}
        result = {
            "hostname": facts.get("hostname", ""),
            "model": facts.get("model", ""),
            "version": facts.get("version", ""),
            "serial_number": facts.get("serialnumber", ""),
            "uptime": facts.get("RE0", {}).get("up_time", ""),
            "personality": facts.get("personality", ""),
            "fqdn": facts.get("fqdn", ""),
        }
        dev.close()
        return jsonify(result)
    except (ConnectError, ConnectAuthError, ConnectRefusedError, ConnectTimeoutError) as e:
        return _error_response(f"Connection failed: {e}", 502)
    except Exception as e:
        return _error_response(f"Unexpected error: {e}", 500)


@bridge.route("/devices/<name>/unlock", methods=["POST"])
def unlock_config(name):
    """Clear any stale configuration lock on the device.

    Useful when a previous session left a lock behind.  Connects, rolls back
    the candidate to discard uncommitted edits, and closes cleanly.
    """
    dev_dict, _ = _find_device(name)
    if not dev_dict:
        return _error_response(f"Device '{name}' not found.", 404)

    dev = None
    try:
        dev = _connect(dev_dict)
        cu = Config(dev)
        # rollback discards candidate changes; no lock required
        try:
            cu.rollback(0)
        except Exception:
            pass
        # unlock releases the lock if this session holds it
        try:
            cu.unlock()
        except UnlockError:
            pass
        dev.close()
        return jsonify({"ok": True, "message": "Lock cleared (if any)."})
    except (ConnectError, ConnectAuthError, ConnectRefusedError, ConnectTimeoutError) as e:
        return _error_response(f"Connection failed: {e}", 502)
    except Exception as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Unlock failed: {e}", 500)


def _acquire_lock(dev_dict, cu, dev):
    """Try to lock the candidate config.  On LockError, reconnect and retry once."""
    try:
        cu.lock()
        return cu, dev
    except LockError:
        # Previous session may have left a stale lock.
        # Close this connection (which releases any lock *we* hold),
        # wait briefly, reconnect, and try once more.
        print("  Lock failed — retrying after reconnect...")
        try:
            cu.rollback(0)
        except Exception:
            pass
        try:
            cu.unlock()
        except Exception:
            pass
        try:
            dev.close()
        except Exception:
            pass
        time.sleep(2)
        dev = _connect(dev_dict)
        cu = Config(dev)
        cu.lock()          # If this also fails, LockError propagates to caller
        return cu, dev


@bridge.route("/devices/<name>/load", methods=["POST"])
def load_config(name):
    """Load configuration into candidate configuration."""
    dev_dict, _ = _find_device(name)
    if not dev_dict:
        return _error_response(f"Device '{name}' not found.", 404)

    data = request.get_json(silent=True)
    if not data or not data.get("config"):
        return _error_response("Request body must include 'config' field.")

    fmt = data.get("format", "set")
    if fmt not in ("set", "xml", "text"):
        return _error_response("Format must be 'set', 'xml', or 'text'.")

    config_text = data["config"]
    # Strip comment lines and blanks for set format — NETCONF rejects non-command lines
    if fmt == "set":
        lines = [l for l in config_text.splitlines() if l.strip() and not l.strip().startswith("#")]
        config_text = "\n".join(lines)
    if not config_text.strip():
        return _error_response("Configuration is empty after filtering.")

    dev = None
    locked = False
    try:
        dev = _connect(dev_dict)
        cu = Config(dev)
        cu, dev = _acquire_lock(dev_dict, cu, dev)
        locked = True

        # First try loading the full config at once
        try:
            cu.load(config_text, format=fmt)
            cu.unlock()
            locked = False
            dev.close()
            total = len(config_text.splitlines())
            return jsonify({"ok": True, "message": f"Configuration loaded ({total} lines)."})
        except ConfigLoadError:
            cu.rollback()  # Clean slate for line-by-line

        # Batch load failed — fall back to line-by-line for set format
        if fmt != "set":
            cu.unlock()
            locked = False
            dev.close()
            return _error_response("Configuration load failed. Check syntax.", 400)

        errors = []
        loaded = 0
        skipped = 0
        for i, line in enumerate(config_text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                cu.load(line, format="set")
                loaded += 1
            except ConfigLoadError as e:
                skipped += 1
                msg = str(e).split("\n")[0][:200] if str(e) else "syntax error"
                errors.append({"line": i, "command": line[:120], "message": msg})
                print(f"  Line {i} SKIP: {line[:80]}")
                print(f"    Error: {msg}")

        cu.unlock()
        locked = False
        dev.close()

        if loaded == 0:
            return _error_response(
                f"All {skipped} lines failed to load.",
                400,
                details=errors[:50],
            )

        return jsonify({
            "ok": True,
            "message": f"Loaded {loaded} commands, skipped {skipped} with errors.",
            "warnings": errors[:50] if errors else None,
            "loaded": loaded,
            "skipped": skipped,
        })
    except LockError:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(
            "Could not lock configuration after retry. "
            "Another CLI/NETCONF session may hold the lock. "
            "Try 'clear system commit' on the device CLI, or use the Unlock button.",
            409,
        )
    except (ConnectError, ConnectAuthError, ConnectRefusedError, ConnectTimeoutError) as e:
        return _error_response(f"Connection failed: {e}", 502)
    except Exception as e:
        # Always try to unlock + close on unexpected errors
        if dev:
            if locked:
                try:
                    Config(dev).unlock()
                except Exception:
                    pass
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Unexpected error: {e}", 500)


@bridge.route("/devices/<name>/diff", methods=["GET"])
def config_diff(name):
    """Show candidate vs active configuration diff."""
    dev_dict, _ = _find_device(name)
    if not dev_dict:
        return _error_response(f"Device '{name}' not found.", 404)

    dev = None
    try:
        dev = _connect(dev_dict)
        cu = Config(dev)
        diff = cu.diff() or ""
        dev.close()
        return jsonify({"ok": True, "diff": diff})
    except (ConnectError, ConnectAuthError, ConnectRefusedError, ConnectTimeoutError) as e:
        return _error_response(f"Connection failed: {e}", 502)
    except Exception as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Unexpected error: {e}", 500)


@bridge.route("/devices/<name>/commit-check", methods=["POST"])
def commit_check(name):
    """Dry-run commit check — validates candidate without applying."""
    dev_dict, _ = _find_device(name)
    if not dev_dict:
        return _error_response(f"Device '{name}' not found.", 404)

    dev = None
    try:
        dev = _connect(dev_dict)
        cu = Config(dev)
        cu.commit_check()
        dev.close()
        return jsonify({"ok": True, "message": "Commit check passed."})
    except CommitError as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        errors = []
        if hasattr(e, "errs") and e.errs:
            for err in e.errs:
                errors.append({
                    "message": err.get("message", str(err)),
                    "severity": err.get("severity", "error"),
                })
        else:
            errors.append({"message": str(e), "severity": "error"})
        return jsonify({"ok": False, "errors": errors})
    except (ConnectError, ConnectAuthError, ConnectRefusedError, ConnectTimeoutError) as e:
        return _error_response(f"Connection failed: {e}", 502)
    except Exception as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Unexpected error: {e}", 500)


@bridge.route("/devices/<name>/commit", methods=["POST"])
def commit(name):
    """Commit the candidate configuration."""
    dev_dict, _ = _find_device(name)
    if not dev_dict:
        return _error_response(f"Device '{name}' not found.", 404)

    data = request.get_json(silent=True) or {}
    comment = data.get("comment", "")
    confirm_minutes = data.get("confirm_minutes")

    dev = None
    try:
        dev = _connect(dev_dict)
        cu = Config(dev)

        kwargs = {}
        if comment:
            kwargs["comment"] = comment
        if confirm_minutes and int(confirm_minutes) > 0:
            kwargs["confirm"] = int(confirm_minutes)

        cu.commit(**kwargs)
        dev.close()

        msg = "Configuration committed successfully."
        if confirm_minutes and int(confirm_minutes) > 0:
            msg = (
                f"Configuration committed with {confirm_minutes}-minute confirm timer. "
                f"Run 'confirm' within {confirm_minutes} minutes or the device will auto-rollback."
            )
        return jsonify({"ok": True, "message": msg, "confirm_active": bool(confirm_minutes)})
    except CommitError as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Commit failed: {e}", 400, details=str(e))
    except (ConnectError, ConnectAuthError, ConnectRefusedError, ConnectTimeoutError) as e:
        return _error_response(f"Connection failed: {e}", 502)
    except Exception as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Unexpected error: {e}", 500)


@bridge.route("/devices/<name>/confirm", methods=["POST"])
def confirm_commit(name):
    """Confirm a pending commit-confirm (cancel the auto-rollback timer)."""
    dev_dict, _ = _find_device(name)
    if not dev_dict:
        return _error_response(f"Device '{name}' not found.", 404)

    dev = None
    try:
        dev = _connect(dev_dict)
        cu = Config(dev)
        cu.commit()  # A bare commit after commit-confirm confirms it
        dev.close()
        return jsonify({"ok": True, "message": "Commit confirmed. Auto-rollback cancelled."})
    except CommitError as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Confirm failed: {e}", 400, details=str(e))
    except (ConnectError, ConnectAuthError, ConnectRefusedError, ConnectTimeoutError) as e:
        return _error_response(f"Connection failed: {e}", 502)
    except Exception as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Unexpected error: {e}", 500)


@bridge.route("/devices/<name>/rollback", methods=["POST"])
def rollback(name):
    """Rollback the candidate configuration to the last committed state."""
    dev_dict, _ = _find_device(name)
    if not dev_dict:
        return _error_response(f"Device '{name}' not found.", 404)

    data = request.get_json(silent=True) or {}
    rollback_id = data.get("id", 0)

    dev = None
    try:
        dev = _connect(dev_dict)
        cu = Config(dev)
        cu.rollback(int(rollback_id))
        cu.commit(comment="Rollback via PyEZ Bridge")
        dev.close()
        return jsonify({"ok": True, "message": f"Rolled back to configuration {rollback_id}."})
    except (CommitError, RpcError) as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Rollback failed: {e}", 400, details=str(e))
    except (ConnectError, ConnectAuthError, ConnectRefusedError, ConnectTimeoutError) as e:
        return _error_response(f"Connection failed: {e}", 502)
    except Exception as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Unexpected error: {e}", 500)


# ---------------------------------------------------------------------------
# Pull Config (GET running config from device)
# ---------------------------------------------------------------------------

@bridge.route("/devices/<name>/pull-config", methods=["GET"])
def pull_config(name):
    """Pull the running configuration from an SRX device via NETCONF.

    Query params:
      format: 'set' (default) or 'xml'

    Returns the full configuration as a text string that can be pasted
    directly into the Firewall Intent Converter input panel.
    """
    dev_dict, _ = _find_device(name)
    if not dev_dict:
        return _error_response(f"Device '{name}' not found.", 404)

    fmt = request.args.get("format", "set").lower()
    if fmt not in ("set", "xml", "text"):
        return _error_response("format must be 'set', 'xml', or 'text'.", 400)

    dev = None
    try:
        dev = _connect(dev_dict)

        if fmt == "set":
            # 'display set' returns set-format commands
            rpc_reply = dev.rpc.get_config(options={"format": "set"})
            # etree element — extract text from <configuration-set>
            config_text = rpc_reply.text or ""
            if not config_text:
                from lxml import etree
                config_text = etree.tostring(rpc_reply, encoding="unicode")
        elif fmt == "xml":
            rpc_reply = dev.rpc.get_config(options={"format": "xml"})
            from lxml import etree
            config_text = etree.tostring(rpc_reply, pretty_print=True, encoding="unicode")
        else:
            rpc_reply = dev.rpc.get_config(options={"format": "text"})
            config_text = rpc_reply.text or ""

        dev.close()
        dev = None

        return jsonify({
            "ok": True,
            "config": config_text,
            "format": fmt,
            "hostname": dev_dict.get("name", name),
            "host": dev_dict.get("host", ""),
        })

    except (ConnectError, ConnectAuthError, ConnectRefusedError, ConnectTimeoutError) as e:
        return _error_response(f"Connection failed: {e}", 502)
    except RpcError as e:
        return _error_response(f"RPC error: {e}", 400, details=str(e))
    except Exception as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Unexpected error: {e}", 500)


# ---------------------------------------------------------------------------
# Pull Policy Hit Counts
# ---------------------------------------------------------------------------

@bridge.route("/devices/<name>/policy-stats", methods=["GET"])
def policy_stats(name):
    """Pull security policy hit count statistics from an SRX device.

    Uses: show security policies statistics detail
    Returns a list of policy stats with hit counts, last-hit timestamps, etc.
    """
    dev_dict, _ = _find_device(name)
    if not dev_dict:
        return _error_response(f"Device '{name}' not found.", 404)

    dev = None
    try:
        dev = _connect(dev_dict)

        # Run the RPC for security policy statistics
        rpc_reply = dev.rpc.cli("show security policies statistics detail", format="text")
        raw_output = rpc_reply.text or ""

        dev.close()
        dev = None

        # Parse the text output into structured data
        policies = []
        current_policy = None

        for line in raw_output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Policy header: "Policy: <name>, State: enabled, Index: <n>"
            if line.startswith("Policy:"):
                if current_policy:
                    policies.append(current_policy)
                parts = line.split(",")
                policy_name = parts[0].replace("Policy:", "").strip()
                current_policy = {
                    "name": policy_name,
                    "hit_count": 0,
                    "session_count": 0,
                    "byte_count": 0,
                    "last_hit": None,
                }
                continue

            if current_policy:
                if "Session count" in line:
                    try:
                        current_policy["session_count"] = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                elif "Policy count" in line or "Hit count" in line:
                    try:
                        current_policy["hit_count"] = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                elif "Byte count" in line:
                    try:
                        current_policy["byte_count"] = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass

        if current_policy:
            policies.append(current_policy)

        return jsonify({
            "ok": True,
            "policies": policies,
            "count": len(policies),
            "raw_output": raw_output[:10000],  # Cap raw output at 10KB
        })

    except (ConnectError, ConnectAuthError, ConnectRefusedError, ConnectTimeoutError) as e:
        return _error_response(f"Connection failed: {e}", 502)
    except RpcError as e:
        return _error_response(f"RPC error: {e}", 400, details=str(e))
    except Exception as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Unexpected error: {e}", 500)


# ---------------------------------------------------------------------------
# App Usage — Per-policy hit counts + active sessions by application
# ---------------------------------------------------------------------------

@bridge.route("/devices/<name>/app-usage", methods=["GET"])
def app_usage(name):
    """Pull per-policy hit counts and active sessions grouped by application.

    Runs two RPCs:
      1. show security policies hit-count  — per-policy hit counts with zone context
      2. show security flow session summary — active sessions grouped by application

    If either RPC fails, partial results are returned with an ``errors`` list.
    """
    dev_dict, _ = _find_device(name)
    if not dev_dict:
        return _error_response(f"Device '{name}' not found.", 404)

    dev = None
    errors = []
    policies = []
    app_sessions = []

    try:
        dev = _connect(dev_dict)

        # ------------------------------------------------------------------ #
        # RPC 1: show security policies hit-count
        # ------------------------------------------------------------------ #
        try:
            rpc_reply = dev.rpc.cli("show security policies hit-count", format="text")
            raw_hit = rpc_reply.text or ""

            for line in raw_hit.split("\n"):
                stripped = line.strip()
                # Skip blank lines, section headers, and dashes
                if not stripped:
                    continue
                if any(kw in stripped for kw in ("Logical system", "Index", "---")):
                    continue

                # Data lines: Index  From-zone  To-zone  Name  Count
                parts = stripped.split()
                if len(parts) < 5:
                    continue
                try:
                    int(parts[0])  # first field must be numeric index
                except ValueError:
                    continue

                policies.append({
                    "name": parts[3],
                    "from_zone": parts[1],
                    "to_zone": parts[2],
                    "hit_count": int(parts[4]),
                    "session_count": 0,
                    "byte_count": 0,
                })
        except Exception as exc:
            errors.append(f"hit-count RPC failed: {exc}")

        # ------------------------------------------------------------------ #
        # RPC 2: show security flow session summary
        # ------------------------------------------------------------------ #
        try:
            rpc_reply2 = dev.rpc.cli("show security flow session summary", format="text")
            raw_summary = rpc_reply2.text or ""

            in_app_section = False
            for line in raw_summary.split("\n"):
                if not in_app_section:
                    if "Session count by application" in line:
                        in_app_section = True
                    continue

                # Exit on blank line after section starts
                stripped = line.strip()
                if not stripped:
                    break

                parts = stripped.split()
                if len(parts) < 2:
                    continue
                try:
                    session_count = int(parts[-1])
                except ValueError:
                    continue

                app_sessions.append({
                    "application": parts[0],
                    "sessions": session_count,
                })
        except Exception as exc:
            errors.append(f"flow session summary RPC failed: {exc}")

        dev.close()
        dev = None

        response = {
            "ok": True,
            "policies": policies,
            "app_sessions": app_sessions,
            "policy_count": len(policies),
            "app_count": len(app_sessions),
        }
        if errors:
            response["errors"] = errors

        return jsonify(response)

    except (ConnectError, ConnectAuthError, ConnectRefusedError, ConnectTimeoutError) as e:
        return _error_response(f"Connection failed: {e}", 502)
    except RpcError as e:
        return _error_response(f"RPC error: {e}", 400, details=str(e))
    except Exception as e:
        if dev:
            try:
                dev.close()
            except Exception:
                pass
        return _error_response(f"Unexpected error: {e}", 500)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv=None):
    """Validate local-only startup options and run the bridge."""
    parser = argparse.ArgumentParser(description="PyEZ Bridge — REST API for SRX device management")
    parser.add_argument("--port", type=int, default=8830, help="Port to listen on (default: 8830)")
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Numeric loopback address to bind to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--allow-origin",
        action="append",
        default=None,
        help="Exact browser origin to allow; repeat for multiple origins",
    )
    args = parser.parse_args(argv)

    try:
        bind_address = validate_loopback_bind(args.bind)
        allowed_origins = parse_allowed_origins(
            args.allow_origin,
            os.environ.get("PYEZ_BRIDGE_ALLOWED_ORIGINS"),
        )
        runnable_app = create_app(
            {
                "BRIDGE_TOKEN": os.environ.get("PYEZ_BRIDGE_TOKEN"),
                "BRIDGE_ALLOWED_ORIGINS": allowed_origins,
            }
        )
    except ValueError as exc:
        parser.error(str(exc))

    print(f"PyEZ Bridge starting on {bind_address}:{args.port}")
    print(f"Device config: {DEVICES_FILE}")
    print(f"Devices configured: {len(_load_devices())}")
    print(f"Allowed browser origins: {', '.join(allowed_origins)}")
    if runnable_app.config["BRIDGE_TOKEN_GENERATED"]:
        print("Bridge access token (valid for this run):")
        print(runnable_app.config["BRIDGE_TOKEN"])
    else:
        print("Bridge access token loaded from PYEZ_BRIDGE_TOKEN.")
    runnable_app.run(host=bind_address, port=args.port, debug=False)


if __name__ == "__main__":
    main()
else:
    app = create_app()
