"""Security controls shared by the local PyEZ bridge and its tests."""

import ipaddress
import hmac
import math
import secrets
import threading
import time
from urllib.parse import urlsplit

from flask import jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge


DEFAULT_ALLOWED_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)
MIN_TOKEN_LENGTH = 32
MAX_REQUEST_BYTES = 10 * 1024 * 1024
READ_METHODS = frozenset(("GET", "HEAD", "OPTIONS"))


def validate_loopback_bind(host):
    """Return a validated numeric loopback address or raise ``ValueError``."""
    try:
        address = ipaddress.ip_address(host)
    except (TypeError, ValueError) as exc:
        raise ValueError("Bind address must be a numeric loopback address.") from exc
    if not address.is_loopback:
        raise ValueError("PyEZ Bridge only supports loopback bind addresses.")
    return host


def _validate_origin(origin):
    """Validate and return one exact HTTP(S) browser origin."""
    if not isinstance(origin, str):
        raise ValueError("Allowed origins must be strings.")
    value = origin.strip()
    if not value or value in ("*", "null"):
        raise ValueError("Wildcard and opaque origins are not allowed.")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid allowed origin: {value!r}.") from exc

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Allowed origins must use HTTP or HTTPS.")
    if not parsed.hostname.isascii():
        raise ValueError("Allowed-origin hostnames must use ASCII form.")
    if parsed.username or parsed.password:
        raise ValueError("Allowed origins cannot contain credentials.")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("Allowed origins cannot contain a path, query, or fragment.")
    if (parsed.scheme == "http" and port == 80) or (
        parsed.scheme == "https" and port == 443
    ):
        raise ValueError("Default ports must be omitted from allowed origins.")

    canonical_host = (
        f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    )
    canonical_netloc = (
        f"{canonical_host}:{port}" if port is not None else canonical_host
    )
    canonical = f"{parsed.scheme}://{canonical_netloc}"
    if value != canonical:
        raise ValueError("Allowed origins must use their exact canonical form.")
    return value


def parse_allowed_origins(cli_origins=None, env_value=None):
    """Merge, validate, and de-duplicate exact browser origins."""
    candidates = []
    if cli_origins:
        candidates.extend(cli_origins)
    if env_value:
        candidates.extend(env_value.split(","))
    if not candidates:
        candidates.extend(DEFAULT_ALLOWED_ORIGINS)

    origins = []
    for candidate in candidates:
        origin = _validate_origin(candidate)
        if origin not in origins:
            origins.append(origin)
    return origins


def resolve_token(configured=None):
    """Return ``(token, generated)`` with a strong bearer token."""
    if configured is None:
        return secrets.token_urlsafe(32), True
    if not isinstance(configured, str) or not configured.strip():
        raise ValueError("PYEZ_BRIDGE_TOKEN cannot be blank.")
    if len(configured) < MIN_TOKEN_LENGTH:
        raise ValueError(
            f"PYEZ_BRIDGE_TOKEN must contain at least {MIN_TOKEN_LENGTH} characters."
        )
    return configured, False


class WindowRateLimiter:
    """Thread-safe fixed-window limiter for one local bridge process."""

    def __init__(
        self,
        read_limit=120,
        mutation_limit=30,
        window_seconds=60,
        clock=time.monotonic,
    ):
        if read_limit < 1 or mutation_limit < 1 or window_seconds < 1:
            raise ValueError("Rate limits and window duration must be positive.")
        self.read_limit = read_limit
        self.mutation_limit = mutation_limit
        self.window_seconds = window_seconds
        self.clock = clock
        self._windows = {}
        self._lock = threading.Lock()

    def check(self, key, method):
        """Return ``(allowed, retry_after_seconds)`` for a request."""
        category = "read" if method.upper() in READ_METHODS else "mutation"
        limit = self.read_limit if category == "read" else self.mutation_limit
        window_key = (key, category)
        now = self.clock()

        with self._lock:
            started_at, count = self._windows.get(window_key, (now, 0))
            elapsed = now - started_at
            if elapsed >= self.window_seconds or elapsed < 0:
                started_at, count, elapsed = now, 0, 0

            if count >= limit:
                retry_after = max(1, math.ceil(self.window_seconds - elapsed))
                return False, retry_after

            self._windows[window_key] = (started_at, count + 1)
            return True, 0


def _authentication_failed():
    return jsonify({"ok": False, "error": "Authentication required."}), 401


def install_security(app, token, allowed_origins, limiter=None):
    """Install authentication, CORS, limits, and hardening on ``app``."""
    resolved_token, _ = resolve_token(token)
    origins = parse_allowed_origins(allowed_origins, None)
    rate_limiter = limiter or WindowRateLimiter()

    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
    CORS(
        app,
        origins=origins,
        methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        supports_credentials=False,
        send_wildcard=False,
        vary_header=True,
        always_send=False,
    )

    @app.before_request
    def enforce_bridge_security():
        if request.method == "OPTIONS":
            return None
        if request.method == "GET" and request.path == "/health":
            return None

        authorization = request.headers.get("Authorization", "")
        scheme, separator, credential = authorization.partition(" ")
        if (
            scheme != "Bearer"
            or separator != " "
            or not credential
            or " " in credential
            or not hmac.compare_digest(credential, resolved_token)
        ):
            return _authentication_failed()

        source = request.remote_addr or "unknown"
        allowed, retry_after = rate_limiter.check(source, request.method)
        if not allowed:
            response = jsonify(
                {"ok": False, "error": "Request rate limit exceeded."}
            )
            response.status_code = 429
            response.headers["Retry-After"] = str(retry_after)
            return response
        return None

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        return jsonify({"ok": False, "error": "Request body is too large."}), 413

    @app.after_request
    def add_security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
