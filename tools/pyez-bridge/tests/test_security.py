"""Security-policy tests for the local PyEZ bridge."""

import sys
import unittest
from pathlib import Path

from flask import Flask, jsonify, request


BRIDGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE_DIR))

from security import (  # noqa: E402
    DEFAULT_ALLOWED_ORIGINS,
    WindowRateLimiter,
    install_security,
    parse_allowed_origins,
    resolve_token,
    validate_loopback_bind,
)


TOKEN = "test-bridge-token-value-with-32-characters"
ALLOWED_ORIGIN = "http://localhost:5173"


class SecurityConfigurationTests(unittest.TestCase):
    def test_accepts_ipv4_and_ipv6_loopback_bind_addresses(self):
        self.assertEqual(validate_loopback_bind("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_loopback_bind("127.42.0.9"), "127.42.0.9")
        self.assertEqual(validate_loopback_bind("::1"), "::1")

    def test_rejects_non_loopback_and_hostname_bind_values(self):
        for value in (
            "0.0.0.0",
            "::",
            "192.0.2.10",
            "localhost",
            "example.com",
            "",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_loopback_bind(value)

    def test_defaults_to_exact_local_vite_origins(self):
        self.assertEqual(
            parse_allowed_origins(None, None),
            list(DEFAULT_ALLOWED_ORIGINS),
        )

    def test_merges_cli_and_environment_origins_without_duplicates(self):
        self.assertEqual(
            parse_allowed_origins(
                ["https://ui.example.test", "http://localhost:5173"],
                "https://other.example.test, https://ui.example.test",
            ),
            [
                "https://ui.example.test",
                "http://localhost:5173",
                "https://other.example.test",
            ],
        )

    def test_rejects_origins_that_are_not_exact_http_origins(self):
        for value in (
            "*",
            "null",
            "https://user@example.test",
            "https://user:pass@example.test",
            "https://example.test/path",
            "https://example.test?query=yes",
            "https://example.test/#fragment",
            "file:///tmp/index.html",
            "https://example.test/",
            "https://example.test:443",
            "HTTPS://example.test",
            "https://EXAMPLE.test",
            "",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_allowed_origins([value], None)

    def test_accepts_explicit_http_and_https_origins_with_nondefault_ports(self):
        self.assertEqual(
            parse_allowed_origins(
                ["http://localhost:4173", "https://converter.example.test:8443"],
                None,
            ),
            ["http://localhost:4173", "https://converter.example.test:8443"],
        )

    def test_rejects_short_or_blank_configured_tokens(self):
        for value in ("", " ", "short", "x" * 31):
            with self.subTest(length=len(value)):
                with self.assertRaises(ValueError):
                    resolve_token(value)

    def test_accepts_strong_configured_token_without_replacing_it(self):
        configured = "configured-token-value-with-32-chars"
        token, generated = resolve_token(configured)
        self.assertEqual(token, configured)
        self.assertFalse(generated)

    def test_generates_a_strong_token_when_none_is_configured(self):
        first, first_generated = resolve_token(None)
        second, second_generated = resolve_token(None)
        self.assertTrue(first_generated)
        self.assertTrue(second_generated)
        self.assertGreaterEqual(len(first), 32)
        self.assertGreaterEqual(len(second), 32)
        self.assertNotEqual(first, second)


def make_test_app(limiter=None):
    app = Flask(__name__)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/devices", methods=["GET", "POST"])
    def devices():
        if request.method == "POST":
            request.get_json()
        return jsonify({"ok": True})

    @app.post("/devices/demo/load")
    def load_config():
        request.get_json()
        return jsonify({"ok": True})

    install_security(app, TOKEN, [ALLOWED_ORIGIN], limiter=limiter)
    app.config["TESTING"] = True
    return app


class RequestSecurityTests(unittest.TestCase):
    def setUp(self):
        self.app = make_test_app()
        self.client = self.app.test_client()
        self.auth = {"Authorization": f"Bearer {TOKEN}"}

    def test_health_is_public_but_device_routes_require_authentication(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        response = self.client.get("/devices")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.get_json(),
            {"ok": False, "error": "Authentication required."},
        )

    def test_accepts_the_exact_bearer_token(self):
        response = self.client.get("/devices", headers=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"ok": True})

    def test_malformed_and_incorrect_credentials_have_the_same_response(self):
        expected = None
        for authorization in (
            "",
            "Basic abc123",
            "Bearer",
            "bearer " + TOKEN,
            "Bearer wrong-token-value-with-32-characters",
            f"Bearer {TOKEN} extra",
        ):
            with self.subTest(authorization=authorization):
                headers = {"Authorization": authorization} if authorization else {}
                response = self.client.get("/devices", headers=headers)
                self.assertEqual(response.status_code, 401)
                body = response.get_json()
                if expected is None:
                    expected = body
                self.assertEqual(body, expected)

    def test_approved_preflight_allows_only_required_headers_and_origin(self):
        response = self.client.options(
            "/devices",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("Access-Control-Allow-Origin"), ALLOWED_ORIGIN
        )
        allow_headers = response.headers.get("Access-Control-Allow-Headers", "")
        self.assertIn("Authorization", allow_headers)
        self.assertIn("Content-Type", allow_headers)
        self.assertNotEqual(response.headers.get("Access-Control-Allow-Origin"), "*")
        self.assertNotEqual(
            response.headers.get("Access-Control-Allow-Credentials"), "true"
        )

    def test_unapproved_and_opaque_origins_receive_no_cors_permission(self):
        for origin in ("https://evil.example", "null"):
            with self.subTest(origin=origin):
                response = self.client.options(
                    "/devices",
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                        "Access-Control-Request-Headers": "Authorization",
                    },
                )
                self.assertNotIn("Access-Control-Allow-Origin", response.headers)

    def test_allowed_actual_request_has_exact_cors_origin(self):
        response = self.client.get(
            "/devices",
            headers={**self.auth, "Origin": ALLOWED_ORIGIN},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("Access-Control-Allow-Origin"), ALLOWED_ORIGIN
        )

    def test_request_body_larger_than_ten_mib_is_rejected(self):
        response = self.client.post(
            "/devices/demo/load",
            headers=self.auth,
            data=b"x" * ((10 * 1024 * 1024) + 1),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 413)

    def test_read_rate_limit_returns_retry_after(self):
        client = make_test_app(
            WindowRateLimiter(read_limit=2, mutation_limit=10)
        ).test_client()
        self.assertEqual(client.get("/devices", headers=self.auth).status_code, 200)
        self.assertEqual(client.get("/devices", headers=self.auth).status_code, 200)
        limited = client.get("/devices", headers=self.auth)
        self.assertEqual(limited.status_code, 429)
        self.assertGreaterEqual(int(limited.headers["Retry-After"]), 1)

    def test_mutation_rate_limit_is_separate_from_reads(self):
        client = make_test_app(
            WindowRateLimiter(read_limit=10, mutation_limit=1)
        ).test_client()
        self.assertEqual(client.get("/devices", headers=self.auth).status_code, 200)
        self.assertEqual(
            client.post("/devices", headers=self.auth, json={}).status_code,
            200,
        )
        limited = client.post("/devices", headers=self.auth, json={})
        self.assertEqual(limited.status_code, 429)

    def test_health_and_preflights_do_not_consume_rate_limit(self):
        client = make_test_app(
            WindowRateLimiter(read_limit=1, mutation_limit=1)
        ).test_client()
        for _ in range(5):
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(
                client.options(
                    "/devices",
                    headers={
                        "Origin": ALLOWED_ORIGIN,
                        "Access-Control-Request-Method": "GET",
                    },
                ).status_code,
                200,
            )
        self.assertEqual(client.get("/devices", headers=self.auth).status_code, 200)

    def test_security_headers_are_present_on_success_and_errors(self):
        for response in (
            self.client.get("/health"),
            self.client.get("/devices"),
            self.client.get("/devices", headers=self.auth),
        ):
            with self.subTest(status=response.status_code):
                self.assertEqual(response.headers.get("Cache-Control"), "no-store")
                self.assertEqual(
                    response.headers.get("X-Content-Type-Options"), "nosniff"
                )


if __name__ == "__main__":
    unittest.main()
