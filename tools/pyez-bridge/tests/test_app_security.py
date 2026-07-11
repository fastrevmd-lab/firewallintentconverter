"""Integration tests for security on the real PyEZ bridge routes."""

import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch


BRIDGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE_DIR))

import app as app_module  # noqa: E402
from app import create_app  # noqa: E402
from security import WindowRateLimiter  # noqa: E402


TOKEN = "integration-bridge-token-with-32-characters"
ALLOWED_ORIGIN = "http://localhost:5173"


class BridgeApplicationSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.devices_file = Path(self.temp_dir.name) / "devices.yaml"
        self.devices_file.write_text("devices: []\n", encoding="utf-8")
        self.devices_patch = patch.object(
            app_module, "DEVICES_FILE", self.devices_file
        )
        self.devices_patch.start()
        self.addCleanup(self.devices_patch.stop)

        self.app = create_app(
            {
                "TESTING": True,
                "BRIDGE_TOKEN": TOKEN,
                "BRIDGE_ALLOWED_ORIGINS": [ALLOWED_ORIGIN],
                "BRIDGE_RATE_LIMITER": WindowRateLimiter(
                    read_limit=100, mutation_limit=100
                ),
            }
        )
        self.client = self.app.test_client()
        self.auth = {"Authorization": f"Bearer {TOKEN}"}

    def test_factory_records_resolved_security_configuration(self):
        self.assertEqual(self.app.config["BRIDGE_TOKEN"], TOKEN)
        self.assertFalse(self.app.config["BRIDGE_TOKEN_GENERATED"])
        self.assertEqual(
            self.app.config["BRIDGE_ALLOWED_ORIGINS"], [ALLOWED_ORIGIN]
        )

    def test_health_is_public_and_inventory_requires_authentication(self):
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.get_json()["service"], "pyez-bridge")

        self.assertEqual(self.client.get("/devices").status_code, 401)
        inventory = self.client.get("/devices", headers=self.auth)
        self.assertEqual(inventory.status_code, 200)
        self.assertEqual(inventory.get_json(), {"devices": []})

    def test_rejected_request_never_reaches_a_device_connection(self):
        with patch.object(app_module, "_connect") as connect:
            response = self.client.get("/devices/demo/facts")
        self.assertEqual(response.status_code, 401)
        connect.assert_not_called()

    def test_allowed_preflight_and_denied_origin(self):
        allowed = self.client.options(
            "/devices",
            headers={
                "Origin": ALLOWED_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )
        self.assertEqual(
            allowed.headers.get("Access-Control-Allow-Origin"), ALLOWED_ORIGIN
        )

        denied = self.client.options(
            "/devices",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertNotIn("Access-Control-Allow-Origin", denied.headers)

    def test_oversized_device_request_is_rejected_before_parsing(self):
        response = self.client.post(
            "/devices",
            headers=self.auth,
            data=b"x" * ((10 * 1024 * 1024) + 1),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json(),
            {"ok": False, "error": "Request body is too large."},
        )

    def test_load_validation_rejects_before_connect(self):
        self.devices_file.write_text(
            "devices:\n"
            "  - name: edge\n"
            "    host: 127.0.0.1\n"
            "    username: user\n"
            "    password: pass\n",
            encoding="utf-8",
        )
        payloads = (
            {"format": "set", "config": "set system services telnet"},
            {
                "format": "set",
                "config": "set system host-name x\n"
                "set system root-authentication plain-text-password-value x",
            },
            {
                "format": "xml",
                "config": "<configuration><system><services>"
                "<telnet/></services></system></configuration>",
            },
            {"format": "text", "config": "system { host-name edge; }"},
        )
        with patch.object(app_module, "_connect") as connect:
            for payload in payloads:
                with self.subTest(payload=payload):
                    response = self.client.post(
                        "/devices/edge/load",
                        headers=self.auth,
                        json=payload,
                    )
                    self.assertEqual(response.status_code, 400)
                    body = response.get_json()
                    self.assertEqual(
                        body["error"], "Configuration validation failed."
                    )
                    self.assertNotIn(payload["config"], str(body))
        connect.assert_not_called()

    def test_generated_token_is_marked_but_not_returned_by_health(self):
        generated_app = create_app(
            {
                "TESTING": True,
                "BRIDGE_TOKEN": None,
                "BRIDGE_ALLOWED_ORIGINS": [ALLOWED_ORIGIN],
            }
        )
        token = generated_app.config["BRIDGE_TOKEN"]
        self.assertGreaterEqual(len(token), 32)
        self.assertTrue(generated_app.config["BRIDGE_TOKEN_GENERATED"])
        health_body = generated_app.test_client().get("/health").get_json()
        self.assertNotIn(token, str(health_body))

    def test_cli_rejects_non_loopback_before_creating_application(self):
        with patch.object(app_module, "create_app") as factory:
            with redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    app_module.main(["--bind", "0.0.0.0"])
        self.assertEqual(raised.exception.code, 2)
        factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
