"""Integration tests for security on the real PyEZ bridge routes."""

import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
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


def write_inventory(path, text):
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)


class BridgeApplicationSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.devices_file = Path(self.temp_dir.name) / "devices.yaml"
        write_inventory(self.devices_file, "devices: []\n")
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

    def test_health_reports_strict_host_key_verification(self):
        body = self.client.get("/health").get_json()
        self.assertEqual(body["host_key_verification"], "strict")
        expected_permissions = (
            "enforced" if os.name == "posix" else "unavailable-platform"
        )
        self.assertEqual(
            body["inventory_posix_permissions"], expected_permissions
        )

    def test_device_api_accepts_only_credential_references(self):
        for field in (
            "password",
            "passwd",
            "ssh_key",
            "ssh_private_key_file",
        ):
            with self.subTest(field=field):
                response = self.client.post(
                    "/devices",
                    headers=self.auth,
                    json={
                        "name": f"edge-{field}",
                        "host": "192.0.2.10",
                        "port": 830,
                        "username": "netops",
                        "auth_method": "agent",
                        field: "SENTINEL_SECRET",
                    },
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json()["code"], "INVENTORY_UNSAFE"
                )
                self.assertNotIn(
                    "SENTINEL_SECRET", response.get_data(as_text=True)
                )

    def test_device_api_rejects_invalid_record_shapes_safely(self):
        payloads = (
            ["not-a-record"],
            {
                "name": 7,
                "host": "192.0.2.10",
                "username": "netops",
                "auth_method": "agent",
            },
            {
                "name": "edge",
                "host": {"value": "192.0.2.10"},
                "username": "netops",
                "auth_method": "agent",
            },
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                response = self.client.post(
                    "/devices", headers=self.auth, json=payload
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json()["code"], "INVENTORY_UNSAFE"
                )

    def test_device_api_routes_every_parsed_falsy_record_to_inventory_validation(self):
        for value in ([], False, "", None, {}):
            with self.subTest(value=value):
                response = self.client.post(
                    "/devices",
                    headers=self.auth,
                    data=json.dumps(value),
                    content_type="application/json",
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json(),
                    {
                        "ok": False,
                        "error": "Device inventory is unsafe or invalid.",
                        "code": "INVENTORY_UNSAFE",
                    },
                )

    def test_device_api_keeps_missing_and_invalid_json_errors_constant(self):
        requests = (
            {},
            {"data": "{", "content_type": "application/json"},
        )
        for kwargs in requests:
            with self.subTest(kwargs=kwargs):
                response = self.client.post(
                    "/devices", headers=self.auth, **kwargs
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json(),
                    {"ok": False, "error": "Request body must be JSON."},
                )

    def test_device_list_omits_credential_reference(self):
        write_inventory(
            self.devices_file,
            "devices:\n"
            "  - name: edge\n"
            "    host: 192.0.2.10\n"
            "    port: 830\n"
            "    username: netops\n"
            "    auth_method: password-env\n"
            "    password_env: SENTINEL_PASSWORD_ENV\n",
        )
        response = self.client.get("/devices", headers=self.auth)
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(
            body,
            {
                "devices": [
                    {
                        "name": "edge",
                        "host": "192.0.2.10",
                        "port": 830,
                        "username": "netops",
                        "auth_method": "password-env",
                        "credential_ready": False,
                        "status": "unknown",
                    }
                ]
            },
        )
        self.assertNotIn("password_env", response.get_data(as_text=True))
        self.assertNotIn("SENTINEL_PASSWORD_ENV", response.get_data(as_text=True))

    def test_device_listing_checks_credential_membership_without_value_access(self):
        class MembershipOnlyEnvironment:
            def __contains__(self, key):
                return key == "FIC_EDGE_PASSWORD"

            def get(self, *_args, **_kwargs):
                raise AssertionError("credential value was retrieved with get()")

            def __getitem__(self, _key):
                raise AssertionError("credential value was retrieved")

        device = {
            "name": "edge",
            "host": "192.0.2.10",
            "port": 830,
            "username": "netops",
            "auth_method": "password-env",
            "password_env": "FIC_EDGE_PASSWORD",
        }
        with patch.object(
            app_module.os,
            "environ",
            MembershipOnlyEnvironment(),
        ):
            info = app_module._safe_device_info(device)

        self.assertTrue(info["credential_ready"])
        self.assertNotIn("password_env", info)

    def test_connect_uses_strict_host_key_verification_by_default(self):
        device = {
            "name": "edge",
            "host": "192.0.2.10",
            "port": 830,
            "username": "netops",
            "auth_method": "agent",
        }
        with self.app.app_context():
            with patch.object(app_module, "connect_device") as connect:
                app_module._connect(device)
        connect.assert_called_once_with(device, allow_unknown_hosts=False)

    def test_development_override_is_visible_in_health_and_connection(self):
        override = create_app(
            {
                "TESTING": True,
                "BRIDGE_TOKEN": TOKEN,
                "BRIDGE_ALLOWED_ORIGINS": [ALLOWED_ORIGIN],
                "ALLOW_UNKNOWN_HOSTS": True,
            }
        )
        self.assertEqual(
            override.test_client()
            .get("/health")
            .get_json()["host_key_verification"],
            "disabled-development",
        )
        device = {
            "name": "edge",
            "host": "192.0.2.10",
            "port": 830,
            "username": "netops",
            "auth_method": "agent",
        }
        with override.app_context():
            with patch.object(app_module, "connect_device") as connect:
                app_module._connect(device)
        connect.assert_called_once_with(device, allow_unknown_hosts=True)

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
        write_inventory(
            self.devices_file,
            "devices:\n"
            "  - name: edge\n"
            "    host: 127.0.0.1\n"
            "    username: user\n"
            "    auth_method: agent\n",
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

    def test_load_validation_does_not_reflect_unknown_xml_element_paths(self):
        write_inventory(
            self.devices_file,
            "devices:\n"
            "  - name: edge\n"
            "    host: 127.0.0.1\n"
            "    username: user\n"
            "    auth_method: agent\n",
        )
        sentinel = "SENTINEL_PASSWORD"
        response = self.client.post(
            "/devices/edge/load",
            headers=self.auth,
            json={
                "format": "xml",
                "config": (
                    f"<configuration><{sentinel}/></configuration>"
                ),
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(sentinel, response.get_data(as_text=True))
        self.assertNotIn("path", response.get_json())

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

    def test_cli_flag_enables_only_the_development_host_key_override(self):
        fake_app = unittest.mock.Mock()
        fake_app.config = {
            "BRIDGE_TOKEN_GENERATED": False,
            "BRIDGE_TOKEN": TOKEN,
        }
        stdout = StringIO()
        with patch.object(app_module, "create_app", return_value=fake_app) as factory:
            with patch.object(app_module, "_load_devices", return_value=[]):
                with patch.dict(
                    os.environ,
                    {
                        "PYEZ_BRIDGE_TOKEN": TOKEN,
                        "PYEZ_BRIDGE_ALLOWED_ORIGINS": (
                            "https://sentinel-env-value.example"
                        ),
                    },
                    clear=True,
                ):
                    with redirect_stdout(stdout):
                        app_module.main(["--insecure-allow-unknown-hosts"])
        supplied = factory.call_args.args[0]
        self.assertIs(supplied["ALLOW_UNKNOWN_HOSTS"], True)
        output = stdout.getvalue()
        self.assertIn(app_module.INSECURE_HOST_KEY_WARNING, output)
        self.assertNotIn("sentinel-env-value", output)
        self.assertNotIn("PYEZ_BRIDGE", output)
        self.assertNotIn(str(app_module.DEVICES_FILE), output)
        fake_app.run.assert_called_once_with(
            host="127.0.0.1", port=8830, debug=False
        )


if __name__ == "__main__":
    unittest.main()
