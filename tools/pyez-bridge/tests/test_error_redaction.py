"""Endpoint-wide tests for stable, redacted bridge failures."""

import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch


BRIDGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE_DIR))

import app as app_module  # noqa: E402
from app import create_app  # noqa: E402
from connection import DeviceConnectionError  # noqa: E402
from jnpr.junos.exception import (  # noqa: E402
    CommitError,
    ConfigLoadError,
    LockError,
    RpcError,
)


TOKEN = "redaction-bridge-token-with-32-characters"
ALLOWED_ORIGIN = "http://localhost:5173"
ROUTES = (
    ("get", "/devices/edge/facts", None),
    ("post", "/devices/edge/unlock", {}),
    (
        "post",
        "/devices/edge/load",
        {"format": "set", "config": "set system host-name edge"},
    ),
    ("get", "/devices/edge/diff", None),
    ("post", "/devices/edge/commit-check", {}),
    ("post", "/devices/edge/commit", {"comment": "safe"}),
    ("post", "/devices/edge/confirm", {}),
    ("post", "/devices/edge/rollback", {"rollback_id": 0}),
    ("get", "/devices/edge/pull-config", None),
    ("get", "/devices/edge/policy-stats", None),
    ("get", "/devices/edge/app-usage", None),
)
SENTINELS = (
    "SENTINEL_PASSWORD",
    "/home/user/.ssh/SENTINEL_KEY",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "SHA256:SENTINEL_FINGERPRINT",
    "set system root-authentication SENTINEL_COMMAND",
)
PRIVATE_MESSAGE = " ".join(SENTINELS)


def write_inventory(path, text):
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)


class BridgeErrorRedactionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.devices_file = Path(self.temp_dir.name) / "devices.yaml"
        write_inventory(
            self.devices_file,
            "devices:\n"
            "  - name: edge\n"
            "    host: 192.0.2.10\n"
            "    port: 830\n"
            "    username: netops\n"
            "    auth_method: agent\n",
        )
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
            }
        )
        self.client = self.app.test_client()
        self.auth = {"Authorization": f"Bearer {TOKEN}"}

    def request_with_captured_output(self, method, path, payload):
        stdout = StringIO()
        stderr = StringIO()
        kwargs = {"headers": self.auth}
        if payload is not None:
            kwargs["json"] = payload
        with redirect_stdout(stdout), redirect_stderr(stderr):
            response = getattr(self.client, method)(path, **kwargs)
        return response, stdout.getvalue() + stderr.getvalue()

    def assert_redacted(self, response, captured):
        public_text = response.get_data(as_text=True) + captured
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, public_text)

    def test_connection_failures_are_stable_and_redacted_on_every_route(self):
        for method, path, payload in ROUTES:
            with self.subTest(method=method, path=path):
                with patch.object(
                    app_module,
                    "_connect",
                    side_effect=DeviceConnectionError(
                        "DEVICE_IDENTITY_FAILED"
                    ),
                ):
                    response, captured = self.request_with_captured_output(
                        method, path, payload
                    )
                self.assertFalse(200 <= response.status_code < 300)
                self.assertEqual(
                    response.get_json()["code"], "DEVICE_IDENTITY_FAILED"
                )
                self.assert_redacted(response, captured)

    def test_unexpected_failures_are_stable_and_redacted_on_every_route(self):
        for method, path, payload in ROUTES:
            with self.subTest(method=method, path=path):
                with patch.object(
                    app_module,
                    "_connect",
                    side_effect=RuntimeError(PRIVATE_MESSAGE),
                ):
                    response, captured = self.request_with_captured_output(
                        method, path, payload
                    )
                self.assertFalse(200 <= response.status_code < 300)
                self.assertEqual(
                    response.get_json()["code"], "UNEXPECTED_ERROR"
                )
                self.assert_redacted(response, captured)

    def test_non_object_json_is_rejected_without_tracebacks_or_reflection(self):
        for path in (
            "/devices/edge/load",
            "/devices/edge/commit",
            "/devices/edge/rollback",
        ):
            with self.subTest(path=path):
                response, captured = self.request_with_captured_output(
                    "post", path, [PRIVATE_MESSAGE]
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.content_type, "application/json")
                self.assertFalse(response.get_json()["ok"])
                self.assert_redacted(response, captured)

    def test_commit_errors_are_operation_failures_without_details(self):
        device = Mock()
        config = Mock()
        config.commit_check.side_effect = CommitError(
            None, errs=[{"message": PRIVATE_MESSAGE, "severity": "error"}]
        )
        with patch.object(app_module, "_connect", return_value=device):
            with patch.object(app_module, "Config", return_value=config):
                response, captured = self.request_with_captured_output(
                    "post", "/devices/edge/commit-check", {}
                )
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()["code"], "DEVICE_OPERATION_FAILED")
        self.assertNotIn("details", response.get_json())
        self.assert_redacted(response, captured)
        device.close.assert_called_once_with()

    def test_config_load_errors_are_operation_failures_without_details(self):
        device = Mock()
        config = Mock()
        config.load.side_effect = ConfigLoadError(
            None, errs=[{"message": PRIVATE_MESSAGE, "severity": "error"}]
        )
        with patch.object(app_module, "_connect", return_value=device):
            with patch.object(app_module, "Config", return_value=config):
                response, captured = self.request_with_captured_output(
                    "post",
                    "/devices/edge/load",
                    {"format": "set", "config": "set system host-name edge"},
                )
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()["code"], "DEVICE_OPERATION_FAILED")
        self.assertNotIn("details", response.get_json())
        self.assert_redacted(response, captured)
        device.close.assert_called_once_with()

    def test_failed_lock_retry_closes_the_replacement_connection(self):
        first_device = Mock()
        retry_device = Mock()
        first_config = Mock()
        retry_config = Mock()
        first_config.lock.side_effect = LockError(None)
        retry_config.lock.side_effect = LockError(None)
        with patch.object(
            app_module,
            "_connect",
            side_effect=(first_device, retry_device),
        ):
            with patch.object(
                app_module,
                "Config",
                side_effect=(first_config, retry_config),
            ):
                with patch.object(app_module.time, "sleep"):
                    response, captured = self.request_with_captured_output(
                        "post",
                        "/devices/edge/load",
                        {
                            "format": "set",
                            "config": "set system host-name edge",
                        },
                    )
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()["code"], "DEVICE_OPERATION_FAILED")
        self.assert_redacted(response, captured)
        self.assertTrue(first_device.close.called)
        retry_device.close.assert_called_once_with()

    def test_rpc_errors_are_operation_failures_without_details(self):
        device = Mock()
        device.rpc.get_config.side_effect = RpcError(
            cmd=PRIVATE_MESSAGE,
            errs=[{"message": PRIVATE_MESSAGE, "severity": "error"}],
        )
        with patch.object(app_module, "_connect", return_value=device):
            response, captured = self.request_with_captured_output(
                "get", "/devices/edge/pull-config", None
            )
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()["code"], "DEVICE_OPERATION_FAILED")
        self.assertNotIn("details", response.get_json())
        self.assert_redacted(response, captured)
        device.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
