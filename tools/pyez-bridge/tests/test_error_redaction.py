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
    RpcError,
)


TOKEN = "redaction-bridge-token-with-32-characters"
ALLOWED_ORIGIN = "http://localhost:5173"
# diff/commit-check/commit don't reconnect — they run on the device's live
# load session (a private candidate only exists on the connection that
# opened it), so they're tested separately below.
ALWAYS_RECONNECTS_ROUTES = (
    ("get", "/devices/edge/facts", None),
    ("post", "/devices/edge/unlock", {}),
    (
        "post",
        "/devices/edge/load",
        {"format": "set", "config": "set system host-name edge"},
    ),
    ("post", "/devices/edge/confirm", {}),
    ("post", "/devices/edge/rollback", {"rollback_id": 0}),
    ("get", "/devices/edge/pull-config", None),
    ("get", "/devices/edge/policy-stats", None),
    ("get", "/devices/edge/app-usage", None),
)
SESSION_REQUIRED_ROUTES = (
    ("get", "/devices/edge/diff", None),
    ("post", "/devices/edge/commit-check", {}),
    ("post", "/devices/edge/commit", {"comment": "safe"}),
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
        self.addCleanup(app_module._load_sessions.clear)
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
        for method, path, payload in ALWAYS_RECONNECTS_ROUTES:
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
        for method, path, payload in ALWAYS_RECONNECTS_ROUTES:
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

    def test_session_required_routes_fail_closed_without_a_session(self):
        for method, path, payload in SESSION_REQUIRED_ROUTES:
            with self.subTest(method=method, path=path):
                with patch.object(app_module, "_connect") as connect_mock:
                    response, captured = self.request_with_captured_output(
                        method, path, payload
                    )
                self.assertEqual(response.status_code, 409)
                self.assertFalse(response.get_json()["ok"])
                connect_mock.assert_not_called()
                self.assert_redacted(response, captured)

    def test_session_required_routes_are_redacted_on_device_failure(self):
        for method, path, payload in SESSION_REQUIRED_ROUTES:
            with self.subTest(method=method, path=path):
                device = Mock()
                config = Mock()
                config.diff.side_effect = RpcError(
                    cmd=PRIVATE_MESSAGE,
                    errs=[{"message": PRIVATE_MESSAGE, "severity": "error"}],
                )
                config.commit_check.side_effect = CommitError(
                    None, errs=[{"message": PRIVATE_MESSAGE, "severity": "error"}]
                )
                config.commit.side_effect = CommitError(
                    None, errs=[{"message": PRIVATE_MESSAGE, "severity": "error"}]
                )
                session = app_module._LoadSession(device, config)
                if path.endswith("/commit"):
                    session.checked = True
                app_module._store_session("edge", session)

                response, captured = self.request_with_captured_output(
                    method, path, payload
                )
                self.assertEqual(response.status_code, 502)
                self.assertEqual(
                    response.get_json()["code"], "DEVICE_OPERATION_FAILED"
                )
                self.assert_redacted(response, captured)
                device.close.assert_called_once_with()
                self.assertIsNone(app_module._get_session("edge"))

    def test_unexpected_validator_failure_is_stable_and_redacted(self):
        with patch.object(
            app_module,
            "validate_config_payload",
            side_effect=RuntimeError(PRIVATE_MESSAGE),
        ):
            response, captured = self.request_with_captured_output(
                "post",
                "/devices/edge/load",
                {"format": "set", "config": "set system host-name edge"},
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.get_json(),
            {
                "ok": False,
                "error": "An unexpected bridge error occurred.",
                "code": "UNEXPECTED_ERROR",
            },
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

    def test_load_opens_and_closes_the_private_candidate_on_failure(self):
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
        config.rpc.open_configuration.assert_called_once_with(private=True)
        config.rpc.close_configuration.assert_called_once_with()
        device.close.assert_called_once_with()
        self.assert_redacted(response, captured)

    def test_confirm_unsupported_on_private_never_echoes_device_text(self):
        device = Mock()
        config = Mock()
        config.commit.side_effect = CommitError(
            None,
            errs=[
                {
                    "message": (
                        "commit confirmed not supported for private configuration"
                    ),
                    "severity": "error",
                }
            ],
        )
        session = app_module._LoadSession(device, config)
        session.checked = True
        app_module._store_session("edge", session)

        response, captured = self.request_with_captured_output(
            "post",
            "/devices/edge/commit",
            {"comment": "x", "confirm_minutes": 1},
        )
        body = response.get_json()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(body["code"], "CONFIRM_UNSUPPORTED_ON_PRIVATE")
        # The fixed message text, never the raw Junos rpc-error string.
        public_text = response.get_data(as_text=True) + captured
        self.assertNotIn("commit confirmed not supported for private configuration", public_text)
        self.assert_redacted(response, captured)

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
