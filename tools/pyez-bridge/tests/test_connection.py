"""Tests for the secure PyEZ NETCONF connection boundary."""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

from ncclient.transport.errors import SSHUnknownHostError
from paramiko import BadHostKeyException


BRIDGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE_DIR))

from jnpr.junos.exception import (  # noqa: E402
    ConnectAuthError,
    ConnectError,
    ConnectRefusedError,
    ConnectTimeoutError,
)
from connection import (  # noqa: E402
    DeviceConnectionError,
    classify_connection_error,
    connect_device,
)


AGENT = {
    "name": "edge",
    "host": "192.0.2.10",
    "port": 830,
    "username": "netops",
    "auth_method": "agent",
}


class ConnectionTests(unittest.TestCase):
    def test_agent_connection_is_strict_and_has_no_explicit_secret(self):
        device = Mock()
        factory = Mock(return_value=device)

        self.assertIs(connect_device(AGENT, device_factory=factory), device)

        kwargs = factory.call_args.kwargs
        self.assertTrue(kwargs["hostkey_verify"])
        self.assertTrue(kwargs["allow_agent"])
        self.assertTrue(kwargs["look_for_keys"])
        self.assertNotIn("passwd", kwargs)
        self.assertNotIn("password", kwargs)
        self.assertNotIn("ssh_private_key_file", kwargs)
        self.assertNotIn("ssh_config", kwargs)
        device.open.assert_called_once_with()
        self.assertEqual(device.timeout, 30)

    def test_password_reference_resolves_only_at_connection_time(self):
        record = {
            **AGENT,
            "auth_method": "password-env",
            "password_env": "FIC_EDGE_PASSWORD",
        }
        original = record.copy()
        factory = Mock(return_value=Mock())

        connect_device(
            record,
            environ={"FIC_EDGE_PASSWORD": "SENTINEL_PASSWORD"},
            device_factory=factory,
        )

        kwargs = factory.call_args.kwargs
        self.assertEqual(kwargs["passwd"], "SENTINEL_PASSWORD")
        self.assertFalse(kwargs["allow_agent"])
        self.assertFalse(kwargs["look_for_keys"])
        self.assertNotIn("password_env", kwargs)
        self.assertEqual(record, original)

    def test_missing_password_reference_fails_before_device_construction(self):
        record = {
            **AGENT,
            "auth_method": "password-env",
            "password_env": "FIC_EDGE_PASSWORD",
        }
        factory = Mock()

        with self.assertRaises(DeviceConnectionError) as raised:
            connect_device(record, environ={}, device_factory=factory)

        factory.assert_not_called()
        self.assertEqual(
            raised.exception.code,
            "DEVICE_CREDENTIAL_UNAVAILABLE",
        )
        self.assertNotIn("FIC_EDGE_PASSWORD", str(raised.exception))

    def test_only_explicit_override_disables_host_key_verification(self):
        factory = Mock(return_value=Mock())

        connect_device(
            AGENT,
            allow_unknown_hosts=True,
            device_factory=factory,
        )

        self.assertFalse(factory.call_args.kwargs["hostkey_verify"])

    def test_non_boolean_override_does_not_disable_host_key_verification(self):
        factory = Mock(return_value=Mock())

        connect_device(
            AGENT,
            allow_unknown_hosts="true",
            device_factory=factory,
        )

        self.assertTrue(factory.call_args.kwargs["hostkey_verify"])

    def test_classification_is_stable_and_redacted(self):
        changed_key = BadHostKeyException(
            "192.0.2.10",
            Mock(get_base64=Mock(return_value="SENTINEL_NEW_KEY")),
            Mock(get_base64=Mock(return_value="SENTINEL_OLD_KEY")),
        )
        cases = (
            (
                SSHUnknownHostError("192.0.2.10", "SHA256:SENTINEL"),
                "DEVICE_IDENTITY_FAILED",
            ),
            (changed_key, "DEVICE_IDENTITY_FAILED"),
            (ConnectAuthError(Mock()), "DEVICE_AUTHENTICATION_FAILED"),
            (ConnectRefusedError(Mock()), "DEVICE_UNREACHABLE"),
            (ConnectTimeoutError(Mock()), "DEVICE_UNREACHABLE"),
            (RuntimeError("SENTINEL_SECRET"), "UNEXPECTED_ERROR"),
        )
        for error, code in cases:
            with self.subTest(code=code, error_type=type(error).__name__):
                classified = classify_connection_error(error)
                self.assertEqual(classified.code, code)
                self.assertNotIn("SENTINEL", str(classified))
                self.assertIsNone(classified.__cause__)
                self.assertIsNone(classified.__context__)

    def test_wrapped_unknown_host_is_an_identity_failure(self):
        unknown = SSHUnknownHostError(
            "192.0.2.10",
            "SHA256:SENTINEL_WRAPPED_FINGERPRINT",
        )
        pyez_wrapper = ConnectError(Mock(), unknown)
        chained_wrapper = RuntimeError("SENTINEL_WRAPPER")
        chained_wrapper.__cause__ = pyez_wrapper

        classified = classify_connection_error(chained_wrapper)

        self.assertEqual(classified.code, "DEVICE_IDENTITY_FAILED")
        self.assertNotIn("SENTINEL", str(classified))

    def test_connection_translation_does_not_retain_private_error_details(self):
        original = SSHUnknownHostError(
            "SENTINEL_HOST",
            "SHA256:SENTINEL_FINGERPRINT",
        )
        pyez_wrapper = ConnectError(Mock(), original)
        device = Mock()
        device.open.side_effect = pyez_wrapper

        with self.assertRaises(DeviceConnectionError) as raised:
            connect_device(AGENT, device_factory=Mock(return_value=device))

        public_error = raised.exception
        self.assertEqual(public_error.code, "DEVICE_IDENTITY_FAILED")
        self.assertNotIn("SENTINEL", str(public_error))
        self.assertIsNone(public_error.__cause__)
        self.assertIsNone(public_error.__context__)


if __name__ == "__main__":
    unittest.main()
