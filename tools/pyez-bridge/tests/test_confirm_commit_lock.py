"""Tests for /devices/<name>/confirm failing closed on the shared candidate.

confirm_commit() connects fresh and has no session of its own to reuse (a
commit-confirm was issued in some earlier request), so it must take the
exclusive lock before committing. Junos refuses that lock while another
operator or tool has uncommitted changes in the shared candidate, so
confirming a pending commit-confirm must never commit that unreviewed
config. See MEC-152.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

BRIDGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE_DIR))

import app as app_module  # noqa: E402
from app import create_app  # noqa: E402
from jnpr.junos.exception import CommitError, LockError, UnlockError  # noqa: E402


TOKEN = "confirm-commit-lock-bridge-token-32chr"
ALLOWED_ORIGIN = "http://localhost:5173"


def write_inventory(path, text):
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)


class ConfirmCommitLockTests(unittest.TestCase):
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

    def _confirm(self, dev, config):
        with patch.object(app_module, "_connect", return_value=dev):
            with patch.object(app_module, "Config", return_value=config):
                return self.client.post("/devices/edge/confirm", headers=self.auth)

    def test_lock_failure_fails_closed_without_committing(self):
        """A held lock (shared candidate has someone else's changes) must
        block confirm rather than committing over it."""
        dev = Mock()
        config = Mock()
        config.lock.side_effect = LockError(None)

        response = self._confirm(dev, config)

        body = response.get_json()
        self.assertFalse(body["ok"])
        self.assertEqual(response.status_code, 502)
        config.commit.assert_not_called()

    def test_lock_is_released_after_a_successful_commit(self):
        dev = Mock()
        config = Mock()

        response = self._confirm(dev, config)

        self.assertTrue(response.get_json()["ok"])
        config.lock.assert_called_once_with()
        config.commit.assert_called_once_with()
        config.unlock.assert_called_once_with()
        dev.close.assert_called_once_with()

    def test_lock_is_released_when_commit_itself_fails(self):
        dev = Mock()
        config = Mock()
        config.commit.side_effect = CommitError(
            None, errs=[{"message": "commit failed", "severity": "error"}]
        )

        response = self._confirm(dev, config)

        self.assertFalse(response.get_json()["ok"])
        config.unlock.assert_called_once_with()
        dev.close.assert_called_once_with()

    def test_lock_error_never_attempts_an_unlock(self):
        """We never held the lock, so there is nothing of ours to release —
        an unlock call here would just be a confusing no-op RPC at best."""
        dev = Mock()
        config = Mock()
        config.lock.side_effect = LockError(None)

        self._confirm(dev, config)

        config.unlock.assert_not_called()
        dev.close.assert_called_once_with()

    def test_unlock_failure_after_commit_still_reports_success_and_closes(self):
        dev = Mock()
        config = Mock()
        config.unlock.side_effect = UnlockError(None)

        response = self._confirm(dev, config)

        self.assertTrue(response.get_json()["ok"])
        dev.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
