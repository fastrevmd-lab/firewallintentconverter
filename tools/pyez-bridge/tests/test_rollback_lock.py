"""Tests for /devices/<name>/rollback failing closed on the shared candidate.

rollback() connects fresh and has no session of its own, so it must take
the exclusive lock before rolling back and committing. Junos refuses that
lock while another operator or tool has uncommitted changes in the shared
candidate, so a rollback must never commit over that unreviewed config. See
MEC-168 (sibling of MEC-152, which fixed the same class of bug in confirm).
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


TOKEN = "rollback-lock-bridge-token-32characters"
ALLOWED_ORIGIN = "http://localhost:5173"


def write_inventory(path, text):
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, 0o600)


class RollbackLockTests(unittest.TestCase):
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

    def _rollback(self, dev, config, rollback_id=0):
        with patch.object(app_module, "_connect", return_value=dev):
            with patch.object(app_module, "Config", return_value=config):
                return self.client.post(
                    "/devices/edge/rollback",
                    headers=self.auth,
                    json={"id": rollback_id},
                )

    def test_lock_failure_fails_closed_without_rolling_back_or_committing(self):
        """A held lock (shared candidate has someone else's changes) must
        block rollback rather than overwriting it. This must fail against
        current main, which never takes a lock and always commits."""
        dev = Mock()
        config = Mock()
        config.lock.side_effect = LockError(None)

        response = self._rollback(dev, config)

        body = response.get_json()
        self.assertFalse(body["ok"])
        self.assertEqual(response.status_code, 502)
        config.rollback.assert_not_called()
        config.commit.assert_not_called()

    def test_lock_error_never_attempts_an_unlock(self):
        dev = Mock()
        config = Mock()
        config.lock.side_effect = LockError(None)

        self._rollback(dev, config)

        config.unlock.assert_not_called()
        dev.close.assert_called_once_with()

    def test_lock_is_released_after_a_successful_rollback_and_commit(self):
        dev = Mock()
        config = Mock()

        response = self._rollback(dev, config, rollback_id=3)

        self.assertTrue(response.get_json()["ok"])
        config.lock.assert_called_once_with()
        config.rollback.assert_called_once_with(3)
        config.commit.assert_called_once_with(comment="Rollback via PyEZ Bridge")
        config.unlock.assert_called_once_with()
        dev.close.assert_called_once_with()

    def test_lock_is_released_when_commit_itself_fails(self):
        dev = Mock()
        config = Mock()
        config.commit.side_effect = CommitError(
            None, errs=[{"message": "commit failed", "severity": "error"}]
        )

        response = self._rollback(dev, config)

        self.assertFalse(response.get_json()["ok"])
        config.unlock.assert_called_once_with()
        dev.close.assert_called_once_with()

    def test_unlock_failure_after_commit_still_reports_success_and_closes(self):
        dev = Mock()
        config = Mock()
        config.unlock.side_effect = UnlockError(None)

        response = self._rollback(dev, config)

        self.assertTrue(response.get_json()["ok"])
        dev.close.assert_called_once_with()

    def test_rejects_string_id_without_connecting(self):
        dev = Mock()
        config = Mock()

        response = self._rollback(dev, config, rollback_id="not-a-number")

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])
        config.lock.assert_not_called()
        dev.close.assert_not_called()

    def test_rejects_negative_id_without_connecting(self):
        dev = Mock()
        config = Mock()

        response = self._rollback(dev, config, rollback_id=-1)

        self.assertEqual(response.status_code, 400)
        config.lock.assert_not_called()
        dev.close.assert_not_called()

    def test_rejects_id_above_range_without_connecting(self):
        dev = Mock()
        config = Mock()

        response = self._rollback(dev, config, rollback_id=50)

        self.assertEqual(response.status_code, 400)
        config.lock.assert_not_called()
        dev.close.assert_not_called()

    def test_accepts_id_at_upper_bound(self):
        dev = Mock()
        config = Mock()

        response = self._rollback(dev, config, rollback_id=49)

        self.assertTrue(response.get_json()["ok"])
        config.rollback.assert_called_once_with(49)


if __name__ == "__main__":
    unittest.main()
