"""Security tests for the local PyEZ device inventory."""

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


BRIDGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BRIDGE_DIR))

import inventory  # noqa: E402
from inventory import (  # noqa: E402
    InventoryError,
    load_devices,
    save_devices,
    validate_device,
)


AGENT_DEVICE = {
    "name": "edge",
    "host": "192.0.2.10",
    "port": 830,
    "username": "netops",
    "auth_method": "agent",
}
REPLACEMENT_DEVICE = {
    **AGENT_DEVICE,
    "name": "replacement",
    "host": "198.51.100.50",
}


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        os.chmod(self.root, 0o700)
        self.path = self.root / "devices.yaml"

    def assert_generic_error(self, operation):
        with self.assertRaises(InventoryError) as raised:
            operation()
        self.assertEqual(raised.exception.code, "INVENTORY_UNSAFE")
        self.assertEqual(
            str(raised.exception),
            "Device inventory is unsafe or invalid.",
        )

    def test_round_trip_is_owner_only_and_secret_free(self):
        save_devices(self.path, [AGENT_DEVICE])
        self.assertEqual(load_devices(self.path), [AGENT_DEVICE])
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        text = self.path.read_text(encoding="utf-8")
        self.assertNotIn("password:", text)
        self.assertNotIn("ssh_key", text)

    def test_rejects_forbidden_and_unknown_authentication_fields(self):
        for field in (
            "password",
            "passwd",
            "ssh_key",
            "ssh_private_key_file",
            "private_key",
            "private_key_file",
            "private_key_material",
            "credential",
        ):
            with self.subTest(field=field):
                with self.assertRaises(InventoryError):
                    validate_device({**AGENT_DEVICE, field: "SENTINEL_SECRET"})

    def test_rejects_private_key_material_in_every_submitted_field(self):
        marker = "-----BEGIN OPENSSH PRIVATE KEY-----"
        password_device = {
            **AGENT_DEVICE,
            "auth_method": "password-env",
            "password_env": "FIC_EDGE_PASSWORD",
        }
        for field in password_device:
            with self.subTest(field=field):
                with self.assertRaises(InventoryError) as raised:
                    validate_device({**password_device, field: marker})
                self.assertNotIn(marker, str(raised.exception))

    def test_password_env_is_a_reference_not_a_value(self):
        expected = {
            **AGENT_DEVICE,
            "auth_method": "password-env",
            "password_env": "FIC_EDGE_PASSWORD",
        }
        self.assertEqual(validate_device(expected), expected)
        for invalid in ("", "lowercase", "1PREFIX", "HAS-DASH", "A" * 129):
            with self.subTest(invalid=invalid):
                with self.assertRaises(InventoryError):
                    validate_device({**expected, "password_env": invalid})

    def test_authentication_fields_must_match_authentication_method(self):
        with self.assertRaises(InventoryError):
            validate_device({**AGENT_DEVICE, "password_env": "FIC_EDGE_PASSWORD"})
        with self.assertRaises(InventoryError):
            validate_device({**AGENT_DEVICE, "auth_method": "password-env"})

    def test_rejects_invalid_required_fields_auth_methods_and_ports(self):
        for field in ("name", "host", "username"):
            for invalid in (None, "", "   "):
                with self.subTest(field=field, invalid=invalid):
                    with self.assertRaises(InventoryError):
                        validate_device({**AGENT_DEVICE, field: invalid})
        for auth_method in (None, "key", "password"):
            with self.subTest(auth_method=auth_method):
                with self.assertRaises(InventoryError):
                    validate_device({**AGENT_DEVICE, "auth_method": auth_method})
        for port in (0, 65536, -1, True, "830"):
            with self.subTest(port=port):
                with self.assertRaises(InventoryError):
                    validate_device({**AGENT_DEVICE, "port": port})

    def test_missing_port_defaults_to_netconf_port(self):
        device = {key: value for key, value in AGENT_DEVICE.items() if key != "port"}
        self.assertEqual(validate_device(device), AGENT_DEVICE)

    def test_rejects_duplicate_names(self):
        with self.assertRaises(InventoryError):
            save_devices(self.path, [AGENT_DEVICE, AGENT_DEVICE])

    @unittest.skipUnless(os.name == "posix", "POSIX metadata is required")
    def test_rejects_wrong_owner_and_unsafe_destination_mode_without_repair(self):
        save_devices(self.path, [AGENT_DEVICE])
        with patch("inventory.os.getuid", return_value=os.getuid() + 1):
            with self.assertRaises(InventoryError):
                load_devices(self.path)
        os.chmod(self.path, 0o644)
        with self.assertRaises(InventoryError):
            load_devices(self.path)
        with self.assertRaises(InventoryError):
            save_devices(self.path, [AGENT_DEVICE])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)

    @unittest.skipUnless(os.name == "posix", "POSIX metadata is required")
    def test_rejects_group_or_world_writable_parent_directories(self):
        for mode in (0o720, 0o702):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.root, mode)
                with self.assertRaises(InventoryError):
                    load_devices(self.path)
                with self.assertRaises(InventoryError):
                    save_devices(self.path, [AGENT_DEVICE])
        os.chmod(self.root, 0o700)

    def test_rejects_parent_symlink(self):
        real_parent = self.root / "real"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.root / "linked"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        linked_path = linked_parent / "devices.yaml"
        with self.assertRaises(InventoryError):
            load_devices(linked_path)
        with self.assertRaises(InventoryError):
            save_devices(linked_path, [AGENT_DEVICE])

    def test_load_rejects_valid_symlink_in_intermediate_ancestor(self):
        real_parent = self.root / "real" / "subdir"
        real_parent.mkdir(parents=True, mode=0o700)
        real_path = real_parent / "devices.yaml"
        save_devices(real_path, [AGENT_DEVICE])
        (self.root / "linked").symlink_to(
            self.root / "real", target_is_directory=True
        )

        linked_path = self.root / "linked" / "subdir" / "devices.yaml"
        with self.assertRaises(InventoryError):
            load_devices(linked_path)

    def test_save_rejects_valid_symlink_in_intermediate_ancestor(self):
        real_parent = self.root / "real" / "subdir"
        real_parent.mkdir(parents=True, mode=0o700)
        (self.root / "linked").symlink_to(
            self.root / "real", target_is_directory=True
        )

        linked_path = self.root / "linked" / "subdir" / "devices.yaml"
        with self.assertRaises(InventoryError):
            save_devices(linked_path, [AGENT_DEVICE])
        self.assertFalse((real_parent / "devices.yaml").exists())

    def test_load_rejects_dangling_symlink_in_intermediate_ancestor(self):
        (self.root / "linked").symlink_to(
            self.root / "missing", target_is_directory=True
        )
        linked_path = self.root / "linked" / "subdir" / "devices.yaml"

        self.assert_generic_error(lambda: load_devices(linked_path))

    def test_save_rejects_dangling_symlink_in_intermediate_ancestor(self):
        (self.root / "linked").symlink_to(
            self.root / "missing", target_is_directory=True
        )
        linked_path = self.root / "linked" / "subdir" / "devices.yaml"

        self.assert_generic_error(
            lambda: save_devices(linked_path, [AGENT_DEVICE])
        )

    @unittest.skipUnless(
        inventory._can_use_secure_dir_fds(),
        "secure dir-fd traversal is unavailable",
    )
    def test_load_keeps_checked_parent_after_ancestor_is_swapped(self):
        checked_parent = self.root / "checked" / "subdir"
        replacement_parent = self.root / "replacement" / "subdir"
        checked_parent.mkdir(parents=True, mode=0o700)
        replacement_parent.mkdir(parents=True, mode=0o700)
        checked_path = checked_parent / "devices.yaml"
        save_devices(checked_path, [AGENT_DEVICE])
        save_devices(replacement_parent / "devices.yaml", [REPLACEMENT_DEVICE])

        checked_ancestor = self.root / "checked"
        detached_ancestor = self.root / "detached"
        real_walk = inventory._walk_parent_with_descriptors

        def walk_then_swap(path):
            result = real_walk(path)
            checked_ancestor.rename(detached_ancestor)
            checked_ancestor.symlink_to(
                self.root / "replacement", target_is_directory=True
            )
            return result

        with patch(
            "inventory._walk_parent_with_descriptors",
            side_effect=walk_then_swap,
        ):
            loaded = load_devices(checked_path)

        self.assertEqual(loaded, [AGENT_DEVICE])
        self.assertEqual(
            load_devices(replacement_parent / "devices.yaml"),
            [REPLACEMENT_DEVICE],
        )

    @unittest.skipUnless(
        inventory._can_use_secure_dir_fds(),
        "secure dir-fd traversal is unavailable",
    )
    def test_save_keeps_checked_parent_after_ancestor_is_swapped(self):
        checked_parent = self.root / "checked" / "subdir"
        replacement_parent = self.root / "replacement" / "subdir"
        checked_parent.mkdir(parents=True, mode=0o700)
        replacement_parent.mkdir(parents=True, mode=0o700)
        checked_path = checked_parent / "devices.yaml"
        replacement_path = replacement_parent / "devices.yaml"
        save_devices(replacement_path, [REPLACEMENT_DEVICE])

        checked_ancestor = self.root / "checked"
        detached_ancestor = self.root / "detached"
        real_walk = inventory._walk_parent_with_descriptors

        def walk_then_swap(path):
            result = real_walk(path)
            checked_ancestor.rename(detached_ancestor)
            checked_ancestor.symlink_to(
                self.root / "replacement", target_is_directory=True
            )
            return result

        with patch(
            "inventory._walk_parent_with_descriptors",
            side_effect=walk_then_swap,
        ):
            save_devices(checked_path, [AGENT_DEVICE])

        self.assertEqual(load_devices(replacement_path), [REPLACEMENT_DEVICE])
        self.assertEqual(
            load_devices(detached_ancestor / "subdir" / "devices.yaml"),
            [AGENT_DEVICE],
        )

    def test_rejects_valid_and_dangling_destination_symlinks(self):
        target = self.root / "target.yaml"
        target.write_text("devices: []\n", encoding="utf-8")
        os.chmod(target, 0o600)
        self.path.symlink_to(target)
        with self.assertRaises(InventoryError):
            load_devices(self.path)
        with self.assertRaises(InventoryError):
            save_devices(self.path, [AGENT_DEVICE])

        self.path.unlink()
        self.path.symlink_to(self.root / "missing.yaml")
        with self.assertRaises(InventoryError):
            load_devices(self.path)
        with self.assertRaises(InventoryError):
            save_devices(self.path, [AGENT_DEVICE])

    @unittest.skipUnless(os.name == "posix", "FIFO support is required")
    def test_rejects_fifo_destination(self):
        os.mkfifo(self.path, mode=0o600)
        with self.assertRaises(InventoryError):
            load_devices(self.path)
        with self.assertRaises(InventoryError):
            save_devices(self.path, [AGENT_DEVICE])

    def test_rejects_non_regular_destination(self):
        self.path.mkdir(mode=0o700)
        with self.assertRaises(InventoryError):
            load_devices(self.path)
        with self.assertRaises(InventoryError):
            save_devices(self.path, [AGENT_DEVICE])

    def test_rejects_oversized_malformed_and_non_mapping_yaml(self):
        self.path.write_bytes(b"x" * ((1024 * 1024) + 1))
        os.chmod(self.path, 0o600)
        with self.assertRaises(InventoryError):
            load_devices(self.path)
        for text in ("devices: [", "- not-a-mapping\n", "devices: {}\n"):
            self.path.write_text(text, encoding="utf-8")
            os.chmod(self.path, 0o600)
            with self.subTest(text=text):
                with self.assertRaises(InventoryError):
                    load_devices(self.path)

    def test_os_yaml_and_unicode_failures_have_generic_messages(self):
        self.path.write_bytes(b"\xff")
        os.chmod(self.path, 0o600)
        self.assert_generic_error(lambda: load_devices(self.path))

        self.path.write_text("devices: [SENTINEL_SECRET", encoding="utf-8")
        os.chmod(self.path, 0o600)
        self.assert_generic_error(lambda: load_devices(self.path))

        with patch("inventory.os.open", side_effect=OSError("SENTINEL_SECRET")):
            self.assert_generic_error(lambda: load_devices(self.path))

    def test_cleans_temporary_file_after_replace_failure(self):
        with patch(
            "inventory.os.replace", side_effect=OSError("SENTINEL_SECRET")
        ):
            with self.assertRaises(InventoryError) as raised:
                save_devices(self.path, [AGENT_DEVICE])
        self.assertNotIn("SENTINEL_SECRET", str(raised.exception))
        self.assertEqual(list(self.root.glob(".devices.yaml.*.tmp")), [])

    def test_closes_and_cleans_temporary_file_after_fchmod_failure(self):
        created_fds = []

        def fail_fchmod(fd, _mode):
            created_fds.append(fd)
            raise OSError("SENTINEL_SECRET")

        def close_leaked_fd():
            if created_fds:
                try:
                    os.close(created_fds[0])
                except OSError:
                    pass

        self.addCleanup(close_leaked_fd)
        with patch("inventory.os.fchmod", side_effect=fail_fchmod):
            self.assert_generic_error(
                lambda: save_devices(self.path, [AGENT_DEVICE])
            )

        with self.assertRaises(OSError):
            os.fstat(created_fds[0])
        self.assertEqual(list(self.root.glob(".devices.yaml.*.tmp")), [])

    @unittest.skipUnless(os.name == "posix", "directory fsync is POSIX-specific")
    def test_atomic_replace_fsyncs_file_and_parent_directory(self):
        synced_types = []
        real_fsync = os.fsync

        def observe_fsync(fd):
            synced_types.append(stat.S_IFMT(os.fstat(fd).st_mode))
            return real_fsync(fd)

        with patch("inventory.os.replace", wraps=os.replace) as replaced:
            with patch("inventory.os.fsync", side_effect=observe_fsync):
                save_devices(self.path, [AGENT_DEVICE])

        replaced.assert_called_once()
        self.assertIn(stat.S_IFREG, synced_types)
        self.assertIn(stat.S_IFDIR, synced_types)
        self.assertEqual(load_devices(self.path), [AGENT_DEVICE])


if __name__ == "__main__":
    unittest.main()
