"""Secure persistence for the local PyEZ device inventory."""

import os
import re
import secrets
import stat
import tempfile
from pathlib import Path

import yaml


MAX_INVENTORY_BYTES = 1024 * 1024
ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,127}\Z")
BASE_KEYS = {"name", "host", "port", "username", "auth_method"}
FORBIDDEN_KEYS = {
    "password",
    "passwd",
    "ssh_key",
    "ssh_private_key_file",
    "private_key",
    "private_key_file",
    "private_key_material",
}


class InventoryError(Exception):
    """A device inventory failed validation or filesystem safety checks."""

    def __init__(self, public_message="Device inventory is unsafe or invalid."):
        super().__init__(public_message)
        self.code = "INVENTORY_UNSAFE"
        self.public_message = public_message


def validate_device(value):
    """Validate and normalize one secret-free device record."""
    if not isinstance(value, dict):
        raise InventoryError()

    auth_method = value.get("auth_method")
    allowed = BASE_KEYS | (
        {"password_env"} if auth_method == "password-env" else set()
    )
    if set(value) & FORBIDDEN_KEYS or set(value) - allowed:
        raise InventoryError(
            "Device inventory contains unsupported credential fields."
        )
    if any(
        isinstance(item, str) and "PRIVATE KEY-----" in item.upper()
        for item in value.values()
    ):
        raise InventoryError(
            "Device inventory contains unsupported credential fields."
        )
    if auth_method not in {"agent", "password-env"}:
        raise InventoryError("Device authentication method is invalid.")

    for field in ("name", "host", "username"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise InventoryError(
                "Device inventory contains an invalid required field."
            )

    port = value.get("port", 830)
    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise InventoryError("Device port is invalid.")

    if auth_method == "password-env":
        env_name = value.get("password_env")
        if not isinstance(env_name, str) or not ENV_NAME.fullmatch(env_name):
            raise InventoryError("Password environment variable name is invalid.")
    elif "password_env" in value:
        raise InventoryError(
            "Agent authentication cannot contain a password reference."
        )

    result = {key: value[key] for key in ("name", "host")}
    result["port"] = port
    result["username"] = value["username"]
    result["auth_method"] = auth_method
    if auth_method == "password-env":
        result["password_env"] = value["password_env"]
    return result


def _parent_anchor_and_components(path):
    parent = path.parent
    if parent.anchor:
        return parent.anchor, parent.parts[1:]
    return ".", parent.parts


def _walk_parent_with_descriptors(path):
    anchor, components = _parent_anchor_and_components(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(anchor, flags)
    try:
        for component in components:
            next_fd = os.open(component, flags, dir_fd=directory_fd)
            previous_fd = directory_fd
            directory_fd = next_fd
            os.close(previous_fd)
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def _walk_parent_with_lstat(path):
    anchor, components = _parent_anchor_and_components(path)
    current = Path(anchor)
    current_stat = current.lstat()
    if stat.S_ISLNK(current_stat.st_mode) or not stat.S_ISDIR(
        current_stat.st_mode
    ):
        raise InventoryError()
    for component in components:
        current = current / component
        current_stat = current.lstat()
        if stat.S_ISLNK(current_stat.st_mode) or not stat.S_ISDIR(
            current_stat.st_mode
        ):
            raise InventoryError()
    return current_stat


def _can_use_secure_dir_fds():
    required_dir_fd_functions = (os.open, os.stat, os.unlink, os.rename)
    return (
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and all(
            function in os.supports_dir_fd
            for function in required_dir_fd_functions
        )
    )


def _validate_parent_stat(parent_stat):
    if os.name == "posix":
        if (
            parent_stat.st_uid != os.getuid()
            or stat.S_IMODE(parent_stat.st_mode) & 0o022
        ):
            raise InventoryError()
    return parent_stat


def _open_checked_parent(path):
    directory_fd = _walk_parent_with_descriptors(path)
    try:
        _validate_parent_stat(os.fstat(directory_fd))
    except Exception:
        os.close(directory_fd)
        raise
    return directory_fd


def _check_parent(path):
    if _can_use_secure_dir_fds():
        directory_fd = _open_checked_parent(path)
        try:
            return os.fstat(directory_fd)
        finally:
            os.close(directory_fd)
    return _validate_parent_stat(_walk_parent_with_lstat(path))


def _existing_stat(path):
    """Return lstat metadata, preserving dangling symlinks as existing entries."""
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _existing_stat_at(directory_fd, name):
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _check_existing(path, file_stat=None):
    if file_stat is None:
        file_stat = path.lstat()
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise InventoryError()
    if os.name == "posix":
        if (
            file_stat.st_uid != os.getuid()
            or stat.S_IMODE(file_stat.st_mode) != 0o600
        ):
            raise InventoryError()
    if file_stat.st_size > MAX_INVENTORY_BYTES:
        raise InventoryError()
    return file_stat


def _validated_list(data):
    if (
        not isinstance(data, dict)
        or set(data) != {"devices"}
        or not isinstance(data["devices"], list)
    ):
        raise InventoryError()
    devices = [validate_device(item) for item in data["devices"]]
    names = [item["name"] for item in devices]
    if len(names) != len(set(names)):
        raise InventoryError("Device names must be unique.")
    return devices


def _read_bounded(fd):
    chunks = []
    remaining = MAX_INVENTORY_BYTES + 1
    while remaining:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _load_devices_at(directory_fd, name):
    existing = _existing_stat_at(directory_fd, name)
    if existing is None:
        return []
    expected = _check_existing(None, existing)
    flags = os.O_RDONLY | os.O_NOFOLLOW
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (
            expected.st_dev,
            expected.st_ino,
        ):
            raise InventoryError()
        raw = _read_bounded(fd)
    finally:
        os.close(fd)
    if len(raw) > MAX_INVENTORY_BYTES:
        raise InventoryError()
    return _validated_list(yaml.safe_load(raw.decode("utf-8")))


def _load_devices_portable(path):
    _check_parent(path)
    existing = _existing_stat(path)
    if existing is None:
        return []
    expected = _check_existing(path, existing)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (
            expected.st_dev,
            expected.st_ino,
        ):
            raise InventoryError()
        raw = _read_bounded(fd)
    finally:
        os.close(fd)
    if len(raw) > MAX_INVENTORY_BYTES:
        raise InventoryError()
    return _validated_list(yaml.safe_load(raw.decode("utf-8")))


def load_devices(path):
    """Load and validate an owner-only device inventory."""
    path = Path(path)
    try:
        if not _can_use_secure_dir_fds():
            return _load_devices_portable(path)
        directory_fd = _open_checked_parent(path)
        try:
            return _load_devices_at(directory_fd, path.name)
        finally:
            os.close(directory_fd)
    except InventoryError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError):
        raise InventoryError() from None


def _create_temporary_at(directory_fd, destination_name):
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    for _ in range(128):
        name = f".{destination_name}.{secrets.token_hex(16)}.tmp"
        try:
            fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
        except FileExistsError:
            continue
        return fd, name
    raise InventoryError()


def _write_temporary(fd, normalized):
    try:
        os.fchmod(fd, 0o600)
        expected = os.fstat(fd)
        with os.fdopen(fd, "w", encoding="utf-8", closefd=True) as stream:
            yaml.safe_dump(
                {"devices": normalized},
                stream,
                default_flow_style=False,
                sort_keys=False,
            )
            stream.flush()
            os.fsync(stream.fileno())
        return expected
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _save_devices_at(directory_fd, name, normalized):
    existing = _existing_stat_at(directory_fd, name)
    if existing is not None:
        _check_existing(None, existing)

    temp_name = None
    try:
        fd, temp_name = _create_temporary_at(directory_fd, name)
        expected = _write_temporary(fd, normalized)

        existing = _existing_stat_at(directory_fd, name)
        if existing is not None:
            _check_existing(None, existing)
        os.replace(
            temp_name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temp_name = None

        final_stat = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (final_stat.st_dev, final_stat.st_ino) != (
            expected.st_dev,
            expected.st_ino,
        ):
            raise InventoryError()
        _check_existing(None, final_stat)
        os.fsync(directory_fd)
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=directory_fd)
            except OSError:
                pass


def _save_devices_portable(path, normalized):
    temp_path = None
    try:
        _check_parent(path)
        existing = _existing_stat(path)
        if existing is not None:
            _check_existing(path, existing)

        fd, raw_temp = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temp_path = Path(raw_temp)
        expected = _write_temporary(fd, normalized)

        existing = _existing_stat(path)
        if existing is not None:
            _check_existing(path, existing)
        os.replace(temp_path, path)
        temp_path = None
        if os.name == "posix":
            os.chmod(path, 0o600, follow_symlinks=False)
            parent_fd = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        return expected
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass


def save_devices(path, devices):
    """Atomically save a validated, owner-only device inventory."""
    path = Path(path)
    normalized = _validated_list({"devices": devices})
    try:
        if not _can_use_secure_dir_fds():
            _save_devices_portable(path, normalized)
            return
        directory_fd = _open_checked_parent(path)
        try:
            _save_devices_at(directory_fd, path.name, normalized)
        finally:
            os.close(directory_fd)
    except InventoryError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError):
        raise InventoryError() from None
