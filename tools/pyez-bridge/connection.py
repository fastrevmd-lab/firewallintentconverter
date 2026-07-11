"""Secure construction and error translation for PyEZ connections."""

import os

from jnpr.junos import Device
from jnpr.junos.exception import (
    ConnectAuthError,
    ConnectError,
    ConnectRefusedError,
    ConnectTimeoutError,
)


CONNECT_TIMEOUT = 10
OPERATION_TIMEOUT = 30

PUBLIC_ERRORS = {
    "DEVICE_IDENTITY_FAILED": (
        "NETCONF device identity verification failed.",
        502,
    ),
    "DEVICE_AUTHENTICATION_FAILED": (
        "NETCONF device authentication failed.",
        502,
    ),
    "DEVICE_CREDENTIAL_UNAVAILABLE": (
        "The configured device credential is unavailable.",
        503,
    ),
    "DEVICE_UNREACHABLE": ("The NETCONF device is unreachable.", 502),
    "DEVICE_OPERATION_FAILED": (
        "The NETCONF device operation failed.",
        502,
    ),
    "UNEXPECTED_ERROR": ("An unexpected bridge error occurred.", 500),
}

IDENTITY_ERROR_NAMES = {"BadHostKeyException", "SSHUnknownHostError"}


class DeviceConnectionError(Exception):
    """A stable, redacted connection failure suitable for an API response."""

    def __init__(self, code):
        message, status = PUBLIC_ERRORS[code]
        super().__init__(message)
        self.code = code
        self.public_message = message
        self.status = status


def _error_chain(error):
    """Yield wrapped exceptions without rendering their private messages."""
    pending = [error]
    seen = set()
    while pending:
        current = pending.pop()
        if not isinstance(current, BaseException) or id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        for attribute in ("__cause__", "__context__", "_orig"):
            wrapped = getattr(current, attribute, None)
            if isinstance(wrapped, BaseException):
                pending.append(wrapped)


def classify_connection_error(error):
    """Translate a private transport exception into a stable public error."""
    chain = tuple(_error_chain(error))
    if any(item.__class__.__name__ in IDENTITY_ERROR_NAMES for item in chain):
        return DeviceConnectionError("DEVICE_IDENTITY_FAILED")
    if any(isinstance(item, ConnectAuthError) for item in chain):
        return DeviceConnectionError("DEVICE_AUTHENTICATION_FAILED")
    if any(
        isinstance(
            item,
            (ConnectRefusedError, ConnectTimeoutError, ConnectError),
        )
        for item in chain
    ):
        return DeviceConnectionError("DEVICE_UNREACHABLE")
    return DeviceConnectionError("UNEXPECTED_ERROR")


def connect_device(
    device,
    allow_unknown_hosts=False,
    environ=None,
    device_factory=None,
):
    """Open a strictly verified PyEZ connection for a validated device."""
    environ = os.environ if environ is None else environ
    device_factory = Device if device_factory is None else device_factory
    kwargs = {
        "host": device["host"],
        "user": device["username"],
        "port": device.get("port", 830),
        "conn_open_timeout": CONNECT_TIMEOUT,
        "hostkey_verify": allow_unknown_hosts is not True,
    }
    if device["auth_method"] == "agent":
        kwargs.update(allow_agent=True, look_for_keys=True)
    else:
        password = environ.get(device["password_env"])
        if not password:
            raise DeviceConnectionError("DEVICE_CREDENTIAL_UNAVAILABLE")
        kwargs.update(
            passwd=password,
            allow_agent=False,
            look_for_keys=False,
        )

    public_error = None
    try:
        connection = device_factory(**kwargs)
        connection.open()
        connection.timeout = OPERATION_TIMEOUT
    except Exception as error:
        public_error = classify_connection_error(error)

    if public_error is not None:
        raise public_error from None
    return connection
