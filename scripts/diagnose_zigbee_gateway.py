#!/usr/bin/env python3
"""Read-only host diagnostic for one registered USB Zigbee gateway.

Run this file only with ``rfid_vault.py device-script-run``.  It checks that
the registered serial device still exists and that the local host can open it.
It does not send serial data, change TTY settings, pair devices, or change the
Zigbee network.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path


EXPECTED_SCRIPT_KEY = "zigbee.gateway.diagnose"


def fail(message: str) -> int:
    print(f"FAIL {message}", file=sys.stderr)
    return 1


def udev_properties(endpoint: Path) -> dict[str, str]:
    """Return a small, non-secret set of udev facts for the registered port."""
    result = subprocess.run(
        ["udevadm", "info", "--query=property", f"--name={endpoint}"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        return {}
    allowed = {"ID_VENDOR", "ID_VENDOR_ID", "ID_MODEL", "ID_MODEL_ID", "ID_USB_DRIVER"}
    properties: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in allowed:
            properties[key] = value
    return properties


def main() -> int:
    if os.environ.get("DEVICE_CLI_CONTEXT") != "1" or os.environ.get("DEVICE_CLI_SCRIPT_KEY") != EXPECTED_SCRIPT_KEY:
        print(
            "Error: run this operation through rfid_vault.py device-script-run zigbee.gateway.diagnose.",
            file=sys.stderr,
        )
        return 2

    endpoint_text = os.environ.get("DEVICE_CLI_DEVICE_ENDPOINT")
    if not endpoint_text:
        return fail("The registered gateway has no active serial endpoint.")
    endpoint = Path(endpoint_text)
    try:
        mode = endpoint.stat().st_mode
    except OSError as error:
        return fail(f"Cannot stat registered endpoint {endpoint}: {error.strerror or error}")
    if not stat.S_ISCHR(mode):
        return fail(f"Registered endpoint {endpoint} is not a character device.")

    try:
        descriptor = os.open(str(endpoint), os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError as error:
        return fail(f"Cannot open registered endpoint {endpoint} without I/O: {error.strerror or error}")
    else:
        os.close(descriptor)

    print(
        json.dumps(
            {
                "status": "pass",
                "endpoint": str(endpoint),
                "character_device": True,
                "open_without_serial_io": "pass",
                "usb": udev_properties(endpoint),
                "not_verified": ["coordinator firmware", "Zigbee radio link", "sensor visibility"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
