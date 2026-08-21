#!/usr/bin/env python3
"""Read the Z-Stack association table from the registered Zigbee coordinator.

This script sends only the ZNP UTIL_GET_DEVICE_INFO request.  It does not
permit joining, pair a device, change a coordinator setting, or send a radio
request to an end device.
"""

from __future__ import annotations

import json
import os
import select
import sys
import termios
import time
from pathlib import Path


EXPECTED_SCRIPT_KEY = "zigbee.network.read"
BAUD_RATE = termios.B115200
GET_DEVICE_INFO_FRAME = b"\xfe\x00\x27\x00\x27"
RESPONSE_TIMEOUT_SECONDS = 6


def fail(message: str) -> int:
    print(f"FAIL {message}", file=sys.stderr)
    return 1


def frame_checksum(frame: bytes) -> int:
    checksum = 0
    for value in frame:
        checksum ^= value
    return checksum


def read_exact(file_descriptor: int, size: int, deadline: float) -> bytes:
    received = bytearray()
    while len(received) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ZNP response timeout")
        readable, _, _ = select.select([file_descriptor], [], [], remaining)
        if not readable:
            raise TimeoutError("ZNP response timeout")
        chunk = os.read(file_descriptor, size - len(received))
        if not chunk:
            raise OSError("Serial endpoint closed while reading")
        received.extend(chunk)
    return bytes(received)


def read_frame(file_descriptor: int, timeout_seconds: float) -> tuple[int, int, bytes]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if read_exact(file_descriptor, 1, deadline) != b"\xfe":
            continue
        length = read_exact(file_descriptor, 1, deadline)[0]
        body = read_exact(file_descriptor, length + 3, deadline)
        command0, command1 = body[0], body[1]
        payload, checksum = body[2:-1], body[-1]
        if frame_checksum(bytes([length, command0, command1]) + payload) != checksum:
            continue
        return command0, command1, payload


def configure_serial(file_descriptor: int) -> list[object]:
    original = termios.tcgetattr(file_descriptor)
    configured = termios.tcgetattr(file_descriptor)
    configured[0] = 0
    configured[1] = 0
    configured[2] = termios.CS8 | termios.CLOCAL | termios.CREAD
    configured[3] = 0
    configured[4] = BAUD_RATE
    configured[5] = BAUD_RATE
    configured[6][termios.VMIN] = 0
    configured[6][termios.VTIME] = 0
    termios.tcsetattr(file_descriptor, termios.TCSANOW, configured)
    return original


def query_associations(endpoint: Path) -> dict[str, object]:
    file_descriptor = os.open(str(endpoint), os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    original_settings: list[object] | None = None
    try:
        original_settings = configure_serial(file_descriptor)
        termios.tcflush(file_descriptor, termios.TCIFLUSH)
        os.write(file_descriptor, GET_DEVICE_INFO_FRAME)
        deadline = time.monotonic() + RESPONSE_TIMEOUT_SECONDS
        while True:
            command0, command1, payload = read_frame(file_descriptor, deadline - time.monotonic())
            if (command0, command1) == (0x67, 0x00):
                break
        if len(payload) < 14:
            raise ValueError("ZNP UTIL_GET_DEVICE_INFO response is too short")
        if payload[0] != 0:
            raise ValueError(f"ZNP UTIL_GET_DEVICE_INFO returned status 0x{payload[0]:02x}")
        declared_count = payload[13]
        addresses = payload[14:]
        if len(addresses) != declared_count * 2:
            raise ValueError("ZNP association list length does not match its declared count")
        return {
            "coordinator_state": payload[12],
            "associated_device_count": declared_count,
            "association_table_read": "pass",
            "radio_sensor_read": "not_sent",
        }
    finally:
        if original_settings is not None:
            termios.tcsetattr(file_descriptor, termios.TCSANOW, original_settings)
        os.close(file_descriptor)


def main() -> int:
    if os.environ.get("DEVICE_CLI_CONTEXT") != "1" or os.environ.get("DEVICE_CLI_SCRIPT_KEY") != EXPECTED_SCRIPT_KEY:
        print(
            "Error: run this operation through rfid_vault.py device-script-run zigbee.network.read.",
            file=sys.stderr,
        )
        return 2
    endpoint_text = os.environ.get("DEVICE_CLI_DEVICE_ENDPOINT")
    if not endpoint_text:
        return fail("The registered gateway has no active serial endpoint.")
    endpoint = Path(endpoint_text)
    if not endpoint.exists():
        return fail(f"The registered gateway endpoint {endpoint} does not exist.")
    try:
        result = query_associations(endpoint)
    except TimeoutError:
        return fail(
            "No ZNP response at 115200 baud. Ensure that ETH-52P is in USB Zigbee mode "
            "and that no Zigbee application owns the serial port."
        )
    except (OSError, ValueError) as error:
        return fail(str(error))
    print(json.dumps({"status": "pass", "endpoint": str(endpoint), **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
