#!/usr/bin/env python3
"""Run the reviewed Gree discovery code on an authorized Raspberry Pi."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from typing import Mapping, Sequence


EXPECTED_SCRIPT_KEY = "raspberry.gree-wifi.discover"
GREE_DEVICE_KEY = "appliance:example-gree-air-conditioner"
PROJECT_KEY = "home-infrastructure"


def has_cli_context(environment: Mapping[str, str]) -> bool:
    return (
        environment.get("DEVICE_CLI_CONTEXT") == "1"
        and environment.get("DEVICE_CLI_SCRIPT_KEY") == EXPECTED_SCRIPT_KEY
    )


def ssh_arguments(host: str, user: str) -> list[str]:
    """Return the fixed SSH argument list for the authorized Pi."""
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "LogLevel=ERROR",
        f"{user}@{host}",
        "env",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "DEVICE_CLI_CONTEXT=1",
        "DEVICE_CLI_SCRIPT_KEY=gree.wifi.discover",
        "python3",
        "-",
    ]


def run_checked(arguments: Sequence[str], *, cwd: Path, timeout_seconds: float) -> int:
    result = subprocess.run(
        list(arguments),
        cwd=cwd,
        check=False,
        timeout=timeout_seconds,
    )
    return result.returncode


def main() -> int:
    if os.environ.get("DEVICE_CLI_CONTEXT") != "1" or os.environ.get("DEVICE_CLI_SCRIPT_KEY") != EXPECTED_SCRIPT_KEY:
        print(
            "Error: run this operation through rfid_vault.py device-script-run raspberry.gree-wifi.discover.",
            file=sys.stderr,
        )
        return 2

    repository = Path(__file__).resolve().parents[1]
    vault_cli = repository / "rfid_vault.py"
    discovery_script = repository / "scripts" / "discover_gree_wifi.py"

    access_code = run_checked(
        [
            str(vault_cli),
            "access-check",
            "--project",
            PROJECT_KEY,
            "--device",
            GREE_DEVICE_KEY,
        ],
        cwd=repository,
        timeout_seconds=10,
    )
    if access_code != 0:
        print("Error: active Gree discovery authorization is required.", file=sys.stderr)
        return access_code

    verify_code = run_checked([str(vault_cli), "verify"], cwd=repository, timeout_seconds=30)
    if verify_code != 0:
        print("Error: the registered discovery script did not pass integrity verification.", file=sys.stderr)
        return verify_code

    host = os.environ.get("DEVICE_CLI_DEVICE_ADDRESS") or os.environ.get("RASPBERRY_HOST")
    if not host:
        print("Error: the active Raspberry Pi address is not available in the inventory.", file=sys.stderr)
        return 2
    user = os.environ.get("RASPBERRY_USER", "inventory-user")
    try:
        source = discovery_script.read_text(encoding="utf-8")
        result = subprocess.run(
            ssh_arguments(host, user),
            input=source,
            text=True,
            check=False,
            timeout=35,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"Error: Raspberry Pi discovery could not run: {type(error).__name__}.", file=sys.stderr)
        return 1
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
