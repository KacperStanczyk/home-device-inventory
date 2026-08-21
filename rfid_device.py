#!/usr/bin/env python3
"""Reusable Proxmark3 device access for the RFID SQLite CLI."""

from __future__ import annotations

from datetime import datetime
import getpass
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import shlex
import shutil
import stat
import subprocess
import time
from typing import Any, Iterable
import uuid


ROOT = Path(__file__).resolve().parent
DEFAULT_PROJECT_KEY = "rfid-home-lab"
DEFAULT_READER_KEY = "reader:example-proxmark3-reader"
DEFAULT_RASPBERRY_PROJECT_KEY = "home-infrastructure"
DEFAULT_RASPBERRY_DEVICE_KEY = "computer:raspberry-pi-3"
LOCAL_TRANSPORT = "local"
RASPBERRY_SSH_TRANSPORT = "raspberry-ssh"
UDEV_RULE_SOURCE = ROOT / "proxmark3" / "driver" / "77-pm3-usb-device-blacklist-dialout.rules"
UDEV_RULE_TARGET = Path("/etc/udev/rules.d/77-pm3-usb-device-blacklist-dialout.rules")

BUILTIN_COMMANDS = (
    (
        "pm3.hw-version",
        "Hardware version",
        "Read the Proxmark3 client, firmware, FPGA, and hardware version.",
        "hw version",
        "inspect",
        "read_only",
        30,
    ),
    (
        "pm3.hw-status",
        "Hardware status",
        "Read the current Proxmark3 hardware status and memory state.",
        "hw status",
        "inspect",
        "read_only",
        30,
    ),
    (
        "pm3.hw-tune",
        "Antenna tuning",
        "Measure LF and HF antenna tuning.",
        "hw tune",
        "test",
        "read_only",
        60,
    ),
    (
        "pm3.auto-scan",
        "Automatic tag scan",
        "Run the Proxmark3 automatic tag identification workflow.",
        "auto",
        "read",
        "read_only",
        120,
    ),
    (
        "pm3.hf-search",
        "HF tag search",
        "Search for a supported high-frequency RFID or NFC tag.",
        "hf search",
        "read",
        "read_only",
        60,
    ),
    (
        "pm3.lf-search",
        "LF tag search",
        "Search for a supported low-frequency RFID tag.",
        "lf search",
        "read",
        "read_only",
        60,
    ),
    (
        "pm3.lf-read",
        "LF sample acquisition",
        "Acquire 12000 low-frequency samples without running optional chipset probes.",
        "lf read -v -s 12000",
        "read",
        "read_only",
        30,
    ),
)


class DeviceAccessError(ValueError):
    """The registered device cannot be used through the CLI."""


def timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def command_key(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{1,127}", value):
        raise ValueError(
            "A command key must contain 2-128 lowercase letters, numbers, dots, colons, underscores, or hyphens"
        )
    return value


def seed_builtin_commands(connection: Any, now: str) -> None:
    for key, name, description, text, operation, risk, timeout_seconds in BUILTIN_COMMANDS:
        connection.execute(
            """
            INSERT INTO device_commands(
                command_key, device_kind, display_name, description, command_text,
                required_operation, risk_level, timeout_seconds, enabled, builtin,
                created_at, updated_at
            ) VALUES (?, 'rfid_reader', ?, ?, ?, ?, ?, ?, 1, 1, ?, ?)
            ON CONFLICT(command_key) DO UPDATE SET
                device_kind=excluded.device_kind,
                display_name=excluded.display_name,
                description=excluded.description,
                command_text=excluded.command_text,
                required_operation=excluded.required_operation,
                risk_level=excluded.risk_level,
                timeout_seconds=excluded.timeout_seconds,
                enabled=1,
                builtin=1,
                updated_at=excluded.updated_at
            """,
            (key, name, description, text, operation, risk, timeout_seconds, now, now),
        )


def add_command(
    connection: Any,
    *,
    key: str,
    name: str,
    description: str,
    text: str,
    operation: str,
    risk_level: str,
    timeout_seconds: int,
    now: str | None = None,
) -> int:
    now = now or timestamp()
    connection.execute(
        """
        INSERT INTO device_commands(
            command_key, device_kind, display_name, description, command_text,
            required_operation, risk_level, timeout_seconds, enabled, builtin,
            created_at, updated_at
        ) VALUES (?, 'rfid_reader', ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
        """,
        (
            command_key(key),
            name,
            description,
            text,
            operation,
            risk_level,
            timeout_seconds,
            now,
            now,
        ),
    )
    command_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
    connection.commit()
    return command_id


def list_commands(connection: Any) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            """
            SELECT command_key, display_name, description, command_text,
                   required_operation, risk_level, timeout_seconds, builtin
            FROM device_commands
            WHERE enabled = 1
            ORDER BY builtin DESC, command_key
            """
        ).fetchall()
    ]


def _reader_row(connection: Any, project_key: str, device_key: str | None) -> Any:
    parameters: list[Any] = [project_key]
    condition = ""
    if device_key:
        condition = "AND d.device_key = ?"
        parameters.append(device_key)
    rows = connection.execute(
        f"""
        SELECT p.id AS project_id, p.project_key, d.id AS device_id, d.device_key,
               d.name AS device_name, d.lifecycle_status, pd.status AS scope_status,
               d.legacy_reader_id, r.device_path, r.usb_serial, r.usb_vendor_id,
               r.usb_product_id, r.kernel_driver, r.client_version
        FROM projects AS p
        JOIN project_devices AS pd ON pd.project_id = p.id
        JOIN devices AS d ON d.id = pd.device_id
        LEFT JOIN readers AS r ON r.id = d.legacy_reader_id
        WHERE p.project_key = ? AND d.device_kind = 'rfid_reader' {condition}
        ORDER BY d.device_key
        """,
        tuple(parameters),
    ).fetchall()
    if not rows:
        target = device_key or "an RFID reader"
        raise DeviceAccessError(f"No registered reader matches {target!r} in project {project_key!r}")
    if len(rows) > 1:
        keys = ", ".join(str(row["device_key"]) for row in rows)
        raise DeviceAccessError(f"More than one reader is registered. Select one with --device: {keys}")
    return rows[0]


def _allowed_operations(connection: Any, project_key: str, device_key: str) -> set[str]:
    allowed: set[str] = set()
    for row in connection.execute(
        """
        SELECT allowed_operations_json
        FROM active_authorized_devices
        WHERE project_key = ? AND device_key = ?
        """,
        (project_key, device_key),
    ).fetchall():
        allowed.update(str(value) for value in json.loads(row[0]))
    return allowed


def find_client(
    explicit_path: str | Path | None = None,
    preferred_version: str | None = None,
) -> Path | None:
    candidates: list[Path] = []
    if explicit_path:
        candidates.append(Path(explicit_path).expanduser())
    environment_path = os.environ.get("RFID_PM3_CLIENT")
    if environment_path:
        candidates.append(Path(environment_path).expanduser())
    if preferred_version:
        normalized_version = preferred_version.strip()
        if not normalized_version.startswith("v"):
            normalized_version = f"v{normalized_version}"
        candidates.append(ROOT / f"proxmark3-{normalized_version}" / "client" / "proxmark3")
        candidates.append(ROOT / f"proxmark3-{normalized_version}" / "pm3")
    candidates.extend(
        (
            ROOT / "proxmark3" / "client" / "proxmark3",
            ROOT / "proxmark3" / "pm3",
            ROOT / "proxmark3-v4.20728" / "client" / "proxmark3",
            ROOT / "proxmark3-v4.20728" / "pm3",
        )
    )
    for executable_name in ("pm3", "proxmark3"):
        executable = shutil.which(executable_name)
        if executable:
            candidates.append(Path(executable))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    return None


def _port_details(port: Path | None) -> dict[str, Any]:
    details: dict[str, Any] = {
        "port": str(port) if port else None,
        "port_exists": False,
        "port_is_character_device": False,
        "port_readable": False,
        "port_writable": False,
        "port_owner": None,
        "port_group": None,
        "port_mode": None,
    }
    if port is None or not port.exists():
        return details
    port_stat = port.stat()
    details.update(
        {
            "port_exists": True,
            "port_is_character_device": stat.S_ISCHR(port_stat.st_mode),
            "port_readable": os.access(port, os.R_OK),
            "port_writable": os.access(port, os.W_OK),
            "port_owner": pwd.getpwuid(port_stat.st_uid).pw_name,
            "port_group": grp.getgrgid(port_stat.st_gid).gr_name,
            "port_mode": f"{stat.S_IMODE(port_stat.st_mode):04o}",
        }
    )
    return details


def _ssh_endpoint(endpoint: str) -> tuple[str, int]:
    """Validate one inventory SSH endpoint and split it into host and port."""
    match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9.-]{0,252})(?::([0-9]{1,5}))?", endpoint)
    if match is None:
        raise DeviceAccessError("The Raspberry SSH endpoint is not a valid host[:port] value")
    host = match.group(1)
    port = int(match.group(2) or "22")
    if not 1 <= port <= 65535:
        raise DeviceAccessError("The Raspberry SSH endpoint has an invalid port")
    return host, port


def _remote_serial_port(port: str | Path | None) -> str:
    value = str(port) if port is not None else ""
    if not re.fullmatch(r"/dev/(?:ttyACM|ttyUSB)[0-9]+", value):
        raise DeviceAccessError(
            "A Raspberry Proxmark3 endpoint must be a local serial port such as /dev/ttyACM0"
        )
    return value


def _ssh_target(endpoint: str, account_label: str | None) -> tuple[list[str], str, int, str]:
    host, port = _ssh_endpoint(endpoint)
    account = account_label or getpass.getuser()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", account):
        raise DeviceAccessError("The Raspberry SSH account label is not valid")
    arguments = [
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
        "-p",
        str(port),
        f"{account}@{host}",
    ]
    return arguments, host, port, account


def _remote_probe_command(remote_port: str, preferred_version: str | None) -> str:
    """Return a fixed remote script. Values are quoted before SSH passes them to sh."""
    version_suffix = ""
    if preferred_version:
        normalized = preferred_version.strip()
        if not re.fullmatch(r"v[0-9][0-9A-Za-z._-]{0,63}", normalized):
            raise DeviceAccessError("The registered Proxmark3 client version is not valid")
        version_suffix = normalized
    candidates = '$(command -v pm3 2>/dev/null || true) $(command -v proxmark3 2>/dev/null || true)'
    if version_suffix:
        candidates += f' "$HOME/proxmark3-{version_suffix}/client/proxmark3"'
    script = (
        "set -eu; port=$1; client=''; "
        f"for candidate in {candidates}; do "
        "if [ -n \"$candidate\" ] && [ -x \"$candidate\" ]; then client=$candidate; break; fi; "
        "done; "
        "if [ -z \"$client\" ]; then exit 127; fi; "
        "if [ ! -c \"$port\" ]; then exit 4; fi; "
        "if [ ! -r \"$port\" ] || [ ! -w \"$port\" ]; then exit 13; fi; "
        "printf 'PM3_CLIENT=%s\\n' \"$client\""
    )
    return f"sh -c {shlex.quote(script)} -- {shlex.quote(remote_port)}"


def _remote_pm3_command(
    remote_client: str,
    remote_port: str,
    command_text: str,
    timeout_seconds: int,
) -> str:
    if not re.fullmatch(r"/(?:[A-Za-z0-9._+@%=-]+/)*[A-Za-z0-9._+@%=-]+", remote_client):
        raise DeviceAccessError("The Raspberry Proxmark3 client path is not valid")
    return (
        "exec timeout --signal=TERM --kill-after=5s "
        f"{timeout_seconds}s {shlex.quote(remote_client)} -p {shlex.quote(remote_port)} "
        f"-c {shlex.quote(command_text)}"
    )


def _bridge_row(connection: Any, project_key: str, device_key: str) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT p.id AS project_id, p.project_key, p.status AS project_status,
               d.id AS device_id, d.device_key, d.lifecycle_status,
               pd.status AS scope_status, method.endpoint, method.account_label
        FROM projects AS p
        JOIN project_devices AS pd ON pd.project_id = p.id
        JOIN devices AS d ON d.id = pd.device_id
        LEFT JOIN access_methods AS method
          ON method.project_id = p.id AND method.device_id = d.id
         AND method.method_type = 'ssh' AND method.status = 'active'
        WHERE p.project_key = ? AND d.device_key = ?
        ORDER BY method.id
        LIMIT 1
        """,
        (project_key, device_key),
    ).fetchone()
    if row is None:
        raise DeviceAccessError(
            f"No registered Raspberry bridge matches {device_key!r} in project {project_key!r}"
        )
    allowed_operations = _allowed_operations(connection, project_key, device_key)
    result = dict(row)
    result["allowed_operations"] = allowed_operations
    return result


def _reader_ssh_method(connection: Any, reader: Any) -> Any:
    return connection.execute(
        """
        SELECT endpoint, account_label
        FROM access_methods
        WHERE project_id = ? AND device_id = ? AND method_type = 'ssh' AND status = 'active'
        ORDER BY id
        LIMIT 1
        """,
        (reader["project_id"], reader["device_id"]),
    ).fetchone()


def _raspberry_probe(
    connection: Any,
    *,
    reader: Any,
    allowed_operations: set[str],
    port_path: str | Path | None,
    bridge_project_key: str,
    bridge_device_key: str,
) -> dict[str, Any]:
    bridge = _bridge_row(connection, bridge_project_key, bridge_device_key)
    problems: list[str] = []
    repair_steps: list[str] = []
    if not allowed_operations:
        problems.append("No active per-device authorization exists in SQLite.")
    if bridge["project_status"] != "active":
        problems.append("The Raspberry bridge project is not active.")
    if bridge["lifecycle_status"] != "active" or bridge["scope_status"] != "in_scope":
        problems.append("The Raspberry bridge is not active and in scope.")
    if "inspect" not in bridge["allowed_operations"]:
        problems.append("The Raspberry bridge authorization does not allow operation 'inspect'.")
    reader_method = _reader_ssh_method(connection, reader)
    if reader_method is None or not reader_method["endpoint"]:
        problems.append("No active Raspberry SSH transport is registered for this Proxmark3 reader.")
        repair_steps.append(
            "Register an active ssh access method for the reader that matches the Raspberry SSH endpoint."
        )
    if not bridge["endpoint"]:
        problems.append("The Raspberry bridge has no active SSH endpoint.")

    local_port = port_path
    if local_port is None:
        serial_method = connection.execute(
            """
            SELECT endpoint FROM access_methods
            WHERE project_id = ? AND device_id = ? AND method_type = 'usb_serial' AND status = 'active'
            ORDER BY id LIMIT 1
            """,
            (reader["project_id"], reader["device_id"]),
        ).fetchone()
        local_port = serial_method[0] if serial_method and serial_method[0] else reader["device_path"]
    try:
        remote_port = _remote_serial_port(local_port)
    except DeviceAccessError as error:
        problems.append(str(error))
        remote_port = None

    ssh_arguments: list[str] | None = None
    bridge_endpoint: str | None = None
    bridge_account: str | None = None
    if reader_method is not None and reader_method["endpoint"] and bridge["endpoint"]:
        try:
            reader_host, reader_port = _ssh_endpoint(str(reader_method["endpoint"]))
            bridge_host, bridge_port = _ssh_endpoint(str(bridge["endpoint"]))
            if (reader_host, reader_port) != (bridge_host, bridge_port):
                problems.append("The reader SSH transport does not match the registered Raspberry SSH endpoint.")
            else:
                bridge_endpoint = f"{bridge_host}:{bridge_port}"
                ssh_arguments, _host, _port, bridge_account = _ssh_target(
                    bridge_endpoint,
                    str(reader_method["account_label"] or bridge["account_label"] or ""),
                )
        except DeviceAccessError as error:
            problems.append(str(error))

    remote_client: str | None = None
    stdout = b""
    stderr = b""
    if not problems and ssh_arguments is not None and remote_port is not None:
        try:
            completed = _run_captured_process(
                [*ssh_arguments, _remote_probe_command(remote_port, reader["client_version"])],
                cwd=ROOT,
                timeout_seconds=30,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            if completed.returncode == 0:
                match = re.search(rb"(?m)^PM3_CLIENT=(/.+)$", stdout)
                if match is not None:
                    remote_client = match.group(1).decode("utf-8", errors="strict")
                else:
                    problems.append("Raspberry client discovery returned an invalid result.")
            elif completed.returncode == 127:
                problems.append("No executable Proxmark3 client was found on the Raspberry Pi.")
                repair_steps.append("Build the client version stored in readers.client_version on the Raspberry Pi.")
            elif completed.returncode == 4:
                problems.append(f"The Raspberry serial endpoint does not exist: {remote_port}")
                repair_steps.append("Reconnect the Proxmark3 data cable to the Raspberry Pi, then rerun pm3-probe.")
            elif completed.returncode == 13:
                problems.append(f"The Raspberry SSH user cannot read and write {remote_port}.")
                repair_steps.append("Add the Raspberry SSH user to dialout, then log in again and rerun pm3-probe.")
            else:
                problems.append(f"Raspberry client discovery failed with exit {completed.returncode}.")
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout or b""
            stderr = error.stderr or b""
            problems.append("Raspberry client discovery exceeded 30 seconds.")
        except OSError as error:
            problems.append(f"Raspberry client discovery could not start: {error.strerror or error}.")
    remote_uri = None
    client_uri = None
    if bridge_endpoint and bridge_account and remote_port:
        remote_uri = f"ssh://{bridge_account}@{bridge_endpoint}/{remote_port.lstrip('/')}"
    if bridge_endpoint and bridge_account and remote_client:
        client_uri = f"ssh://{bridge_account}@{bridge_endpoint}{remote_client}"
    return {
        "transport": RASPBERRY_SSH_TRANSPORT,
        "bridge_project_key": bridge_project_key,
        "bridge_device_key": bridge_device_key,
        "bridge_endpoint": bridge_endpoint,
        "bridge_authorized": "inspect" in bridge["allowed_operations"],
        "remote_port": remote_port,
        "remote_client": remote_client,
        "client": client_uri,
        "client_executable": remote_client is not None,
        "port": remote_uri,
        "port_exists": remote_client is not None,
        "port_is_character_device": remote_client is not None,
        "port_readable": remote_client is not None,
        "port_writable": remote_client is not None,
        "port_owner": None,
        "port_group": None,
        "port_mode": None,
        "problems": problems,
        "repair_steps": repair_steps,
        "ssh_arguments": ssh_arguments,
    }


def probe(
    connection: Any,
    *,
    project_key: str = DEFAULT_PROJECT_KEY,
    device_key: str | None = None,
    client_path: str | Path | None = None,
    port_path: str | Path | None = None,
    transport: str = LOCAL_TRANSPORT,
    bridge_project_key: str = DEFAULT_RASPBERRY_PROJECT_KEY,
    bridge_device_key: str = DEFAULT_RASPBERRY_DEVICE_KEY,
) -> dict[str, Any]:
    reader = _reader_row(connection, project_key, device_key)
    allowed_operations = _allowed_operations(connection, project_key, str(reader["device_key"]))
    if transport not in (LOCAL_TRANSPORT, RASPBERRY_SSH_TRANSPORT):
        raise ValueError(f"Unsupported Proxmark3 transport: {transport}")
    if transport == RASPBERRY_SSH_TRANSPORT:
        if client_path is not None:
            raise DeviceAccessError("--client is not supported with the Raspberry SSH transport")
        remote = _raspberry_probe(
            connection,
            reader=reader,
            allowed_operations=allowed_operations,
            port_path=port_path,
            bridge_project_key=bridge_project_key,
            bridge_device_key=bridge_device_key,
        )
        result = {
            "project_id": int(reader["project_id"]),
            "project_key": str(reader["project_key"]),
            "device_id": int(reader["device_id"]),
            "device_key": str(reader["device_key"]),
            "device_name": str(reader["device_name"]),
            "scope_status": str(reader["scope_status"]),
            "authorized": bool(allowed_operations),
            "allowed_operations": sorted(allowed_operations),
            "current_user": getpass.getuser(),
            "current_groups": sorted(
                {
                    grp.getgrgid(group_id).gr_name
                    for group_id in {*os.getgroups(), os.getgid()}
                    if group_id >= 0
                }
            ),
            "usb_serial": reader["usb_serial"],
            "usb_vendor_id": reader["usb_vendor_id"],
            "usb_product_id": reader["usb_product_id"],
            "kernel_driver": reader["kernel_driver"],
            "preferred_client_version": reader["client_version"],
            **remote,
        }
        result["ready"] = not result["problems"]
        return result
    endpoint = port_path
    if endpoint is None:
        method = connection.execute(
            """
            SELECT endpoint
            FROM access_methods
            WHERE project_id = ? AND device_id = ? AND method_type = 'usb_serial' AND status = 'active'
            ORDER BY id
            LIMIT 1
            """,
            (reader["project_id"], reader["device_id"]),
        ).fetchone()
        endpoint = method[0] if method and method[0] else reader["device_path"]
    port = Path(endpoint) if endpoint else None
    client = find_client(client_path, reader["client_version"])
    port_details = _port_details(port)
    current_groups = sorted(
        {
            grp.getgrgid(group_id).gr_name
            for group_id in {*os.getgroups(), os.getgid()}
            if group_id >= 0
        }
    )
    problems: list[str] = []
    repair_steps: list[str] = []
    if not allowed_operations:
        problems.append("No active per-device authorization exists in SQLite.")
    if client is None:
        problems.append("No executable Proxmark3 client was found.")
        repair_steps.append("Build the local client, then rerun pm3-probe.")
    if not port_details["port_exists"]:
        problems.append(f"The configured serial endpoint does not exist: {port_details['port']}")
        repair_steps.append("Reconnect the Proxmark3 data port, then rerun pm3-probe.")
    elif not port_details["port_is_character_device"]:
        problems.append(f"The configured endpoint is not a character device: {port_details['port']}")
    elif not (port_details["port_readable"] and port_details["port_writable"]):
        problems.append(
            f"The current user cannot read and write {port_details['port']} "
            f"({port_details['port_owner']}:{port_details['port_group']} mode {port_details['port_mode']})."
        )
        if port_details["port_group"] == "dialout" and "dialout" not in current_groups:
            repair_steps.append(f"sudo usermod -aG dialout {getpass.getuser()}")
            repair_steps.append("Log out and log in again, or run pm3-fix-permissions --apply for an immediate ACL.")
    result = {
        "transport": LOCAL_TRANSPORT,
        "project_id": int(reader["project_id"]),
        "project_key": str(reader["project_key"]),
        "device_id": int(reader["device_id"]),
        "device_key": str(reader["device_key"]),
        "device_name": str(reader["device_name"]),
        "scope_status": str(reader["scope_status"]),
        "authorized": bool(allowed_operations),
        "allowed_operations": sorted(allowed_operations),
        "client": str(client) if client else None,
        "client_executable": bool(client),
        "current_user": getpass.getuser(),
        "current_groups": current_groups,
        "usb_serial": reader["usb_serial"],
        "usb_vendor_id": reader["usb_vendor_id"],
        "usb_product_id": reader["usb_product_id"],
        "kernel_driver": reader["kernel_driver"],
        "preferred_client_version": reader["client_version"],
        **port_details,
        "problems": problems,
        "repair_steps": repair_steps,
    }
    result["ready"] = not problems
    return result


def probe_lines(result: dict[str, Any]) -> list[str]:
    state = "READY" if result["ready"] else "NOT READY"
    lines = [
        f"{state}: {result['project_key']} / {result['device_key']}",
        f"transport: {result['transport']}",
        f"client: {result['client'] or 'not-found'}",
        (
            f"port: {result['port'] or 'not-found'} | exists={result['port_exists']} | "
            f"readable={result['port_readable']} | writable={result['port_writable']}"
        ),
        f"authorization: active={result['authorized']} | operations={','.join(result['allowed_operations'])}",
    ]
    if result["transport"] == RASPBERRY_SSH_TRANSPORT:
        lines.append(
            f"bridge: {result['bridge_project_key']} / {result['bridge_device_key']} | "
            f"endpoint={result['bridge_endpoint'] or 'not-found'} | "
            f"inspect-authorized={result['bridge_authorized']}"
        )
    lines.extend(f"problem: {problem}" for problem in result["problems"])
    lines.extend(f"repair: {step}" for step in result["repair_steps"])
    return lines


def permission_repair_commands(result: dict[str, Any]) -> list[list[str]]:
    commands: list[list[str]] = []
    user = str(result["current_user"])
    if "dialout" not in result["current_groups"]:
        commands.append(["sudo", "usermod", "-aG", "dialout", user])
    if UDEV_RULE_SOURCE.is_file():
        commands.append(
            ["sudo", "install", "-m", "0644", str(UDEV_RULE_SOURCE), str(UDEV_RULE_TARGET)]
        )
        commands.append(["sudo", "udevadm", "control", "--reload-rules"])
    if result.get("port_exists") and shutil.which("setfacl"):
        commands.append(["sudo", "setfacl", "-m", f"u:{user}:rw", str(result["port"])])
    return commands


def apply_permission_repair(result: dict[str, Any]) -> list[list[str]]:
    commands = permission_repair_commands(result)
    for command in commands:
        completed = subprocess.run(command, check=False)
        if completed.returncode != 0:
            raise DeviceAccessError(
                f"Permission repair failed with exit {completed.returncode}: {' '.join(command)}"
            )
    return commands


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_captured_process(
    arguments: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        arguments,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(
            arguments,
            timeout_seconds,
            output=stdout,
            stderr=stderr,
        )
    return subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)


def diagnose_client_output(
    key: str,
    stdout: bytes,
    stderr: bytes,
) -> str | None:
    text = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
    lower_text = text.lower()
    if key == "pm3.firmware-flash" and (
        "the flashing procedure failed" in lower_text
        or "error: proxmark3 not found" in lower_text
        or "sending bytes to proxmark3 failed" in lower_text
        or "error: invalid serial port" in lower_text
        or "aborted on error" in lower_text
        or "arm firmware does not match the source" in lower_text
    ):
        return (
            "The client returned exit code 0 but its output says that firmware flashing failed. "
            "Run the flash command with an active dialout group after the device re-enumerates."
        )
    if "Capabilities structure version sent by Proxmark3 is not the same" in text:
        return (
            "The selected Proxmark3 client is not compatible with the firmware capabilities format. "
            "Use the client version stored in readers.client_version."
        )
    if "unknown command:: 0x037e" in text.lower():
        return (
            "The firmware does not support CMD_LF_HITAGU_UID (0x037e), which this client calls during "
            "online lf search. Use pm3.lf-read to verify LF sampling, or align firmware and client versions."
        )
    if key == "pm3.hw-tune":
        match = re.search(r"13\.56 MHz\.*\s+([0-9]+(?:\.[0-9]+)?) V", text)
        if match and float(match.group(1)) > 100.0:
            return (
                f"The reported HF antenna voltage {match.group(1)} V is physically invalid. "
                "The RDV4 firmware and generic Proxmark3 Easy hardware do not provide a reliable HF tune value."
            )
        if "Contradicting measures seem to indicate" in text:
            return "The antenna measurement reports a device and firmware mismatch."
    return None


def _record_run(
    connection: Any,
    *,
    probe_result: dict[str, Any],
    command_id: int | None,
    command_text: str,
    required_operation: str,
    started_at: str,
    completed_at: str,
    duration_ms: int,
    status_value: str,
    exit_code: int | None,
    stdout: bytes,
    stderr: bytes,
    error_message: str | None,
) -> str:
    run_key = f"pm3:{uuid.uuid4()}"
    connection.execute(
        """
        INSERT INTO device_command_runs(
            run_key, project_id, device_id, command_id, command_text,
            required_operation, client_path, endpoint, started_at, completed_at,
            duration_ms, status, exit_code, stdout_sha256, stderr_sha256,
            stdout_content, stderr_content, error_message, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_key,
            probe_result["project_id"],
            probe_result["device_id"],
            command_id,
            command_text,
            required_operation,
            probe_result.get("client"),
            probe_result.get("port"),
            started_at,
            completed_at,
            duration_ms,
            status_value,
            exit_code,
            _hash(stdout),
            _hash(stderr),
            stdout,
            stderr,
            error_message,
            completed_at,
        ),
    )
    connection.commit()
    return run_key


def run_named_command(
    connection: Any,
    *,
    key: str,
    project_key: str = DEFAULT_PROJECT_KEY,
    device_key: str | None = None,
    client_path: str | Path | None = None,
    port_path: str | Path | None = None,
    timeout_seconds: int | None = None,
    transport: str = LOCAL_TRANSPORT,
    bridge_project_key: str = DEFAULT_RASPBERRY_PROJECT_KEY,
    bridge_device_key: str = DEFAULT_RASPBERRY_DEVICE_KEY,
) -> dict[str, Any]:
    command = connection.execute(
        "SELECT * FROM device_commands WHERE command_key = ? AND enabled = 1",
        (command_key(key),),
    ).fetchone()
    if command is None:
        raise DeviceAccessError(f"Named device command {key!r} does not exist or is disabled")
    probe_result = probe(
        connection,
        project_key=project_key,
        device_key=device_key,
        client_path=client_path,
        port_path=port_path,
        transport=transport,
        bridge_project_key=bridge_project_key,
        bridge_device_key=bridge_device_key,
    )
    started_at = timestamp()
    start = time.monotonic()
    required_operation = str(command["required_operation"])
    if not probe_result["ready"] or required_operation not in probe_result["allowed_operations"]:
        message_parts = list(probe_result["problems"])
        if required_operation not in probe_result["allowed_operations"]:
            message_parts.append(f"Authorization does not allow operation {required_operation!r}.")
        error_message = " ".join(message_parts)
        completed_at = timestamp()
        run_key = _record_run(
            connection,
            probe_result=probe_result,
            command_id=int(command["id"]),
            command_text=str(command["command_text"]),
            required_operation=required_operation,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=max(0, int((time.monotonic() - start) * 1000)),
            status_value="blocked",
            exit_code=None,
            stdout=b"",
            stderr=error_message.encode("utf-8"),
            error_message=error_message,
        )
        raise DeviceAccessError(f"{error_message} Audit run: {run_key}")

    effective_timeout = timeout_seconds or int(command["timeout_seconds"])
    if not 1 <= effective_timeout <= 3600:
        raise ValueError("Timeout must be between 1 and 3600 seconds")
    if probe_result["transport"] == RASPBERRY_SSH_TRANSPORT:
        ssh_arguments = probe_result.get("ssh_arguments")
        remote_client = probe_result.get("remote_client")
        remote_port = probe_result.get("remote_port")
        if not isinstance(ssh_arguments, list) or not remote_client or not remote_port:
            raise DeviceAccessError("The Raspberry SSH transport is incomplete after pm3-probe.")
        arguments = [
            *ssh_arguments,
            _remote_pm3_command(
                str(remote_client),
                str(remote_port),
                str(command["command_text"]),
                effective_timeout,
            ),
        ]
        process_timeout = effective_timeout + 10
    else:
        arguments = [
            str(probe_result["client"]),
            "-p",
            str(probe_result["port"]),
            "-c",
            str(command["command_text"]),
        ]
        process_timeout = effective_timeout
    try:
        completed = _run_captured_process(
            arguments,
            cwd=ROOT,
            timeout_seconds=process_timeout,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        exit_code: int | None = completed.returncode
        diagnosis = diagnose_client_output(key, stdout, stderr)
        status_value = "succeeded" if completed.returncode == 0 and diagnosis is None else "failed"
        if diagnosis is not None:
            error_message = diagnosis
        elif probe_result["transport"] == RASPBERRY_SSH_TRANSPORT and completed.returncode == 124:
            status_value = "timed_out"
            error_message = f"Raspberry client exceeded timeout of {effective_timeout} seconds"
        elif completed.returncode != 0:
            error_message = f"Client exited with {completed.returncode}"
        else:
            error_message = None
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        exit_code = None
        status_value = "timed_out"
        error_message = f"Client exceeded timeout of {effective_timeout} seconds"
    completed_at = timestamp()
    run_key = _record_run(
        connection,
        probe_result=probe_result,
        command_id=int(command["id"]),
        command_text=str(command["command_text"]),
        required_operation=required_operation,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=max(0, int((time.monotonic() - start) * 1000)),
        status_value=status_value,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        error_message=error_message,
    )
    return {
        "run_key": run_key,
        "status": status_value,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "error_message": error_message,
    }


def _authorization_problem(probe_result: dict[str, Any], required_operation: str) -> str | None:
    message_parts = list(probe_result["problems"])
    if required_operation not in probe_result["allowed_operations"]:
        message_parts.append(f"Authorization does not allow operation {required_operation!r}.")
    return " ".join(message_parts) or None


def backup_device_memory(
    connection: Any,
    *,
    output_path: str | Path,
    project_key: str = DEFAULT_PROJECT_KEY,
    device_key: str | None = None,
    client_path: str | Path | None = None,
    port_path: str | Path | None = None,
    length: int = 512 * 1024,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    if not 1 <= length <= 512 * 1024:
        raise ValueError("Firmware backup length must be between 1 and 524288 bytes")
    if not 1 <= timeout_seconds <= 3600:
        raise ValueError("Timeout must be between 1 and 3600 seconds")

    probe_result = probe(
        connection,
        project_key=project_key,
        device_key=device_key,
        client_path=client_path,
        port_path=port_path,
    )
    required_operation = "inspect"
    started_at = timestamp()
    start = time.monotonic()
    destination = Path(output_path).expanduser().resolve()
    command_text = f"firmware backup length={length} output={destination}"
    authorization_problem = _authorization_problem(probe_result, required_operation)
    if authorization_problem:
        completed_at = timestamp()
        run_key = _record_run(
            connection,
            probe_result=probe_result,
            command_id=None,
            command_text=command_text,
            required_operation=required_operation,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=max(0, int((time.monotonic() - start) * 1000)),
            status_value="blocked",
            exit_code=None,
            stdout=b"",
            stderr=authorization_problem.encode("utf-8"),
            error_message=authorization_problem,
        )
        raise DeviceAccessError(f"{authorization_problem} Audit run: {run_key}")
    if destination.exists():
        raise DeviceAccessError(f"Firmware backup already exists: {destination}")

    parent_was_missing = not destination.parent.exists()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if parent_was_missing:
        os.chmod(destination.parent, 0o700)
    arguments = [
        str(probe_result["client"]),
        "-p",
        str(probe_result["port"]),
        "--dumpmem",
        str(destination),
        "--dumplen",
        str(length),
    ]
    try:
        completed = _run_captured_process(
            arguments,
            cwd=ROOT,
            timeout_seconds=timeout_seconds,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        exit_code: int | None = completed.returncode
        if completed.returncode != 0:
            status_value = "failed"
            error_message = f"Client exited with {completed.returncode}"
        elif not destination.is_file():
            status_value = "failed"
            error_message = "The client reported success but did not create the firmware backup"
        elif destination.stat().st_size != length:
            status_value = "failed"
            error_message = (
                f"Firmware backup has {destination.stat().st_size} bytes; expected {length} bytes"
            )
        else:
            status_value = "succeeded"
            error_message = None
            os.chmod(destination, 0o600)
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        exit_code = None
        status_value = "timed_out"
        error_message = f"Client exceeded timeout of {timeout_seconds} seconds"
    completed_at = timestamp()
    run_key = _record_run(
        connection,
        probe_result=probe_result,
        command_id=None,
        command_text=command_text,
        required_operation=required_operation,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=max(0, int((time.monotonic() - start) * 1000)),
        status_value=status_value,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        error_message=error_message,
    )
    return {
        "run_key": run_key,
        "status": status_value,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "error_message": error_message,
        "path": destination,
        "size": destination.stat().st_size if destination.is_file() else None,
        "sha256": _file_hash(destination) if status_value == "succeeded" else None,
    }


def flash_firmware(
    connection: Any,
    *,
    fullimage_path: str | Path | None = None,
    bootrom_path: str | Path | None = None,
    confirmed: bool = False,
    force: bool = False,
    project_key: str = DEFAULT_PROJECT_KEY,
    device_key: str | None = None,
    client_path: str | Path | None = None,
    port_path: str | Path | None = None,
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    if fullimage_path is None and bootrom_path is None:
        raise ValueError("Select at least one firmware image")
    if not 1 <= timeout_seconds <= 3600:
        raise ValueError("Timeout must be between 1 and 3600 seconds")

    images: list[tuple[str, Path, str]] = []
    for image_kind, supplied_path in (
        ("bootrom", bootrom_path),
        ("fullimage", fullimage_path),
    ):
        if supplied_path is None:
            continue
        image_path = Path(supplied_path).expanduser().resolve()
        if not image_path.is_file():
            raise DeviceAccessError(f"Firmware image does not exist: {image_path}")
        if image_path.suffix.lower() != ".elf":
            raise DeviceAccessError(f"Firmware image must be an ELF file: {image_path}")
        images.append((image_kind, image_path, _file_hash(image_path)))

    probe_result = probe(
        connection,
        project_key=project_key,
        device_key=device_key,
        client_path=client_path,
        port_path=port_path,
    )
    required_operation = "configure"
    started_at = timestamp()
    start = time.monotonic()
    image_description = " ".join(
        f"{image_kind}={image_path.name} sha256={image_hash}"
        for image_kind, image_path, image_hash in images
    )
    command_text = f"firmware flash force={str(force).lower()} {image_description}"
    authorization_problem = _authorization_problem(probe_result, required_operation)
    if authorization_problem or not confirmed:
        message_parts = [authorization_problem] if authorization_problem else []
        if not confirmed:
            message_parts.append("Firmware flashing requires explicit confirmation.")
        error_message = " ".join(message_parts)
        completed_at = timestamp()
        run_key = _record_run(
            connection,
            probe_result=probe_result,
            command_id=None,
            command_text=command_text,
            required_operation=required_operation,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=max(0, int((time.monotonic() - start) * 1000)),
            status_value="blocked",
            exit_code=None,
            stdout=b"",
            stderr=error_message.encode("utf-8"),
            error_message=error_message,
        )
        raise DeviceAccessError(f"{error_message} Audit run: {run_key}")

    arguments = [
        str(probe_result["client"]),
        "-p",
        str(probe_result["port"]),
        "-w",
        "--flash",
    ]
    if force:
        arguments.append("--force")
    if bootrom_path is not None:
        arguments.append("--unlock-bootloader")
    for _image_kind, image_path, _image_hash in images:
        arguments.extend(("--image", str(image_path)))
    try:
        completed = _run_captured_process(
            arguments,
            cwd=ROOT,
            timeout_seconds=timeout_seconds,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        exit_code: int | None = completed.returncode
        diagnosis = diagnose_client_output("pm3.firmware-flash", stdout, stderr)
        status_value = "succeeded" if completed.returncode == 0 and diagnosis is None else "failed"
        if diagnosis is not None:
            error_message = diagnosis
        elif completed.returncode != 0:
            error_message = f"Client exited with {completed.returncode}"
        else:
            error_message = None
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        exit_code = None
        status_value = "timed_out"
        error_message = f"Client exceeded timeout of {timeout_seconds} seconds"
    completed_at = timestamp()
    run_key = _record_run(
        connection,
        probe_result=probe_result,
        command_id=None,
        command_text=command_text,
        required_operation=required_operation,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=max(0, int((time.monotonic() - start) * 1000)),
        status_value=status_value,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        error_message=error_message,
    )
    return {
        "run_key": run_key,
        "status": status_value,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "error_message": error_message,
        "images": [
            {"kind": image_kind, "path": image_path, "sha256": image_hash}
            for image_kind, image_path, image_hash in images
        ],
    }


def run_history(connection: Any, limit: int = 20) -> list[dict[str, Any]]:
    if not 1 <= limit <= 1000:
        raise ValueError("History limit must be between 1 and 1000")
    return [
        dict(row)
        for row in connection.execute(
            """
            SELECT runs.run_key, p.project_key, d.device_key, commands.command_key,
                   runs.command_text, runs.required_operation, runs.started_at,
                   runs.duration_ms, runs.status, runs.exit_code, runs.error_message
            FROM device_command_runs AS runs
            JOIN projects AS p ON p.id = runs.project_id
            JOIN devices AS d ON d.id = runs.device_id
            LEFT JOIN device_commands AS commands ON commands.id = runs.command_id
            ORDER BY runs.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    ]
