#!/usr/bin/env python3
"""Find one authorized Gree Wi-Fi module without sending control commands."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence


EXPECTED_SCRIPT_KEY = "gree.wifi.discover"
GREE_SCAN_PAYLOAD = b'{"t":"scan"}'
GREE_UDP_PORT = 7000
GR_AC_SSID = re.compile(r"^GR-AC_.+$", re.IGNORECASE)
HEX_SSID = re.compile(r"^[0-9a-f]{1,32}$", re.IGNORECASE)
ALPHANUMERIC_SSID = re.compile(r"^[0-9a-z]{1,32}$", re.IGNORECASE)


def has_cli_context(environment: Mapping[str, str]) -> bool:
    """Return true only for the reviewed CLI execution context."""
    return (
        environment.get("DEVICE_CLI_CONTEXT") == "1"
        and environment.get("DEVICE_CLI_SCRIPT_KEY") == EXPECTED_SCRIPT_KEY
    )


def split_nmcli_fields(line: str) -> list[str]:
    """Split one escaped nmcli terse record."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def gree_ssid_format(ssid: str, frequency_mhz: int) -> str | None:
    """Return the documented Gree pairing SSID format, if it matches."""
    if not 2400 <= frequency_mhz <= 2500:
        return None
    if GR_AC_SSID.fullmatch(ssid):
        return "gr-ac"
    if HEX_SSID.fullmatch(ssid):
        return "hex"
    if ALPHANUMERIC_SSID.fullmatch(ssid):
        return "alphanumeric-possible"
    return None


def run_command(arguments: Sequence[str], timeout_seconds: float) -> subprocess.CompletedProcess[str]:
    """Run one local command without a shell."""
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    return subprocess.run(
        list(arguments),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        env=environment,
    )


def scan_wifi() -> tuple[list[dict[str, Any]], str | None]:
    """Read Wi-Fi beacons and return only documented Gree SSID candidates."""
    nmcli = shutil.which("nmcli")
    if nmcli is None:
        return [], "nmcli is not installed on this computer."
    try:
        result = run_command(
            [
                nmcli,
                "--terse",
                "--escape",
                "yes",
                "--fields",
                "SSID,BSSID,FREQ,SIGNAL,SECURITY",
                "device",
                "wifi",
                "list",
                "--rescan",
                "yes",
            ],
            25,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return [], f"Wi-Fi scan could not start: {type(error).__name__}."
    if result.returncode != 0:
        reason = result.stderr.strip() or f"exit code {result.returncode}"
        return [], f"Wi-Fi scan failed: {reason}"

    candidates: list[dict[str, Any]] = []
    network_count = 0
    for line in result.stdout.splitlines():
        fields = split_nmcli_fields(line)
        if len(fields) != 5:
            continue
        ssid, bssid, frequency_text, signal_text, security = fields
        frequency_match = re.search(r"\d+", frequency_text)
        signal_match = re.search(r"\d+", signal_text)
        if frequency_match is None:
            continue
        network_count += 1
        frequency_mhz = int(frequency_match.group(0))
        candidate_format = gree_ssid_format(ssid, frequency_mhz)
        if candidate_format is None:
            continue
        candidates.append(
            {
                "bssid": bssid,
                "format": candidate_format,
                "frequency_mhz": frequency_mhz,
                "security": security,
                "signal": int(signal_match.group(0)) if signal_match else None,
                "ssid": ssid,
            }
        )
    candidates.sort(key=lambda item: item["signal"] if item["signal"] is not None else -1, reverse=True)
    confirmed_count = sum(item["format"] != "alphanumeric-possible" for item in candidates)
    possible_count = len(candidates) - confirmed_count
    print(
        f"WIFI_SCAN networks={network_count} candidates={confirmed_count} "
        f"possible={possible_count}"
    )
    return candidates, None


def default_private_network() -> tuple[str, ipaddress.IPv4Interface, str | None]:
    """Return the default interface and its private IPv4 network."""
    ip_command = shutil.which("ip")
    if ip_command is None:
        raise RuntimeError("ip is not installed on this computer.")
    route_result = run_command([ip_command, "-j", "-4", "route", "show", "default"], 5)
    if route_result.returncode != 0:
        raise RuntimeError(route_result.stderr.strip() or "Default route is unavailable.")
    routes = json.loads(route_result.stdout or "[]")
    interface_name = next((str(route.get("dev")) for route in routes if route.get("dev")), "")
    if not interface_name:
        raise RuntimeError("Default network interface is unavailable.")

    address_result = run_command([ip_command, "-j", "-4", "address", "show", "dev", interface_name], 5)
    if address_result.returncode != 0:
        raise RuntimeError(address_result.stderr.strip() or "Default interface address is unavailable.")
    interface_records = json.loads(address_result.stdout or "[]")
    for record in interface_records:
        for address in record.get("addr_info", []):
            if address.get("family") != "inet" or address.get("scope") != "global":
                continue
            value = ipaddress.ip_interface(f"{address['local']}/{address['prefixlen']}")
            if isinstance(value, ipaddress.IPv4Interface) and value.ip.is_private:
                return interface_name, value, address.get("broadcast")
    raise RuntimeError("The default interface has no private IPv4 address.")


def parse_gree_response(payload: bytes) -> dict[str, Any] | None:
    """Return safe top-level fields from one Gree discovery response."""
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("t") != "pack" or "pack" not in value:
        return None
    return {
        "cid": value.get("cid"),
        "i": value.get("i"),
        "tcid": value.get("tcid"),
        "type": value.get("t"),
        "uid": value.get("uid"),
    }


def discovery_targets(
    interface_value: ipaddress.IPv4Interface,
    configured_broadcast: str | None,
    inventory_address: str | None,
) -> set[str]:
    """Return broadcasts and one authorized inventory address on this subnet."""
    targets = {
        str(interface_value.network.broadcast_address),
        "255.255.255.255",
    }
    if configured_broadcast:
        targets.add(str(configured_broadcast))
    if inventory_address:
        try:
            inventory_ip = ipaddress.ip_address(inventory_address)
        except ValueError:
            inventory_ip = None
        if isinstance(inventory_ip, ipaddress.IPv4Address) and inventory_ip in interface_value.network:
            targets.add(str(inventory_ip))
    return targets


def discover_gree_udp(
    timeout_seconds: float = 5.0,
    inventory_address: str | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Send only the documented read-only Gree discovery packet."""
    try:
        interface_name, interface_value, configured_broadcast = default_private_network()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        return [], f"UDP discovery has no usable home network: {error}"

    targets = discovery_targets(interface_value, configured_broadcast, inventory_address)

    discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        discovery_socket.bind((str(interface_value.ip), 0))
        discovery_socket.setblocking(False)
        for target in sorted(targets):
            discovery_socket.sendto(GREE_SCAN_PAYLOAD, (target, GREE_UDP_PORT))

        print(
            "UDP_SCAN "
            + json.dumps(
                {
                    "interface": interface_name,
                    "local_ip": str(interface_value.ip),
                    "port": GREE_UDP_PORT,
                    "targets": sorted(targets),
                },
                sort_keys=True,
            )
        )
        deadline = time.monotonic() + timeout_seconds
        responses: list[dict[str, Any]] = []
        seen: set[tuple[str, int, bytes]] = set()
        while time.monotonic() < deadline:
            readable, _, _ = select.select([discovery_socket], [], [], min(0.25, deadline - time.monotonic()))
            if not readable:
                continue
            payload, source = discovery_socket.recvfrom(8192)
            key = (source[0], source[1], payload)
            if key in seen or source[0] == str(interface_value.ip):
                continue
            seen.add(key)
            parsed = parse_gree_response(payload)
            if parsed is None:
                continue
            parsed.update({"bytes": len(payload), "ip": source[0], "port": source[1]})
            responses.append(parsed)
        responses.sort(key=lambda item: (item["ip"], item["port"]))
        return responses, None
    except OSError as error:
        return [], f"UDP discovery failed: {error}"
    finally:
        discovery_socket.close()


def main() -> int:
    if os.environ.get("DEVICE_CLI_CONTEXT") != "1" or os.environ.get("DEVICE_CLI_SCRIPT_KEY") != EXPECTED_SCRIPT_KEY:
        print(
            "Error: run this operation through rfid_vault.py device-script-run gree.wifi.discover.",
            file=sys.stderr,
        )
        return 2

    print(f"INFO time={time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    wifi_candidates, wifi_error = scan_wifi()
    confirmed_wifi = [
        candidate for candidate in wifi_candidates if candidate["format"] != "alphanumeric-possible"
    ]
    possible_wifi = [
        candidate for candidate in wifi_candidates if candidate["format"] == "alphanumeric-possible"
    ]
    for candidate in confirmed_wifi:
        print("WIFI_CANDIDATE " + json.dumps(candidate, ensure_ascii=True, sort_keys=True))
    for candidate in possible_wifi:
        print("WIFI_POSSIBLE " + json.dumps(candidate, ensure_ascii=True, sort_keys=True))
    if wifi_error:
        print(f"WARN {wifi_error}", file=sys.stderr)

    udp_responses, udp_error = discover_gree_udp(
        inventory_address=os.environ.get("DEVICE_CLI_DEVICE_ADDRESS")
    )
    for response in udp_responses:
        print("GREE_UDP_RESPONSE " + json.dumps(response, ensure_ascii=True, sort_keys=True))
    if udp_error:
        print(f"WARN {udp_error}", file=sys.stderr)

    result = {
        "errors": int(wifi_error is not None) + int(udp_error is not None),
        "udp_devices": len(udp_responses),
        "visible": bool(confirmed_wifi or udp_responses),
        "wifi_candidates": len(confirmed_wifi),
        "wifi_possible": len(possible_wifi),
    }
    print("RESULT " + json.dumps(result, sort_keys=True))
    return 1 if wifi_error is not None and udp_error is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())
