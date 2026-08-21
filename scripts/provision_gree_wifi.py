#!/usr/bin/env python3
"""Provision one authorized Gree Wi-Fi module without the vendor application."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import resource
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import Mapping, Sequence
import uuid as uuid_module


EXPECTED_SCRIPT_KEY = "gree.wifi.provision"
PROJECT_KEY = "home-infrastructure"
GREE_DEVICE_KEY = "appliance:example-gree-air-conditioner"
GREE_AP_SSID = "c6b39916"
GREE_AP_BSSID = "50:2C:C6:B3:99:16"
GREE_AP_ADDRESS = "192.168.1.1"
GREE_UDP_PORT = 7000


class ProvisioningError(RuntimeError):
    """A safe, redacted provisioning error."""


class UserCancelled(ProvisioningError):
    """The user closed one local confirmation dialog."""


class TerminationRequested(ProvisioningError):
    """The managed CLI requested a clean stop."""


@dataclass(frozen=True)
class WifiProfile:
    uuid: str
    name: str
    ssid: str
    key_management: str
    priority: int
    saved: bool


def has_cli_context(environment: Mapping[str, str]) -> bool:
    return (
        environment.get("DEVICE_CLI_CONTEXT") == "1"
        and environment.get("DEVICE_CLI_SCRIPT_KEY") == EXPECTED_SCRIPT_KEY
    )


def split_nmcli_fields(line: str) -> list[str]:
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


def run_command(
    arguments: Sequence[str],
    *,
    timeout_seconds: float,
    input_text: str | None = None,
    utf8_locale: bool = False,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C.UTF-8" if utf8_locale else "C"
    return subprocess.run(
        list(arguments),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        input=input_text,
        env=environment,
    )


def require_program(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise ProvisioningError(f"Required local program is missing: {name}.")
    return value


def active_window_id(xprop: str) -> str:
    result = run_command(
        [xprop, "-root", "_NET_ACTIVE_WINDOW"],
        timeout_seconds=5,
    )
    if result.returncode != 0:
        return ""
    match = re.search(r"\b0x[0-9a-fA-F]+\b", result.stdout)
    if match is None:
        return ""
    value = int(match.group(0), 16)
    return str(value) if value > 0 else ""


def dialog_parent_arguments(parent_window: str) -> list[str]:
    arguments = ["--modal"]
    if parent_window:
        arguments.append(f"--attach={parent_window}")
    return arguments


def nmcli_value(nmcli: str, field: str, *tail: str, show_secrets: bool = False) -> str:
    arguments = [nmcli]
    if show_secrets:
        arguments.append("--show-secrets")
    arguments.extend(["--escape", "no", "--get-values", field, *tail])
    result = run_command(arguments, timeout_seconds=10)
    if result.returncode != 0:
        return ""
    return result.stdout.rstrip("\n")


def wifi_interface(nmcli: str) -> str:
    result = run_command(
        [nmcli, "--terse", "--escape", "yes", "--fields", "DEVICE,TYPE,STATE", "device", "status"],
        timeout_seconds=10,
    )
    if result.returncode != 0:
        raise ProvisioningError("NetworkManager device state is unavailable.")
    fallback = ""
    for line in result.stdout.splitlines():
        fields = split_nmcli_fields(line)
        if len(fields) != 3 or fields[1] != "wifi":
            continue
        if fields[2] == "connected":
            return fields[0]
        if not fallback:
            fallback = fields[0]
    if fallback:
        return fallback
    raise ProvisioningError("No Wi-Fi interface is available on this computer.")


def visible_wifi(
    nmcli: str,
    *,
    interface: str = "",
    rescan: bool = True,
    include_active: bool = False,
) -> list[dict[str, str]]:
    fields = "SSID,BSSID,FREQ,SIGNAL,SECURITY"
    if include_active:
        fields = "IN-USE," + fields
    arguments = [
        nmcli,
        "--terse",
        "--escape",
        "yes",
        "--fields",
        fields,
        "device",
        "wifi",
        "list",
    ]
    if interface:
        arguments.extend(["ifname", interface])
    arguments.extend(["--rescan", "yes" if rescan else "no"])
    result = run_command(
        arguments,
        timeout_seconds=25,
    )
    if result.returncode != 0:
        raise ProvisioningError("The Wi-Fi radio scan failed.")
    records: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        fields = split_nmcli_fields(line)
        expected_count = 6 if include_active else 5
        if len(fields) != expected_count:
            continue
        offset = 1 if include_active else 0
        records.append(
            {
                "in_use": fields[0] if include_active else "",
                "ssid": fields[offset],
                "bssid": fields[offset + 1],
                "frequency": fields[offset + 2],
                "signal": fields[offset + 3],
                "security": fields[offset + 4],
            }
        )
    return records


def frequency_mhz(record: Mapping[str, str]) -> int:
    frequency = re.search(r"\d+", record.get("frequency", ""))
    if frequency is None:
        return 0
    return int(frequency.group(0))


def require_gree_ap(records: Sequence[Mapping[str, str]]) -> Mapping[str, str]:
    for record in records:
        if (
            record.get("ssid") == GREE_AP_SSID
            and record.get("bssid", "").upper() == GREE_AP_BSSID
            and 2400 <= frequency_mhz(record) <= 2500
            and "WPA2" in record.get("security", "").upper()
        ):
            return record
    raise ProvisioningError("The verified Gree pairing access point is no longer visible.")


def saved_wifi_profiles(nmcli: str, visible_ssids: set[str]) -> list[WifiProfile]:
    result = run_command(
        [nmcli, "--terse", "--escape", "yes", "--fields", "UUID,NAME,TYPE", "connection", "show"],
        timeout_seconds=10,
    )
    if result.returncode != 0:
        raise ProvisioningError("Saved NetworkManager profiles are unavailable.")
    profiles: list[WifiProfile] = []
    for line in result.stdout.splitlines():
        fields = split_nmcli_fields(line)
        if len(fields) != 3 or fields[2] not in {"wifi", "802-11-wireless"}:
            continue
        uuid, name, _ = fields
        mode = nmcli_value(
            nmcli,
            "802-11-wireless.mode",
            "connection",
            "show",
            "uuid",
            uuid,
        )
        if mode and mode != "infrastructure":
            continue
        ssid = nmcli_value(nmcli, "802-11-wireless.ssid", "connection", "show", "uuid", uuid)
        if not ssid or ssid == GREE_AP_SSID or ssid not in visible_ssids:
            continue
        key_management = nmcli_value(
            nmcli,
            "802-11-wireless-security.key-mgmt",
            "connection",
            "show",
            "uuid",
            uuid,
        )
        normalized_key_management = key_management.lower()
        if "wpa-psk" not in normalized_key_management:
            continue
        priority_text = nmcli_value(
            nmcli,
            "connection.autoconnect-priority",
            "connection",
            "show",
            "uuid",
            uuid,
        )
        try:
            priority = int(priority_text or "0")
        except ValueError:
            priority = 0
        profiles.append(WifiProfile(uuid, name, ssid, key_management, priority, True))
    profiles.sort(key=lambda profile: (-profile.priority, profile.ssid, profile.name))
    return profiles


def bssid_family(value: str) -> str:
    octets = value.upper().split(":")
    if len(octets) != 6 or any(not re.fullmatch(r"[0-9A-F]{2}", octet) for octet in octets):
        return ""
    return ":".join(octets[:5])


def active_wifi_bssid(nmcli: str, interface: str) -> str:
    for record in visible_wifi(
        nmcli,
        interface=interface,
        rescan=False,
        include_active=True,
    ):
        if record.get("in_use") in {"*", "yes"}:
            return str(record.get("bssid", "")).upper()
    raise ProvisioningError("The active home Wi-Fi BSSID is unavailable.")


def eligible_home_profiles(
    nmcli: str,
    records: Sequence[Mapping[str, str]],
    active_bssid: str,
) -> list[WifiProfile]:
    family = bssid_family(active_bssid)
    if not family:
        raise ProvisioningError("The active home Wi-Fi BSSID is not valid.")
    eligible_ssids = {
        str(record["ssid"])
        for record in records
        if record.get("ssid")
        and record.get("ssid") != GREE_AP_SSID
        and 2400 <= frequency_mhz(record) <= 2500
        and record.get("security", "").upper().strip() == "WPA2"
        and bssid_family(str(record.get("bssid", ""))) == family
    }
    profiles = saved_wifi_profiles(nmcli, eligible_ssids)
    saved_ssids = {profile.ssid for profile in profiles}
    for ssid in sorted(eligible_ssids - saved_ssids):
        profiles.append(
            WifiProfile(
                uuid="",
                name="Widoczna sieć 2,4 GHz - hasło wymagane",
                ssid=ssid,
                key_management="wpa-psk",
                priority=-100,
                saved=False,
            )
        )
    profiles.sort(key=lambda profile: (-profile.priority, profile.ssid, profile.name))
    return profiles


def choose_profile(
    zenity: str,
    profiles: Sequence[WifiProfile],
    parent_window: str,
) -> WifiProfile:
    if not profiles:
        raise ProvisioningError("No saved WPA/WPA2 profile is visible on 2.4 GHz.")
    arguments = [
        zenity,
        "--list",
        "--radiolist",
        "--title=Gree - wybierz sieć domową 2,4 GHz",
        "--text=Wybierz sieć, do której ma dołączyć klimatyzator.",
        "--width=760",
        "--height=420",
        "--column=Wybór",
        "--column=SSID",
        "--column=Profil NetworkManager",
        "--column=Priorytet",
        "--column=Indeks",
        "--hide-column=5",
        "--print-column=5",
        *dialog_parent_arguments(parent_window),
    ]
    for index, profile in enumerate(profiles):
        arguments.extend(
            [
                "TRUE" if index == 0 else "FALSE",
                profile.ssid,
                profile.name,
                str(profile.priority),
                str(index),
            ]
        )
    result = run_command(arguments, timeout_seconds=180, utf8_locale=True)
    if result.returncode != 0:
        raise UserCancelled(
            f"Home Wi-Fi selection dialog ended with code {result.returncode}."
        )
    if not result.stdout.strip():
        raise UserCancelled("Home Wi-Fi selection returned no profile UUID.")
    try:
        selected_index = int(result.stdout.strip())
    except ValueError:
        raise ProvisioningError("The selected Wi-Fi target is not valid.") from None
    if not 0 <= selected_index < len(profiles):
        raise ProvisioningError("The selected Wi-Fi target is outside the available list.")
    return profiles[selected_index]


def password_prompt(
    zenity: str,
    title: str,
    text: str,
    parent_window: str,
) -> str:
    result = run_command(
        [
            zenity,
            "--password",
            f"--title={title}",
            f"--text={text}",
            "--width=520",
            *dialog_parent_arguments(parent_window),
        ],
        timeout_seconds=180,
        utf8_locale=True,
    )
    if result.returncode != 0:
        raise UserCancelled(f"{title} was cancelled.")
    value = result.stdout.rstrip("\n")
    if not value:
        raise ProvisioningError(f"{title} is empty.")
    return value


def question(zenity: str, title: str, text: str, parent_window: str) -> None:
    result = run_command(
        [
            zenity,
            "--question",
            f"--title={title}",
            f"--text={text}",
            "--width=560",
            *dialog_parent_arguments(parent_window),
        ],
        timeout_seconds=180,
        utf8_locale=True,
    )
    if result.returncode != 0:
        raise UserCancelled(f"{title} was cancelled.")


def validate_psk(value: str, label: str) -> None:
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ProvisioningError(f"{label} contains an unsupported control character.")
    if len(value) == 64 and re.fullmatch(r"[0-9A-Fa-f]{64}", value):
        return
    if not value.isascii() or not 8 <= len(value) <= 63:
        raise ProvisioningError(
            f"{label} must contain 8 to 63 ASCII characters or exactly 64 hexadecimal characters."
        )


def home_profile_password(
    nmcli: str,
    zenity: str,
    profile: WifiProfile,
    parent_window: str,
) -> str:
    value = ""
    if profile.saved and profile.uuid:
        value = nmcli_value(
            nmcli,
            "802-11-wireless-security.psk",
            "connection",
            "show",
            "uuid",
            profile.uuid,
            show_secrets=True,
        )
    if not value:
        value = password_prompt(
            zenity,
            "Hasło domowej sieci Wi-Fi",
            f"Wpisz hasło sieci {profile.ssid}. Nie wpisuj go w czacie.",
            parent_window,
        )
    validate_psk(value, "Home Wi-Fi password")
    if len(value) > 31:
        question(
            zenity,
            "Długie hasło Wi-Fi",
            "Niektóre starsze moduły Gree przyjmują maksymalnie 31 znaków. Kontynuować próbę?",
            parent_window,
        )
    return value


def active_connection_uuid(nmcli: str, interface: str) -> str:
    return nmcli_value(nmcli, "GENERAL.CON-UUID", "device", "show", interface)


def temporary_profile_arguments(
    nmcli: str,
    interface: str,
    temporary_name: str,
    temporary_uuid: str,
) -> list[str]:
    owner = pwd.getpwuid(os.geteuid()).pw_name
    return [
        nmcli,
        "--wait",
        "10",
        "connection",
        "add",
        "type",
        "wifi",
        "ifname",
        interface,
        "con-name",
        temporary_name,
        "autoconnect",
        "no",
        "save",
        "no",
        "ssid",
        GREE_AP_SSID,
        "--",
        "connection.uuid",
        temporary_uuid,
        "connection.permissions",
        f"user:{owner}",
        "802-11-wireless.mode",
        "infrastructure",
        "802-11-wireless.bssid",
        GREE_AP_BSSID,
        "802-11-wireless-security.key-mgmt",
        "wpa-psk",
        "802-11-wireless-security.psk-flags",
        "not-saved",
        "ipv4.method",
        "auto",
        "ipv4.never-default",
        "yes",
        "ipv4.ignore-auto-dns",
        "yes",
        "ipv6.method",
        "disabled",
    ]


def connect_arguments(nmcli: str, interface: str, temporary_uuid: str) -> list[str]:
    return [
        nmcli,
        "--wait",
        "60",
        "connection",
        "up",
        "uuid",
        temporary_uuid,
        "ifname",
        interface,
        "ap",
        GREE_AP_BSSID,
        "passwd-file",
        "/dev/stdin",
    ]


def wait_for_connection(nmcli: str, interface: str, expected_uuid: str, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        active_uuid = active_connection_uuid(nmcli, interface)
        address = nmcli_value(nmcli, "IP4.ADDRESS", "device", "show", interface)
        if active_uuid == expected_uuid and address:
            return True
        time.sleep(1)
    return False


def require_active_gree_ap(nmcli: str, interface: str, expected_uuid: str) -> None:
    if active_connection_uuid(nmcli, interface) != expected_uuid:
        raise ProvisioningError("The temporary Gree profile is not active on the Wi-Fi interface.")
    records = visible_wifi(
        nmcli,
        interface=interface,
        rescan=False,
        include_active=True,
    )
    for record in records:
        if record.get("in_use") not in {"*", "yes"}:
            continue
        require_gree_ap([record])
        return
    raise ProvisioningError("NetworkManager does not report the verified Gree BSSID as active.")


def direct_route_source(
    nmcli: str,
    ip_program: str,
    interface: str,
    expected_uuid: str,
) -> str:
    require_active_gree_ap(nmcli, interface, expected_uuid)
    address_text = nmcli_value(nmcli, "IP4.ADDRESS", "device", "show", interface)
    interface_addresses: dict[str, ipaddress.IPv4Interface] = {}
    for value in address_text.splitlines():
        try:
            address = ipaddress.ip_interface(value)
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv4Interface):
            interface_addresses[str(address.ip)] = address
    if not interface_addresses:
        raise ProvisioningError("The Gree Wi-Fi interface has no usable IPv4 address.")

    result = run_command(
        [ip_program, "-4", "route", "get", GREE_AP_ADDRESS],
        timeout_seconds=10,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise ProvisioningError("The route to the Gree module is unavailable.")
    tokens = result.stdout.split()
    if "via" in tokens:
        raise ProvisioningError("The Gree address is routed through a gateway, not directly to its access point.")
    try:
        route_interface = tokens[tokens.index("dev") + 1]
        source = tokens[tokens.index("src") + 1]
    except (ValueError, IndexError):
        raise ProvisioningError("The route to the Gree module has an unexpected format.") from None
    if route_interface != interface:
        raise ProvisioningError("The Gree route uses a different network interface.")
    if source not in interface_addresses:
        raise ProvisioningError("The Gree route uses an unexpected source address.")
    target = ipaddress.ip_address(GREE_AP_ADDRESS)
    if target not in interface_addresses[source].network:
        raise ProvisioningError("The Gree address is not on the directly connected Wi-Fi subnet.")
    return source


def send_wifi_configuration(ssid: str, psk: str, source_ipv4: str) -> int:
    payload = json.dumps(
        {"psw": psk, "ssid": ssid, "t": "wlan"},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    target = ipaddress.ip_address(GREE_AP_ADDRESS)
    if not target.is_private:
        raise ProvisioningError("The Gree provisioning target is not a private address.")
    provisioning_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        provisioning_socket.settimeout(3)
        provisioning_socket.setsockopt(socket.SOL_SOCKET, socket.SO_DONTROUTE, 1)
        provisioning_socket.bind((source_ipv4, 0))
        sent = provisioning_socket.sendto(payload, (str(target), GREE_UDP_PORT))
    finally:
        provisioning_socket.close()
        payload = b""
    return sent


def reconnect(
    nmcli: str,
    interface: str,
    original_uuid: str,
    fallback_uuid: str,
) -> bool:
    target_uuid = original_uuid or fallback_uuid
    if not target_uuid:
        return False
    result = run_command(
        [
            nmcli,
            "--wait",
            "45",
            "connection",
            "up",
            "uuid",
            target_uuid,
            "ifname",
            interface,
        ],
        timeout_seconds=50,
    )
    if result.returncode != 0:
        return False
    return wait_for_connection(nmcli, interface, target_uuid, 20)


def delete_temporary_profile(nmcli: str, temporary_uuid: str) -> bool:
    if not connection_exists(nmcli, temporary_uuid):
        return True
    result = run_command(
        [nmcli, "--wait", "15", "connection", "delete", "uuid", temporary_uuid],
        timeout_seconds=20,
    )
    return result.returncode == 0 and not connection_exists(nmcli, temporary_uuid)


def connection_exists(nmcli: str, connection_uuid: str) -> bool:
    value = nmcli_value(
        nmcli,
        "connection.uuid",
        "connection",
        "show",
        "uuid",
        connection_uuid,
    )
    return value == connection_uuid


def discover_on_home_network(repository: Path) -> tuple[bool, str]:
    result = run_command(
        [
            str(repository / "rfid_vault.py"),
            "device-script-run",
            "gree.wifi.discover",
            "--project",
            PROJECT_KEY,
            "--device",
            GREE_DEVICE_KEY,
        ],
        timeout_seconds=50,
    )
    output = (result.stdout + result.stderr).strip()
    return "GREE_UDP_RESPONSE " in output, output


def discover_from_raspberry(repository: Path) -> tuple[bool, str]:
    result = run_command(
        [
            str(repository / "rfid_vault.py"),
            "device-script-run",
            "raspberry.gree-wifi.discover",
            "--project",
            PROJECT_KEY,
            "--device",
            "computer:raspberry-pi-3",
        ],
        timeout_seconds=60,
    )
    output = (result.stdout + result.stderr).strip()
    return "GREE_UDP_RESPONSE " in output, output


def disable_core_dumps() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError):
        raise ProvisioningError("This process could not disable core dumps.") from None


def termination_handler(_signal_number: int, _frame: object) -> None:
    raise TerminationRequested("Provisioning was interrupted; rollback started.")


def main() -> int:
    if os.environ.get("DEVICE_CLI_CONTEXT") != "1" or os.environ.get("DEVICE_CLI_SCRIPT_KEY") != EXPECTED_SCRIPT_KEY:
        print(
            "Error: run this operation through rfid_vault.py device-script-run gree.wifi.provision.",
            file=sys.stderr,
        )
        return 2

    repository = Path(__file__).resolve().parents[1]
    nmcli = ""
    zenity = ""
    ip_program = ""
    xprop = ""
    parent_window = ""
    interface = ""
    original_uuid = ""
    profile: WifiProfile | None = None
    home_psk = ""
    gree_ap_psk = ""
    temporary_uuid = str(uuid_module.uuid4())
    temporary_name = f"codex-gree-{temporary_uuid[:8]}"
    temporary_created = False
    datagram_sent = False
    reconnected = True
    temporary_deleted = True
    old_signal_handlers: dict[int, object] = {}
    failure = ""

    try:
        disable_core_dumps()
        nmcli = require_program("nmcli")
        zenity = require_program("zenity")
        ip_program = require_program("ip")
        xprop = require_program("xprop")
        parent_window = active_window_id(xprop)
        interface = wifi_interface(nmcli)
        records = visible_wifi(nmcli, interface=interface)
        require_gree_ap(records)
        profiles = eligible_home_profiles(
            nmcli,
            records,
            active_wifi_bssid(nmcli, interface),
        )
        profile = choose_profile(zenity, profiles, parent_window)
        original_uuid = active_connection_uuid(nmcli, interface)
        if not original_uuid:
            raise ProvisioningError("The original Wi-Fi connection UUID is unavailable.")
        home_psk = home_profile_password(nmcli, zenity, profile, parent_window)
        gree_ap_psk = password_prompt(
            zenity,
            "Hasło punktu Gree",
            f"Wpisz hasło punktu {GREE_AP_SSID} podane w instrukcji Gree.",
            parent_window,
        )
        validate_psk(gree_ap_psk, "Gree access point password")
        question(
            zenity,
            "Potwierdź provisioning Gree",
            (
                f"PC odłączy się na krótko od bieżącej sieci. Klimatyzator otrzyma ustawienia "
                f"sieci {profile.ssid}. Hasła nie zostaną zapisane w rejestrze. Kontynuować?"
            ),
            parent_window,
        )

        # Recheck the exact radio target immediately before the first mutation.
        require_gree_ap(visible_wifi(nmcli, interface=interface))
        for signal_number in (signal.SIGINT, signal.SIGTERM):
            old_signal_handlers[signal_number] = signal.getsignal(signal_number)
            signal.signal(signal_number, termination_handler)

        try:
            add_result = run_command(
                temporary_profile_arguments(
                    nmcli,
                    interface,
                    temporary_name,
                    temporary_uuid,
                ),
                timeout_seconds=20,
            )
            if add_result.returncode != 0:
                raise ProvisioningError("NetworkManager could not create the isolated Gree profile.")
            temporary_created = True
            temporary_deleted = False

            connect_result = run_command(
                connect_arguments(nmcli, interface, temporary_uuid),
                timeout_seconds=70,
                input_text="802-11-wireless-security.psk:" + gree_ap_psk + "\n",
            )
            if connect_result.returncode != 0:
                raise ProvisioningError("NetworkManager could not connect to the Gree access point.")
            if not wait_for_connection(nmcli, interface, temporary_uuid, 20):
                raise ProvisioningError("The Gree access point did not assign an IPv4 address.")

            source_ipv4 = direct_route_source(
                nmcli,
                ip_program,
                interface,
                temporary_uuid,
            )
            sent = send_wifi_configuration(profile.ssid, home_psk, source_ipv4)
            if sent <= 0:
                raise ProvisioningError("The Gree Wi-Fi configuration datagram was not sent.")
            datagram_sent = True
            print(
                f"PASS one provisioning datagram sent to {GREE_AP_ADDRESS}:{GREE_UDP_PORT}; "
                "credentials were not logged"
            )
            home_psk = ""
            gree_ap_psk = ""
            time.sleep(10)
        finally:
            home_psk = ""
            gree_ap_psk = ""
            try:
                if temporary_created:
                    restore_uuid = original_uuid or profile.uuid
                    if active_connection_uuid(nmcli, interface) == restore_uuid:
                        reconnected = wait_for_connection(nmcli, interface, restore_uuid, 5)
                    else:
                        reconnected = reconnect(nmcli, interface, original_uuid, profile.uuid)
                    if reconnected:
                        temporary_deleted = delete_temporary_profile(nmcli, temporary_uuid)
                    else:
                        temporary_deleted = delete_temporary_profile(nmcli, temporary_uuid)
                        reconnected = reconnect(nmcli, interface, original_uuid, profile.uuid)
                else:
                    reconnected = True
                    temporary_deleted = True
            except (OSError, subprocess.TimeoutExpired, ProvisioningError):
                reconnected = False
                temporary_deleted = False
            finally:
                for signal_number, old_handler in old_signal_handlers.items():
                    signal.signal(signal_number, old_handler)
    except KeyboardInterrupt:
        failure = "Provisioning was interrupted; rollback completed."
    except (OSError, subprocess.TimeoutExpired, ProvisioningError) as error:
        failure = str(error)
    finally:
        home_psk = ""
        gree_ap_psk = ""

    if failure:
        print(f"FAIL {failure}", file=sys.stderr)
        if not temporary_created:
            return 1

    if not reconnected:
        print("FAIL PC did not reconnect to the saved home Wi-Fi profile.", file=sys.stderr)
        return 1
    if not temporary_deleted:
        print("FAIL The isolated temporary NetworkManager profile was not deleted.", file=sys.stderr)
        return 1
    if temporary_created:
        print("PASS PC reconnected to its saved home Wi-Fi profile")
    if not datagram_sent:
        return 1

    for attempt in range(1, 4):
        found, output = discover_on_home_network(repository)
        if output:
            print(f"INFO discovery-attempt={attempt}")
            print(output)
        if found:
            print("PASS Gree joined the home LAN and answered the local discovery request")
            return 0
        raspberry_found, raspberry_output = discover_from_raspberry(repository)
        if raspberry_output:
            print(f"INFO raspberry-discovery-attempt={attempt}")
            print(raspberry_output)
        if raspberry_found:
            print("PASS Gree joined the home LAN and answered Raspberry Pi discovery")
            return 0
        if attempt < 3:
            time.sleep(12)
    print(
        "FAIL The configuration datagram was sent, but Gree did not answer on the home LAN.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
