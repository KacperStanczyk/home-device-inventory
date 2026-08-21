from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parent / "scripts" / "provision_gree_wifi.py"
SPEC = importlib.util.spec_from_file_location("provision_gree_wifi", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load Gree Wi-Fi provisioning module")
PROVISION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROVISION
SPEC.loader.exec_module(PROVISION)


class GreeWifiProvisioningTests(unittest.TestCase):
    def test_dialog_commands_use_a_utf8_locale(self) -> None:
        completed = subprocess.CompletedProcess(["zenity"], 0, "", "")
        with mock.patch.object(PROVISION.subprocess, "run", return_value=completed) as run:
            PROVISION.run_command(
                ["zenity", "--info"],
                timeout_seconds=5,
                utf8_locale=True,
            )
        self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C.UTF-8")

    def test_zenity_dialog_is_attached_to_the_active_window(self) -> None:
        result = subprocess.CompletedProcess(
            ["xprop"],
            0,
            "_NET_ACTIVE_WINDOW(WINDOW): window id # 0x3600004\n",
            "",
        )
        with mock.patch.object(PROVISION, "run_command", return_value=result):
            window_id = PROVISION.active_window_id("xprop")
        self.assertEqual(window_id, str(int("3600004", 16)))
        self.assertEqual(
            PROVISION.dialog_parent_arguments(window_id),
            ["--modal", f"--attach={window_id}"],
        )

    def test_cli_context_requires_exact_script_key(self) -> None:
        self.assertFalse(PROVISION.has_cli_context({}))
        self.assertFalse(
            PROVISION.has_cli_context(
                {
                    "DEVICE_CLI_CONTEXT": "1",
                    "DEVICE_CLI_SCRIPT_KEY": "gree.wifi.discover",
                }
            )
        )
        self.assertTrue(
            PROVISION.has_cli_context(
                {
                    "DEVICE_CLI_CONTEXT": "1",
                    "DEVICE_CLI_SCRIPT_KEY": "gree.wifi.provision",
                }
            )
        )

    def test_connect_arguments_do_not_contain_a_password(self) -> None:
        arguments = PROVISION.connect_arguments("/usr/bin/nmcli", "wlp5s0", "temporary-uuid")
        self.assertIn("connection", arguments)
        self.assertIn("temporary-uuid", arguments)
        self.assertNotIn("password", arguments)
        self.assertNotIn("psk", arguments)
        self.assertNotIn("12345678", arguments)

    def test_temporary_profile_is_pinned_and_has_no_secret(self) -> None:
        arguments = PROVISION.temporary_profile_arguments(
            "/usr/bin/nmcli",
            "wlp5s0",
            "temporary-profile",
            "temporary-uuid",
        )
        self.assertIn("50:2C:C6:B3:99:16", arguments)
        self.assertIn("save", arguments)
        self.assertEqual(arguments[arguments.index("save") + 1], "no")
        self.assertIn("802-11-wireless-security.psk-flags", arguments)
        self.assertIn("not-saved", arguments)
        self.assertNotIn("12345678", arguments)
        self.assertNotIn("802-11-wireless-security.psk", arguments)

    def test_unsaved_target_is_limited_to_same_radio_and_pure_wpa2(self) -> None:
        records = [
            {
                "ssid": "PC",
                "bssid": "E2:4B:A6:CB:3B:01",
                "frequency": "2437 MHz",
                "security": "WPA2",
            },
            {
                "ssid": "Panda visitors",
                "bssid": "E2:4B:A6:CB:3B:00",
                "frequency": "2437 MHz",
                "security": "WPA2 WPA3",
            },
            {
                "ssid": "Neighbor",
                "bssid": "00:11:22:33:44:55",
                "frequency": "2412 MHz",
                "security": "WPA2",
            },
        ]
        with mock.patch.object(PROVISION, "saved_wifi_profiles", return_value=[]):
            profiles = PROVISION.eligible_home_profiles(
                "nmcli",
                records,
                "E2:4B:A6:CB:3B:04",
            )
        self.assertEqual([profile.ssid for profile in profiles], ["PC"])
        self.assertFalse(profiles[0].saved)
        self.assertEqual(profiles[0].uuid, "")

    def test_unsaved_target_password_comes_only_from_hidden_dialog(self) -> None:
        profile = PROVISION.WifiProfile(
            uuid="",
            name="Visible",
            ssid="PC",
            key_management="wpa-psk",
            priority=-100,
            saved=False,
        )
        with (
            mock.patch.object(PROVISION, "nmcli_value") as stored_secret,
            mock.patch.object(PROVISION, "password_prompt", return_value="valid-example") as prompt,
        ):
            value = PROVISION.home_profile_password("nmcli", "zenity", profile, "123")
        self.assertEqual(value, "valid-example")
        stored_secret.assert_not_called()
        prompt.assert_called_once()

    def test_configuration_datagram_is_sent_once_and_not_returned(self) -> None:
        fake_socket = mock.Mock()
        fake_socket.sendto.return_value = 58
        with mock.patch.object(PROVISION.socket, "socket", return_value=fake_socket):
            sent = PROVISION.send_wifi_configuration(
                "Home 2.4",
                "a-secure-example",
                "192.168.1.2",
            )
        self.assertEqual(sent, 58)
        fake_socket.setsockopt.assert_called_once_with(
            PROVISION.socket.SOL_SOCKET,
            PROVISION.socket.SO_DONTROUTE,
            1,
        )
        fake_socket.bind.assert_called_once_with(("192.168.1.2", 0))
        fake_socket.sendto.assert_called_once()
        payload, endpoint = fake_socket.sendto.call_args.args
        self.assertEqual(endpoint, ("192.168.1.1", 7000))
        self.assertEqual(
            json.loads(payload.decode("utf-8")),
            {"psw": "a-secure-example", "ssid": "Home 2.4", "t": "wlan"},
        )
        fake_socket.close.assert_called_once()

    def test_direct_route_rejects_a_gateway(self) -> None:
        route = subprocess.CompletedProcess(
            ["ip"],
            0,
            "192.168.1.1 via 192.168.100.1 dev wlp5s0 src 192.168.100.77\n",
            "",
        )
        with (
            mock.patch.object(PROVISION, "require_active_gree_ap"),
            mock.patch.object(PROVISION, "nmcli_value", return_value="192.168.100.77/24"),
            mock.patch.object(PROVISION, "run_command", return_value=route),
        ):
            with self.assertRaises(PROVISION.ProvisioningError):
                PROVISION.direct_route_source("nmcli", "ip", "wlp5s0", "temporary-uuid")

    def test_direct_route_accepts_only_the_gree_subnet(self) -> None:
        route = subprocess.CompletedProcess(
            ["ip"],
            0,
            "192.168.1.1 dev wlp5s0 src 192.168.1.2 uid 1000\n",
            "",
        )
        with (
            mock.patch.object(PROVISION, "require_active_gree_ap"),
            mock.patch.object(PROVISION, "nmcli_value", return_value="192.168.1.2/24"),
            mock.patch.object(PROVISION, "run_command", return_value=route),
        ):
            source = PROVISION.direct_route_source("nmcli", "ip", "wlp5s0", "temporary-uuid")
        self.assertEqual(source, "192.168.1.2")

    def test_direct_route_stops_on_wrong_active_bssid(self) -> None:
        wrong_access_point = {
            "in_use": "*",
            "ssid": "c6b39916",
            "bssid": "00:11:22:33:44:55",
            "frequency": "2412 MHz",
            "security": "WPA2",
        }
        with (
            mock.patch.object(
                PROVISION,
                "active_connection_uuid",
                return_value="temporary-uuid",
            ),
            mock.patch.object(PROVISION, "visible_wifi", return_value=[wrong_access_point]),
            mock.patch.object(PROVISION, "run_command") as route_command,
        ):
            with self.assertRaises(PROVISION.ProvisioningError):
                PROVISION.direct_route_source("nmcli", "ip", "wlp5s0", "temporary-uuid")
        route_command.assert_not_called()

    def test_cleanup_deletes_only_the_generated_uuid(self) -> None:
        deleted = subprocess.CompletedProcess(["nmcli"], 0, "", "")
        with (
            mock.patch.object(PROVISION, "connection_exists", side_effect=[True, False]),
            mock.patch.object(PROVISION, "run_command", return_value=deleted) as command,
        ):
            self.assertTrue(PROVISION.delete_temporary_profile("nmcli", "temporary-uuid"))
        arguments = command.call_args.args[0]
        self.assertEqual(arguments[-2:], ["uuid", "temporary-uuid"])
        self.assertNotIn("id", arguments)

    def test_psk_validation_rejects_short_and_control_characters(self) -> None:
        with self.assertRaises(PROVISION.ProvisioningError):
            PROVISION.validate_psk("short", "password")
        with self.assertRaises(PROVISION.ProvisioningError):
            PROVISION.validate_psk("long-enough\n", "password")
        with self.assertRaises(PROVISION.ProvisioningError):
            PROVISION.validate_psk("hasło-nie-ascii", "password")
        PROVISION.validate_psk("valid-example", "password")
        PROVISION.validate_psk("A" * 64, "password")


if __name__ == "__main__":
    unittest.main()
