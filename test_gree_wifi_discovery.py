from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parent / "scripts" / "discover_gree_wifi.py"
SPEC = importlib.util.spec_from_file_location("discover_gree_wifi", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load Gree Wi-Fi discovery module")
DISCOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DISCOVERY)


class GreeWifiDiscoveryTests(unittest.TestCase):
    def test_cli_context_requires_both_values(self) -> None:
        self.assertFalse(DISCOVERY.has_cli_context({}))
        self.assertFalse(DISCOVERY.has_cli_context({"DEVICE_CLI_CONTEXT": "1"}))
        self.assertFalse(
            DISCOVERY.has_cli_context(
                {
                    "DEVICE_CLI_CONTEXT": "1",
                    "DEVICE_CLI_SCRIPT_KEY": "another.command",
                }
            )
        )
        self.assertTrue(
            DISCOVERY.has_cli_context(
                {
                    "DEVICE_CLI_CONTEXT": "1",
                    "DEVICE_CLI_SCRIPT_KEY": "gree.wifi.discover",
                }
            )
        )

    def test_nmcli_parser_keeps_escaped_colons_and_backslashes(self) -> None:
        self.assertEqual(
            DISCOVERY.split_nmcli_fields(r"GR-AC_001:AA\:BB\:CC\:DD\:EE\:FF:2412:80:WPA2"),
            ["GR-AC_001", "AA:BB:CC:DD:EE:FF", "2412", "80", "WPA2"],
        )
        self.assertEqual(DISCOVERY.split_nmcli_fields(r"name\\part:value"), [r"name\part", "value"])

    def test_gree_pairing_ssid_formats_require_2_4_ghz(self) -> None:
        self.assertEqual(DISCOVERY.gree_ssid_format("GR-AC_123", 2412), "gr-ac")
        self.assertEqual(DISCOVERY.gree_ssid_format("1ee0ab08", 2462), "hex")
        self.assertEqual(DISCOVERY.gree_ssid_format("a9f0", 2437), "hex")
        self.assertEqual(
            DISCOVERY.gree_ssid_format("Gree123Z", 2437),
            "alphanumeric-possible",
        )
        self.assertIsNone(DISCOVERY.gree_ssid_format("1ee0ab08", 5180))
        self.assertIsNone(DISCOVERY.gree_ssid_format("Home WiFi", 2412))

    def test_udp_response_parser_accepts_only_pack_records(self) -> None:
        parsed = DISCOVERY.parse_gree_response(
            b'{"t":"pack","i":1,"uid":0,"cid":"aabbccddeeff","pack":"encoded"}'
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["type"], "pack")
        self.assertEqual(parsed["cid"], "aabbccddeeff")
        self.assertIsNone(DISCOVERY.parse_gree_response(b'{"t":"status","pack":"encoded"}'))
        self.assertIsNone(DISCOVERY.parse_gree_response(b"not-json"))

    def test_inventory_target_must_be_on_the_active_private_subnet(self) -> None:
        interface = DISCOVERY.ipaddress.ip_interface("192.168.100.77/24")
        targets = DISCOVERY.discovery_targets(
            interface,
            "192.168.100.255",
            "192.168.100.85",
        )
        self.assertIn("192.168.100.85", targets)
        external_targets = DISCOVERY.discovery_targets(
            interface,
            "192.168.100.255",
            "203.0.113.10",
        )
        self.assertNotIn("203.0.113.10", external_targets)


if __name__ == "__main__":
    unittest.main()
