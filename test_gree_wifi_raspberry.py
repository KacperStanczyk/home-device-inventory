from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parent / "scripts" / "discover_gree_wifi_from_raspberry.py"
SPEC = importlib.util.spec_from_file_location("discover_gree_wifi_from_raspberry", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load Raspberry Gree Wi-Fi discovery module")
DISCOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DISCOVERY)


class RaspberryGreeWifiDiscoveryTests(unittest.TestCase):
    def test_cli_context_requires_exact_script_key(self) -> None:
        self.assertFalse(DISCOVERY.has_cli_context({}))
        self.assertFalse(
            DISCOVERY.has_cli_context(
                {
                    "DEVICE_CLI_CONTEXT": "1",
                    "DEVICE_CLI_SCRIPT_KEY": "gree.wifi.discover",
                }
            )
        )
        self.assertTrue(
            DISCOVERY.has_cli_context(
                {
                    "DEVICE_CLI_CONTEXT": "1",
                    "DEVICE_CLI_SCRIPT_KEY": "raspberry.gree-wifi.discover",
                }
            )
        )

    def test_ssh_arguments_are_strict_and_use_no_password(self) -> None:
        arguments = DISCOVERY.ssh_arguments("192.0.2.82", "inventory-user")
        self.assertEqual(arguments[0], "ssh")
        self.assertIn("StrictHostKeyChecking=yes", arguments)
        self.assertIn("PasswordAuthentication=no", arguments)
        self.assertIn("inventory-user@192.0.2.82", arguments)
        self.assertEqual(arguments[-2:], ["python3", "-"])


if __name__ == "__main__":
    unittest.main()
