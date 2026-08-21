from __future__ import annotations

import contextlib
import argparse
from datetime import datetime
import io
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import rfid_device
import rfid_vault


PRIVATE_RASPBERRY_ROOT = rfid_vault.ROOT.parent / "Raspberry"
PRIVATE_RASPBERRY_CREDENTIAL_SCRIPT = PRIVATE_RASPBERRY_ROOT / "save-raspberry-passwords.sh"
PRIVATE_RASPBERRY_POWER_SCRIPT = PRIVATE_RASPBERRY_ROOT / "diagnose-raspberry-power.sh"
PRIVATE_RASPBERRY_HARDWARE_SCRIPT = PRIVATE_RASPBERRY_ROOT / "discover-raspberry-attached-hardware.sh"


class RFIDVaultCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "test.sqlite3"
        self.connection = rfid_vault.open_database(self.database_path)
        rfid_vault.initialize(self.connection)

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary_directory.cleanup()

    def test_initialization_is_idempotent_and_creates_default_project(self) -> None:
        rfid_vault.initialize(self.connection)

        self.assertEqual(self.connection.execute("PRAGMA user_version").fetchone()[0], 7)
        self.assertEqual(
            self.connection.execute(
                "SELECT value FROM schema_info WHERE key = 'schema_version'"
            ).fetchone()[0],
            "7",
        )
        project = self.connection.execute(
            "SELECT project_key, purpose, status FROM projects"
        ).fetchone()
        self.assertEqual(tuple(project), ("rfid-home-lab", "education_and_home", "active"))
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM projects").fetchone()[0], 2)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM device_commands").fetchone()[0], 7)
        raspberry = self.connection.execute(
            "SELECT device_type_key FROM devices WHERE device_key = 'computer:raspberry-pi-3'"
        ).fetchone()
        self.assertEqual(raspberry[0], "computing.raspberry_pi_3")
        script = self.connection.execute(
            "SELECT script_key, required_operation, interactive, script_sha256, script_revision FROM device_scripts"
        ).fetchone()
        if PRIVATE_RASPBERRY_CREDENTIAL_SCRIPT.is_file():
            self.assertEqual(tuple(script[:3]), ("raspberry.credentials.sync", "administer", 1))
            self.assertRegex(script["script_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(script["script_revision"], 1)
        else:
            self.assertIsNone(script)

    def test_initialization_skips_an_absent_private_raspberry_script(self) -> None:
        isolated_directory = Path(self.temporary_directory.name) / "source-only-clone"
        isolated_directory.mkdir()
        isolated_database = Path(self.temporary_directory.name) / "source-only.sqlite3"
        isolated_connection = rfid_vault.open_database(isolated_database)
        try:
            with mock.patch.object(rfid_vault, "ROOT", isolated_directory):
                rfid_vault.initialize(isolated_connection)
            script = isolated_connection.execute(
                "SELECT script_key FROM device_scripts WHERE script_key = 'raspberry.credentials.sync'"
            ).fetchone()
            self.assertIsNone(script)
        finally:
            isolated_connection.close()

    def test_device_is_denied_until_per_device_access_is_granted(self) -> None:
        rfid_vault.add_device(
            self.connection,
            project_key="rfid-home-lab",
            device_key="reader:test-01",
            name="Test reader",
            device_kind="rfid_reader",
            role="tool",
            ownership_status="user_owned",
            now="2026-08-03T10:00:00+02:00",
        )

        scope_status = self.connection.execute(
            "SELECT status FROM project_devices"
        ).fetchone()[0]
        active_count = self.connection.execute(
            "SELECT COUNT(*) FROM active_authorized_devices"
        ).fetchone()[0]
        self.assertEqual(scope_status, "pending_authorization")
        self.assertEqual(active_count, 0)

        rfid_vault.set_rfid_profile(
            self.connection,
            device_key="reader:test-01",
            profile_kind="reader",
            source_reference="test",
        )
        rfid_vault.grant_access(
            self.connection,
            project_key="rfid-home-lab",
            device_key="reader:test-01",
            authorization_key="authorization:test-01",
            subject="project_owner",
            authorization_basis="self_owned",
            access_level="full",
            operations=("read", "test", "write"),
            purpose="education_and_home",
            evidence_reference="test-evidence",
            valid_from="2026-08-03T00:00:00+02:00",
            now="2026-08-03T10:01:00+02:00",
        )

        active = self.connection.execute(
            "SELECT access_level, allowed_operations_json FROM active_authorized_devices"
        ).fetchone()
        self.assertEqual(active["access_level"], "full")
        self.assertEqual(active["allowed_operations_json"], '["read","test","write"]')
        self.assertEqual(rfid_vault.verify_database(self.connection), [])

    def test_device_add_is_idempotent_and_keeps_active_authorization(self) -> None:
        rfid_vault.add_device_type(
            self.connection,
            type_key="network.test-zigbee-gateway",
            display_name="Test Zigbee gateway",
            category="network",
            default_device_kind="network_device",
            description="Temporary type for idempotent catalog testing.",
        )
        first_id = rfid_vault.add_device(
            self.connection,
            project_key="home-infrastructure",
            device_key="network:test-gateway",
            name="Detected USB gateway",
            device_kind="network_device",
            role="support",
            ownership_status="household_owned",
            manufacturer="Example",
            now="2026-08-21T10:00:00+02:00",
        )
        rfid_vault.grant_access(
            self.connection,
            project_key="home-infrastructure",
            device_key="network:test-gateway",
            authorization_key="authorization:test-gateway",
            subject="project_owner",
            authorization_basis="household_owner",
            access_level="test",
            operations=("test",),
            purpose="home",
            evidence_reference="test",
            valid_from="2026-08-21T10:00:00+02:00",
        )

        second_id = rfid_vault.add_device(
            self.connection,
            project_key="home-infrastructure",
            device_key="network:test-gateway",
            name="Confirmed Zigbee USB gateway",
            device_kind="network_device",
            device_type_key="network.test-zigbee-gateway",
            role="support",
            ownership_status="household_owned",
            model="Gateway V1",
            now="2026-08-21T10:01:00+02:00",
        )

        self.assertEqual(first_id, second_id)
        device = self.connection.execute(
            "SELECT name, manufacturer, model, device_type_key FROM devices WHERE device_key = 'network:test-gateway'"
        ).fetchone()
        self.assertEqual(
            tuple(device),
            ("Confirmed Zigbee USB gateway", "Example", "Gateway V1", "network.test-zigbee-gateway"),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT status FROM project_devices WHERE device_id = ?", (first_id,)
            ).fetchone()[0],
            "in_scope",
        )
        cli = subprocess.run(
            [
                sys.executable,
                str(Path(rfid_vault.__file__)),
                "--db",
                str(self.database_path),
                "device-add",
                "--project",
                "home-infrastructure",
                "--key",
                "network:test-gateway",
                "--name",
                "Confirmed Zigbee USB gateway",
                "--kind",
                "network_device",
                "--type",
                "network.test-zigbee-gateway",
                "--role",
                "support",
                "--ownership",
                "household_owned",
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertIn("authorization is active", cli.stdout)

    def test_legacy_reader_is_cataloged_with_a_profile_and_pending_access(self) -> None:
        timestamp = "2026-08-03T10:00:00+02:00"
        self.connection.execute(
            """
            INSERT INTO readers(name, device_path, connection, usb_serial, metadata_json, created_at, updated_at)
            VALUES ('Proxmark test', '/dev/ttyACM9', 'USB-CDC', 'TEST_SERIAL_1', '{}', ?, ?)
            """,
            (timestamp, timestamp),
        )
        rfid_vault.synchronize_legacy_devices(
            self.connection,
            project_id=rfid_vault.get_project_id(self.connection, "rfid-home-lab"),
            now=timestamp,
        )
        self.connection.commit()

        device = self.connection.execute(
            "SELECT device_key, device_kind, legacy_reader_id FROM devices WHERE legacy_reader_id = 1"
        ).fetchone()
        self.assertEqual(device["device_key"], "reader:test_serial_1")
        self.assertEqual(device["device_kind"], "rfid_reader")
        self.assertEqual(device["legacy_reader_id"], 1)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM active_authorized_devices").fetchone()[0], 0)
        method = self.connection.execute(
            "SELECT method_type, endpoint, secret_reference FROM access_methods "
            "WHERE device_id = (SELECT id FROM devices WHERE legacy_reader_id = 1)"
        ).fetchone()
        self.assertEqual(tuple(method), ("usb_serial", "/dev/ttyACM9", None))
        profile = self.connection.execute(
            "SELECT profile_kind, legacy_reader_id FROM rfid_profiles"
        ).fetchone()
        self.assertEqual(tuple(profile), ("reader", 1))

    def test_rfid_authorization_requires_a_profile(self) -> None:
        rfid_vault.add_device(
            self.connection,
            project_key="rfid-home-lab",
            device_key="reader:profile-required",
            name="Profile required reader",
            device_kind="rfid_reader",
            role="tool",
            ownership_status="user_owned",
            now="2026-08-15T10:00:00+02:00",
        )
        with self.assertRaisesRegex(ValueError, "requires an RFID profile"):
            rfid_vault.grant_access(
                self.connection,
                project_key="rfid-home-lab",
                device_key="reader:profile-required",
                authorization_key="authorization:profile-required",
                subject="project_owner",
                authorization_basis="self_owned",
                access_level="read",
                operations=("read",),
                purpose="education",
                evidence_reference="test",
                valid_from="2026-08-15T10:00:00+02:00",
            )

    def test_shared_inventory_supports_temperature_sensor_relations_and_samples(self) -> None:
        rfid_vault.add_device(
            self.connection,
            project_key="home-infrastructure",
            device_key="sensor:temperature-salon",
            name="Salon temperature sensor",
            device_kind="embedded_device",
            device_type_key="sensor.temperature",
            role="support",
            ownership_status="household_owned",
            now="2026-08-15T10:00:00+02:00",
        )
        rfid_vault.add_device_relation(
            self.connection,
            source_device_key="sensor:temperature-salon",
            target_device_key="computer:raspberry-pi-3",
            relation_type="connected_to",
            source_reference="test",
            observed_at="2026-08-15T10:00:00+02:00",
        )
        rfid_vault.set_device_information(
            self.connection,
            device_key="sensor:temperature-salon",
            information_kind="fact",
            property_key="measurement_precision_c",
            value_json="0.5",
            unit="degC",
            source_reference="test",
            confidence="verified",
            observed_at="2026-08-15T10:00:00+02:00",
        )
        channel_id = rfid_vault.add_measurement_channel(
            self.connection,
            device_key="sensor:temperature-salon",
            channel_key="temperature.c",
            display_name="Temperature",
            quantity_kind="temperature",
            unit="degC",
            minimum_value=-40,
            maximum_value=125,
            retention_days=365,
            source_reference="test",
            observed_at="2026-08-15T10:00:00+02:00",
        )
        sample_id = rfid_vault.add_measurement_sample(
            self.connection,
            device_key="sensor:temperature-salon",
            channel_key="temperature.c",
            observed_at="2026-08-15T10:01:00+02:00",
            value_real=22.5,
            source_reference="test",
        )
        self.assertGreater(channel_id, 0)
        self.assertGreater(sample_id, 0)
        with self.assertRaises(ValueError):
            rfid_vault.add_measurement_sample(
                self.connection,
                device_key="sensor:temperature-salon",
                channel_key="temperature.c",
                observed_at="2026-08-15T10:02:00+02:00",
                value_real=200.0,
                source_reference="test",
            )
        self.assertEqual(rfid_vault.verify_database(self.connection), [])

    def test_information_rejects_plaintext_secret_property_and_detail_hides_identifiers(self) -> None:
        with self.assertRaisesRegex(ValueError, "secret"):
            rfid_vault.set_device_information(
                self.connection,
                device_key="computer:raspberry-pi-3",
                information_kind="configuration",
                property_key="wifi_password",
                value_json='"not-allowed"',
                source_reference="test",
            )
        rfid_vault.add_device_identifier(
            self.connection,
            device_key="computer:raspberry-pi-3",
            identifier_kind="serial.number",
            identifier_value="SERIAL-TEST-01",
            classification="sensitive",
            source_reference="test",
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT COUNT(*) FROM device_identifiers WHERE device_id = "
                "(SELECT id FROM devices WHERE device_key = 'computer:raspberry-pi-3')"
            ).fetchone()[0],
            2,
        )
        self.connection.execute(
            "UPDATE devices SET serial_number = 'SENSITIVE-SERIAL-01' "
            "WHERE device_key = 'computer:raspberry-pi-3'"
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rfid_vault.print_device_detail(self.connection, "computer:raspberry-pi-3", False)
        self.assertNotIn("SENSITIVE-SERIAL-01", output.getvalue())
        self.assertIn("[stored]", output.getvalue())

    def test_unsupported_schema_versions_are_rejected(self) -> None:
        self.connection.execute("PRAGMA user_version = 4")
        self.connection.commit()
        with self.assertRaisesRegex(ValueError, "not supported"):
            rfid_vault.initialize(self.connection)

    def test_verified_clone_gets_its_own_rfid_profile(self) -> None:
        timestamp = "2026-08-15T10:00:00+02:00"
        self.connection.execute(
            """
            INSERT INTO elements(
                label, element_kind, ownership, frequency_mhz, standard, technology, product_family,
                chip_vendor, chip_model, uid_hex, uid_bytes, uid_length, created_at, updated_at
            ) VALUES ('Source fob', 'key_fob', 'user_confirmed_private_property', 13.56,
                      'ISO/IEC 14443-A', 'MIFARE Classic', '1K', 'Vendor', 'Chip',
                      'A1B2C3D4', X'A1B2C3D4', 4, ?, ?)
            """,
            (timestamp, timestamp),
        )
        source_device_id = rfid_vault.add_device(
            self.connection,
            project_key="rfid-home-lab",
            device_key="element:source-test",
            name="Source test fob",
            device_kind="rfid_key_fob",
            role="credential",
            ownership_status="user_owned",
            now=timestamp,
        )
        target_device_id = rfid_vault.add_device(
            self.connection,
            project_key="rfid-home-lab",
            device_key="clone:test-profile",
            name="Target test fob",
            device_kind="rfid_key_fob",
            role="credential",
            ownership_status="user_owned",
            now=timestamp,
        )
        raw_dump = b"x"
        digest = rfid_vault.sha256(raw_dump)
        self.connection.execute(
            """
            INSERT INTO reads(
                run_key, element_id, read_at, status, method, tool_command, complete, verified,
                dump_size, dump_sha256, raw_dump, raw_json, created_at
            ) VALUES ('read:clone-profile', 1, ?, 'complete', 'test', 'test', 1, 1, 1, ?, X'78', '{}', ?)
            """,
            (timestamp, digest, timestamp),
        )
        read_id = self.connection.execute("SELECT id FROM reads WHERE run_key = 'read:clone-profile'").fetchone()[0]
        self.connection.execute(
            """
            INSERT INTO clone_operations(
                run_key, source_device_id, target_device_id, source_read_id, executed_at, status,
                method, tool_command, blocks_written, uid_before_hex, uid_after_hex,
                source_dump_sha256, prewrite_backup_sha256, magic_read_sha256, standard_read_sha256,
                byte_identical, created_at
            ) VALUES ('clone:test-profile', ?, ?, ?, ?, 'verified', 'test', 'test', 64,
                      '00000000', 'A1B2C3D4', ?, ?, ?, ?, 1, ?)
            """,
            (source_device_id, target_device_id, read_id, timestamp, digest, digest, digest, digest, timestamp),
        )
        self.connection.commit()
        rfid_vault.synchronize_clone_profiles(self.connection, now=timestamp)
        profile = self.connection.execute(
            "SELECT profile_kind, technology FROM rfid_profiles WHERE device_id = ?", (target_device_id,)
        ).fetchone()
        self.assertEqual(tuple(profile), ("key_fob", "MIFARE Classic"))
        identifier = self.connection.execute(
            "SELECT identifier_value FROM device_identifiers WHERE device_id = ?", (target_device_id,)
        ).fetchone()
        self.assertEqual(identifier[0], "A1B2C3D4")

    def test_expired_access_is_not_active(self) -> None:
        rfid_vault.add_device(
            self.connection,
            project_key="rfid-home-lab",
            device_key="reader:expired",
            name="Expired test reader",
            device_kind="rfid_reader",
            role="tool",
            ownership_status="user_owned",
            now="2000-01-01T00:00:00+01:00",
        )
        rfid_vault.set_rfid_profile(
            self.connection,
            device_key="reader:expired",
            profile_kind="reader",
            source_reference="test",
        )
        rfid_vault.grant_access(
            self.connection,
            project_key="rfid-home-lab",
            device_key="reader:expired",
            authorization_key="authorization:expired",
            subject="project_owner",
            authorization_basis="self_owned",
            access_level="read",
            operations=("read",),
            purpose="education",
            evidence_reference="expired-test",
            valid_from="2000-01-01T00:00:00+01:00",
            valid_until="2001-01-01T00:00:00+01:00",
            now="2000-01-01T00:00:00+01:00",
        )

        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM active_authorized_devices").fetchone()[0],
            0,
        )
        problems = rfid_vault.verify_database(self.connection)
        self.assertTrue(any("has no active authorization" in problem for problem in problems))

    def _add_authorized_test_reader(self, key: str = "reader:test-cli") -> None:
        rfid_vault.add_device(
            self.connection,
            project_key="rfid-home-lab",
            device_key=key,
            name="CLI test reader",
            device_kind="rfid_reader",
            role="tool",
            ownership_status="user_owned",
            now="2026-08-03T10:00:00+02:00",
        )
        rfid_vault.set_rfid_profile(
            self.connection,
            device_key=key,
            profile_kind="reader",
            source_reference="cli-test",
        )
        rfid_vault.grant_access(
            self.connection,
            project_key="rfid-home-lab",
            device_key=key,
            authorization_key=f"authorization:{key}",
            subject="project_owner",
            authorization_basis="self_owned",
            access_level="full",
            operations=rfid_vault.FULL_AUTHORIZED_OPERATIONS,
            purpose="education_and_home",
            evidence_reference="cli-test",
            valid_from="2026-08-03T00:00:00+02:00",
            now="2026-08-03T10:01:00+02:00",
        )

    def _configure_authorized_raspberry_transport(self, reader_key: str) -> None:
        rfid_vault.grant_access(
            self.connection,
            project_key="home-infrastructure",
            device_key="computer:raspberry-pi-3",
            authorization_key="authorization:test-raspberry-bridge",
            subject="project_owner",
            authorization_basis="household_owner",
            access_level="read",
            operations=("inspect",),
            purpose="home",
            evidence_reference="cli-test",
            valid_from="2026-08-03T00:00:00+02:00",
            now="2026-08-03T10:01:00+02:00",
        )
        rfid_vault.set_access_method(
            self.connection,
            project_key="rfid-home-lab",
            device_key=reader_key,
            method_key="raspberry-pi-ssh",
            method_type="ssh",
            endpoint="raspberry.example.invalid:22",
            account_label="inventory-user",
            authentication_type="ssh_public_key",
            source_reference="cli-test",
            notes="Test-only Proxmark3 transport through Raspberry Pi.",
            now="2026-08-03T10:01:00+02:00",
        )

    @unittest.skipUnless(PRIVATE_RASPBERRY_CREDENTIAL_SCRIPT.is_file(), "requires the private Raspberry script")
    def test_raspberry_script_is_cli_only_and_blocked_without_authorization(self) -> None:
        result = rfid_vault.run_device_script(
            self.connection,
            script_key="raspberry.credentials.sync",
            project_key="home-infrastructure",
            device_key="computer:raspberry-pi-3",
        )

        self.assertEqual(result["status"], "blocked")
        self.assertIn("No active authorization", result["error_message"])
        run = self.connection.execute(
            "SELECT status, command_text, stdout_content, stderr_content FROM device_command_runs "
            "WHERE command_text = 'managed-script raspberry.credentials.sync'"
        ).fetchone()
        self.assertEqual(run["status"], "blocked")
        self.assertEqual(run["stdout_content"], b"")
        self.assertEqual(run["stderr_content"], b"")

        environment = os.environ.copy()
        environment.pop("DEVICE_CLI_CONTEXT", None)
        environment.pop("DEVICE_CLI_SCRIPT_KEY", None)
        direct = subprocess.run(
            [str(rfid_vault.ROOT.parent / "Raspberry" / "save-raspberry-passwords.sh")],
            cwd=rfid_vault.ROOT.parent / "Raspberry",
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(direct.returncode, 2)
        self.assertIn("device-script-run raspberry.credentials.sync", direct.stderr)

    @unittest.skipUnless(PRIVATE_RASPBERRY_POWER_SCRIPT.is_file(), "requires the private Raspberry script")
    def test_raspberry_power_diagnostic_is_cli_only(self) -> None:
        environment = os.environ.copy()
        environment.pop("DEVICE_CLI_CONTEXT", None)
        environment.pop("DEVICE_CLI_SCRIPT_KEY", None)
        direct = subprocess.run(
            [str(rfid_vault.ROOT.parent / "Raspberry" / "diagnose-raspberry-power.sh")],
            cwd=rfid_vault.ROOT.parent / "Raspberry",
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(direct.returncode, 2)
        self.assertIn("device-script-run raspberry.power.diagnose", direct.stderr)

    def test_raspberry_stress_test_is_cli_only(self) -> None:
        environment = os.environ.copy()
        environment.pop("DEVICE_CLI_CONTEXT", None)
        environment.pop("DEVICE_CLI_SCRIPT_KEY", None)
        direct = subprocess.run(
            [str(rfid_vault.ROOT / "test-raspberry-stress.sh")],
            cwd=rfid_vault.ROOT,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(direct.returncode, 2)
        self.assertIn("device-script-run raspberry.stress.test", direct.stderr)

    def test_raspberry_stress_test_has_fast_thermal_safety_monitor(self) -> None:
        script = (rfid_vault.ROOT / "test-raspberry-stress.sh").read_text(encoding="utf-8")

        self.assertIn("THERMAL_LIMIT_C=76.0", script)
        self.assertIn("MONITOR_INTERVAL_SECONDS=1", script)
        self.assertIn('sleep "${MONITOR_INTERVAL_SECONDS}"', script)
        self.assertIn("abort_reason='thermal_safety_limit'", script)
        self.assertIn("abort_reason='current_undervoltage'", script)
        self.assertIn('mktemp -d "${HOME}/.raspberry-stress.XXXXXX"', script)
        self.assertIn("storage_fstype", script)
        self.assertNotIn("mktemp -d /tmp/", script)

    @unittest.skipUnless(PRIVATE_RASPBERRY_HARDWARE_SCRIPT.is_file(), "requires the private Raspberry script")
    def test_raspberry_hardware_discovery_is_cli_only(self) -> None:
        environment = os.environ.copy()
        environment.pop("DEVICE_CLI_CONTEXT", None)
        environment.pop("DEVICE_CLI_SCRIPT_KEY", None)
        direct = subprocess.run(
            [str(rfid_vault.ROOT.parent / "Raspberry" / "discover-raspberry-attached-hardware.sh")],
            cwd=rfid_vault.ROOT.parent / "Raspberry",
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(direct.returncode, 2)
        self.assertIn("device-script-run raspberry.hardware.discover", direct.stderr)

    def test_zigbee_gateway_diagnostic_is_cli_only_and_does_not_send_serial_data(self) -> None:
        environment = os.environ.copy()
        environment.pop("DEVICE_CLI_CONTEXT", None)
        environment.pop("DEVICE_CLI_SCRIPT_KEY", None)
        script_path = rfid_vault.ROOT / "scripts" / "diagnose_zigbee_gateway.py"
        direct = subprocess.run(
            [str(script_path)],
            cwd=rfid_vault.ROOT,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(direct.returncode, 2)
        self.assertIn("device-script-run zigbee.gateway.diagnose", direct.stderr)
        script = script_path.read_text(encoding="utf-8")
        self.assertIn("os.open", script)
        self.assertNotIn("os.write", script)
        self.assertNotIn("termios", script)

    def test_zigbee_association_read_is_cli_only_and_uses_only_get_device_info(self) -> None:
        environment = os.environ.copy()
        environment.pop("DEVICE_CLI_CONTEXT", None)
        environment.pop("DEVICE_CLI_SCRIPT_KEY", None)
        script_path = rfid_vault.ROOT / "scripts" / "read_zigbee_associations.py"
        direct = subprocess.run(
            [str(script_path)],
            cwd=rfid_vault.ROOT,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(direct.returncode, 2)
        self.assertIn("device-script-run zigbee.network.read", direct.stderr)
        script = script_path.read_text(encoding="utf-8")
        self.assertIn('GET_DEVICE_INFO_FRAME = b"\\xfe\\x00\\x27\\x00\\x27"', script)
        self.assertIn("RESPONSE_TIMEOUT_SECONDS = 6", script)
        self.assertIn("No ZNP response at 115200 baud", script)
        self.assertIn('"radio_sensor_read": "not_sent"', script)
        self.assertNotIn("PERMIT_JOIN", script)

    @unittest.skipUnless(PRIVATE_RASPBERRY_CREDENTIAL_SCRIPT.is_file(), "requires the private Raspberry script")
    def test_managed_script_uses_registered_cli_path_and_audits_without_output(self) -> None:
        with self.assertRaisesRegex(ValueError, "DEVICE_CLI_CONTEXT"):
            rfid_vault.add_device_script(
                self.connection,
                script_key="reader.test.missing-guard",
                device_key="computer:raspberry-pi-3",
                display_name="Missing guard",
                description="This script must not be registered.",
                script_path=Path(rfid_vault.__file__),
                required_operation="read",
                risk_level="read_only",
                timeout_seconds=10,
                interactive=False,
            )
        rfid_vault.grant_access(
            self.connection,
            project_key="home-infrastructure",
            device_key="computer:raspberry-pi-3",
            authorization_key="authorization:raspberry-managed-script-test",
            subject="project_owner",
            authorization_basis="household_owner",
            access_level="admin",
            operations=("administer",),
            purpose="home",
            evidence_reference="test",
            valid_from="2026-08-03T00:00:00+02:00",
            now="2026-08-03T10:01:00+02:00",
        )

        process = mock.Mock()
        process.pid = 12345
        process.wait.return_value = 0
        with mock.patch("rfid_vault.subprocess.Popen", return_value=process) as popen:
            result = rfid_vault.run_device_script(
                self.connection,
                script_key="raspberry.credentials.sync",
                project_key="home-infrastructure",
                device_key="computer:raspberry-pi-3",
            )

        self.assertEqual(result["status"], "succeeded")
        arguments, options = popen.call_args
        self.assertEqual(
            arguments[0],
            [str((rfid_vault.ROOT.parent / "Raspberry" / "save-raspberry-passwords.sh").resolve())],
        )
        self.assertTrue(options["start_new_session"])
        self.assertEqual(options["env"]["DEVICE_CLI_CONTEXT"], "1")
        self.assertEqual(options["env"]["DEVICE_CLI_SCRIPT_KEY"], "raspberry.credentials.sync")
        self.assertEqual(options["env"]["DEVICE_CLI_DEVICE_ADDRESS"], "192.0.2.82")
        self.assertEqual(options["env"]["DEVICE_CLI_DEVICE_ENDPOINT"], "raspberry.example.invalid:22")
        self.assertEqual(options["env"]["RASPBERRY_HOST"], "192.0.2.82")
        run = self.connection.execute(
            "SELECT command_id, status, exit_code, stdout_content, stderr_content FROM device_command_runs "
            "WHERE command_text = 'managed-script raspberry.credentials.sync'"
        ).fetchone()
        self.assertIsNone(run["command_id"])
        self.assertEqual(tuple(run[1:]), ("succeeded", 0, b"", b""))
        self.assertEqual(rfid_vault.verify_database(self.connection), [])

    def test_managed_script_content_change_is_blocked_until_it_is_reviewed_again(self) -> None:
        script_handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix=".integrity-script-", suffix=".sh",
            dir=rfid_vault.ROOT, delete=False,
        )
        script_path = Path(script_handle.name)
        script_handle.write(
            "#!/usr/bin/env bash\n"
            "if [[ \"${DEVICE_CLI_CONTEXT:-}\" != \"1\" || \"${DEVICE_CLI_SCRIPT_KEY:-}\" != \"raspberry.test.integrity\" ]]; then\n"
            "  exit 2\n"
            "fi\n"
            "exit 0\n"
        )
        script_handle.close()
        script_path.chmod(0o700)
        try:
            rfid_vault.add_device_script(
                self.connection,
                script_key="raspberry.test.integrity",
                device_key="computer:raspberry-pi-3",
                display_name="Integrity test script",
                description="A temporary script for integrity regression testing.",
                script_path=script_path,
                required_operation="administer",
                risk_level="read_only",
                timeout_seconds=10,
                interactive=False,
            )
            rfid_vault.grant_access(
                self.connection,
                project_key="home-infrastructure",
                device_key="computer:raspberry-pi-3",
                authorization_key="authorization:raspberry-integrity-test",
                subject="project_owner",
                authorization_basis="household_owner",
                access_level="admin",
                operations=("administer",),
                purpose="home",
                evidence_reference="test",
                valid_from="2026-08-03T00:00:00+02:00",
            )
            script_path.write_text(script_path.read_text(encoding="utf-8") + "# changed after review\n", encoding="utf-8")
            with mock.patch("rfid_vault.subprocess.Popen") as popen:
                result = rfid_vault.run_device_script(
                    self.connection,
                    script_key="raspberry.test.integrity",
                    project_key="home-infrastructure",
                    device_key="computer:raspberry-pi-3",
                )
            self.assertEqual(result["status"], "blocked")
            self.assertIn("changed after review", result["error_message"])
            popen.assert_not_called()
            row = self.connection.execute(
                "SELECT status, executed_script_sha256 FROM device_command_runs WHERE run_key = ?",
                (result["run_key"],),
            ).fetchone()
            self.assertEqual(row["status"], "blocked")
            self.assertRegex(row["executed_script_sha256"], r"^[0-9a-f]{64}$")
        finally:
            script_path.unlink(missing_ok=True)

    def test_contract_relation_and_normalized_authorization_operations_are_enforced(self) -> None:
        rfid_vault.add_device(
            self.connection,
            project_key="home-infrastructure",
            device_key="sensor:contract-temperature",
            name="Contract temperature sensor",
            device_kind="embedded_device",
            device_type_key="sensor.temperature",
            role="support",
            ownership_status="household_owned",
        )
        with self.assertRaisesRegex(ValueError, "does not allow measurement channel"):
            rfid_vault.add_measurement_channel(
                self.connection,
                device_key="sensor:contract-temperature",
                channel_key="humidity.percent",
                display_name="Humidity",
                quantity_kind="humidity",
                unit="percent",
                source_reference="test",
            )
        with self.assertRaisesRegex(ValueError, "not registered and active"):
            rfid_vault.add_device_relation(
                self.connection,
                source_device_key="sensor:contract-temperature",
                target_device_key="computer:raspberry-pi-3",
                relation_type="unknown_relation",
                source_reference="test",
            )
        rfid_vault.add_relation_type(
            self.connection,
            relation_type="reports_to",
            display_name="Reports to",
            description="The source device reports data to the target device.",
            directional=True,
        )
        rfid_vault.add_device_relation(
            self.connection,
            source_device_key="sensor:contract-temperature",
            target_device_key="computer:raspberry-pi-3",
            relation_type="reports_to",
            source_reference="test",
        )
        authorization_id = rfid_vault.grant_access(
            self.connection,
            project_key="home-infrastructure",
            device_key="sensor:contract-temperature",
            authorization_key="authorization:contract-temperature",
            subject="project_owner",
            authorization_basis="household_owner",
            access_level="read",
            operations=("read", "inspect"),
            purpose="home",
            evidence_reference="test",
            valid_from="2026-08-03T00:00:00+02:00",
        )
        operations = self.connection.execute(
            "SELECT operation FROM access_authorization_operations WHERE authorization_id = ? ORDER BY operation",
            (authorization_id,),
        ).fetchall()
        self.assertEqual([row["operation"] for row in operations], ["inspect", "read"])
        self.assertEqual(rfid_vault.verify_database(self.connection), [])

    def test_measurement_and_audit_output_retention_are_previewed_and_audited(self) -> None:
        rfid_vault.add_device(
            self.connection,
            project_key="home-infrastructure",
            device_key="sensor:retention-test",
            name="Retention test sensor",
            device_kind="embedded_device",
            role="support",
            ownership_status="household_owned",
        )
        rfid_vault.add_measurement_channel(
            self.connection,
            device_key="sensor:retention-test",
            channel_key="temperature.c",
            display_name="Temperature",
            quantity_kind="temperature",
            unit="degC",
            retention_days=7,
            source_reference="test",
        )
        rfid_vault.add_measurement_sample(
            self.connection,
            device_key="sensor:retention-test",
            channel_key="temperature.c",
            observed_at="2026-08-01T10:00:00+02:00",
            value_real=20,
            source_reference="test",
        )
        preview = rfid_vault.run_measurement_retention(
            self.connection, apply=False, now="2026-08-15T10:00:00+02:00"
        )
        self.assertEqual((preview["candidate_count"], preview["deleted_count"]), (1, 0))
        applied = rfid_vault.run_measurement_retention(
            self.connection, apply=True, now="2026-08-15T10:00:00+02:00"
        )
        self.assertEqual((applied["candidate_count"], applied["deleted_count"]), (1, 1))
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM measurement_samples").fetchone()[0], 0)

        empty_hash = rfid_vault.sha256(b"")
        project_id = rfid_vault.get_project_id(self.connection, "home-infrastructure")
        device_id = rfid_vault.get_device_id(self.connection, "computer:raspberry-pi-3")
        self.connection.execute(
            """
            INSERT INTO device_command_runs(
                run_key, project_id, device_id, command_id, command_text, required_operation,
                started_at, completed_at, duration_ms, status, exit_code, stdout_sha256,
                stderr_sha256, stdout_content, stderr_content, created_at
            ) VALUES ('run:retention-output', ?, ?, NULL, 'test output', 'inspect',
                      '2026-01-01T10:00:00+02:00', '2026-01-01T10:00:00+02:00', 0,
                      'succeeded', 0, ?, ?, X'6F6C64', X'', '2026-01-01T10:00:00+02:00')
            """,
            (project_id, device_id, rfid_vault.sha256(b"old"), empty_hash),
        )
        self.connection.commit()
        audit = rfid_vault.run_audit_output_retention(
            self.connection, apply=True, now="2026-08-15T10:00:00+02:00"
        )
        self.assertEqual(audit["purged_count"], 1)
        run = self.connection.execute(
            "SELECT stdout_content, stdout_original_sha256, output_purged_at FROM device_command_runs "
            "WHERE run_key = 'run:retention-output'"
        ).fetchone()
        self.assertEqual(run["stdout_content"], b"")
        self.assertEqual(run["stdout_original_sha256"], rfid_vault.sha256(b"old"))
        self.assertIsNotNone(run["output_purged_at"])
        self.assertEqual(rfid_vault.verify_database(self.connection), [])

    def test_pm3_probe_combines_registry_authorization_client_and_port(self) -> None:
        self._add_authorized_test_reader()

        result = rfid_device.probe(
            self.connection,
            device_key="reader:test-cli",
            client_path="/bin/true",
            port_path="/dev/null",
        )

        self.assertTrue(result["ready"])
        self.assertTrue(result["authorized"])
        self.assertTrue(result["port_is_character_device"])
        self.assertIn("read", result["allowed_operations"])

    def test_named_pm3_command_uses_authorized_raspberry_ssh_transport(self) -> None:
        self._add_authorized_test_reader()
        self._configure_authorized_raspberry_transport("reader:test-cli")
        discovery = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"PM3_CLIENT=/usr/local/bin/pm3\n", stderr=b""
        )
        command = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"remote-hw-version\n", stderr=b""
        )

        with mock.patch("rfid_device._run_captured_process", side_effect=(discovery, command)) as run:
            result = rfid_device.run_named_command(
                self.connection,
                key="pm3.hw-version",
                device_key="reader:test-cli",
                port_path="/dev/ttyACM0",
                transport="raspberry-ssh",
            )

        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["stdout"], b"remote-hw-version\n")
        discovery_arguments = run.call_args_list[0].args[0]
        command_arguments = run.call_args_list[1].args[0]
        self.assertEqual(discovery_arguments[0], "ssh")
        self.assertIn("StrictHostKeyChecking=yes", discovery_arguments)
        self.assertIn("inventory-user@raspberry.example.invalid", discovery_arguments)
        self.assertEqual(command_arguments[0], "ssh")
        self.assertIn("timeout --signal=TERM --kill-after=5s 30s", command_arguments[-1])
        self.assertIn("'hw version'", command_arguments[-1])
        run_record = self.connection.execute(
            "SELECT client_path, endpoint, status FROM device_command_runs ORDER BY id DESC"
        ).fetchone()
        self.assertEqual(run_record["status"], "succeeded")
        self.assertEqual(run_record["client_path"], "ssh://inventory-user@raspberry.example.invalid:22/usr/local/bin/pm3")
        self.assertEqual(run_record["endpoint"], "ssh://inventory-user@raspberry.example.invalid:22/dev/ttyACM0")

    def test_raspberry_pm3_probe_does_not_connect_without_bridge_authorization(self) -> None:
        self._add_authorized_test_reader()
        rfid_vault.set_access_method(
            self.connection,
            project_key="rfid-home-lab",
            device_key="reader:test-cli",
            method_key="raspberry-pi-ssh",
            method_type="ssh",
            endpoint="raspberry.example.invalid:22",
            account_label="inventory-user",
            authentication_type="ssh_public_key",
            source_reference="cli-test",
        )

        with mock.patch("rfid_device._run_captured_process") as run:
            result = rfid_device.probe(
                self.connection,
                device_key="reader:test-cli",
                port_path="/dev/ttyACM0",
                transport="raspberry-ssh",
            )

        self.assertFalse(result["ready"])
        self.assertIn("Raspberry bridge authorization", " ".join(result["problems"]))
        run.assert_not_called()

    def test_client_selection_prefers_the_version_stored_for_the_reader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            workspace = Path(temporary_directory)
            client = workspace / "proxmark3-v4.20728" / "client" / "proxmark3"
            client.parent.mkdir(parents=True)
            client.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            client.chmod(0o755)
            with mock.patch.object(rfid_device, "ROOT", workspace):
                selected = rfid_device.find_client(preferred_version="v4.20728")

            self.assertEqual(selected, client.resolve())

    def test_output_diagnosis_rejects_impossible_hf_tune_voltage(self) -> None:
        diagnosis = rfid_device.diagnose_client_output(
            "pm3.hw-tune",
            b"[+] 13.56 MHz............. 4294945.88 V",
            b"",
        )

        self.assertIn("physically invalid", diagnosis)

    def test_output_diagnosis_explains_unsupported_lf_command(self) -> None:
        diagnosis = rfid_device.diagnose_client_output(
            "pm3.lf-search",
            b"[#] unknown command:: 0x037e\n[!] timeout while waiting for reply",
            b"",
        )

        self.assertIn("CMD_LF_HITAGU_UID", diagnosis)

    def test_output_diagnosis_rejects_false_firmware_flash_success(self) -> None:
        diagnosis = rfid_device.diagnose_client_output(
            "pm3.firmware-flash",
            b"[!!] Aborted on error\n[!] ARM firmware does not match the source",
            b"",
        )

        self.assertIn("exit code 0", diagnosis)
        self.assertIn("dialout", diagnosis)

    def test_process_timeout_stops_the_complete_client_process_group(self) -> None:
        child_pid_path = Path(self.temporary_directory.name) / "child.pid"
        wrapper_path = Path(self.temporary_directory.name) / "client-wrapper.py"
        wrapper_path.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, subprocess, sys, time\n"
            f"pid_path = pathlib.Path({str(child_pid_path)!r})\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
            "pid_path.write_text(str(child.pid), encoding='ascii')\n"
            "time.sleep(30)\n",
            encoding="utf-8",
        )
        wrapper_path.chmod(0o700)

        with self.assertRaises(subprocess.TimeoutExpired):
            rfid_device._run_captured_process(
                [str(wrapper_path)],
                cwd=Path(self.temporary_directory.name),
                timeout_seconds=1,
            )

        child_pid = int(child_pid_path.read_text(encoding="ascii"))
        for _attempt in range(20):
            process_status = Path(f"/proc/{child_pid}/stat")
            if not process_status.exists() or process_status.read_text().split()[2] == "Z":
                break
            time.sleep(0.05)
        self.assertTrue(
            not process_status.exists() or process_status.read_text().split()[2] == "Z"
        )

    def test_named_pm3_command_runs_without_shell_and_is_audited(self) -> None:
        self._add_authorized_test_reader()

        result = rfid_device.run_named_command(
            self.connection,
            key="pm3.hw-version",
            device_key="reader:test-cli",
            client_path="/bin/true",
            port_path="/dev/null",
        )

        self.assertEqual(result["status"], "succeeded")
        run = self.connection.execute(
            "SELECT status, exit_code, command_text, stdout_sha256, stderr_sha256 FROM device_command_runs"
        ).fetchone()
        self.assertEqual(run["status"], "succeeded")
        self.assertEqual(run["exit_code"], 0)
        self.assertEqual(run["command_text"], "hw version")
        self.assertEqual(
            run["stdout_sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(run["stdout_sha256"], run["stderr_sha256"])
        self.assertEqual(rfid_vault.verify_database(self.connection), [])

    def test_firmware_flash_requires_confirmation_and_is_audited(self) -> None:
        self._add_authorized_test_reader()
        image_path = Path(self.temporary_directory.name) / "fullimage.elf"
        image_path.write_bytes(b"\x7fELF-test-firmware")

        with self.assertRaises(rfid_device.DeviceAccessError):
            rfid_device.flash_firmware(
                self.connection,
                fullimage_path=image_path,
                device_key="reader:test-cli",
                client_path="/bin/true",
                port_path="/dev/null",
            )

        blocked = self.connection.execute(
            "SELECT status, required_operation, error_message FROM device_command_runs ORDER BY id DESC"
        ).fetchone()
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["required_operation"], "configure")
        self.assertIn("explicit confirmation", blocked["error_message"])

        result = rfid_device.flash_firmware(
            self.connection,
            fullimage_path=image_path,
            confirmed=True,
            device_key="reader:test-cli",
            client_path="/bin/true",
            port_path="/dev/null",
        )

        self.assertEqual(result["status"], "succeeded")
        succeeded = self.connection.execute(
            "SELECT status, command_text, stdout_sha256 FROM device_command_runs ORDER BY id DESC"
        ).fetchone()
        self.assertEqual(succeeded["status"], "succeeded")
        self.assertIn("fullimage=fullimage.elf", succeeded["command_text"])
        self.assertIn("sha256=", succeeded["command_text"])
        self.assertEqual(
            succeeded["stdout_sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_blocked_pm3_command_is_also_audited(self) -> None:
        rfid_vault.add_device(
            self.connection,
            project_key="rfid-home-lab",
            device_key="reader:not-authorized",
            name="Pending reader",
            device_kind="rfid_reader",
            role="tool",
            ownership_status="unspecified",
            now="2026-08-03T10:00:00+02:00",
        )

        with self.assertRaises(rfid_device.DeviceAccessError):
            rfid_device.run_named_command(
                self.connection,
                key="pm3.hw-version",
                device_key="reader:not-authorized",
                client_path="/bin/true",
                port_path="/dev/null",
            )

        run = self.connection.execute(
            "SELECT status, exit_code, error_message FROM device_command_runs"
        ).fetchone()
        self.assertEqual(run["status"], "blocked")
        self.assertIsNone(run["exit_code"])
        self.assertIn("No active per-device authorization", run["error_message"])

    def test_cli_command_add_does_not_replace_subcommand_name(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(rfid_vault.__file__)),
                "--db",
                str(self.database_path),
                "pm3-command-add",
                "--key",
                "pm3.test-command",
                "--name",
                "Test command",
                "--description",
                "CLI parser regression test.",
                "--command",
                "hw version",
                "--operation",
                "inspect",
                "--risk",
                "read_only",
                "--timeout",
                "10",
            ],
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Stored reusable Proxmark3 command", completed.stdout)
        command = self.connection.execute(
            "SELECT command_text, builtin FROM device_commands WHERE command_key = 'pm3.test-command'"
        ).fetchone()
        self.assertEqual(tuple(command), ("hw version", 0))

    def test_cli_registers_typed_sensor_and_measurement_channel(self) -> None:
        command_prefix = [sys.executable, str(Path(rfid_vault.__file__)), "--db", str(self.database_path)]
        add_device = subprocess.run(
            command_prefix
            + [
                "device-add",
                "--project",
                "home-infrastructure",
                "--key",
                "sensor:cli-temperature",
                "--name",
                "CLI temperature sensor",
                "--kind",
                "embedded_device",
                "--type",
                "sensor.temperature",
                "--role",
                "support",
                "--ownership",
                "household_owned",
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(add_device.returncode, 0, add_device.stderr)
        add_channel = subprocess.run(
            command_prefix
            + [
                "measurement-channel-add",
                "--device",
                "sensor:cli-temperature",
                "--key",
                "temperature.c",
                "--name",
                "Temperature",
                "--quantity",
                "temperature",
                "--unit",
                "degC",
                "--minimum",
                "-40",
                "--maximum",
                "125",
                "--source",
                "cli-test",
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(add_channel.returncode, 0, add_channel.stderr)
        channel = self.connection.execute(
            "SELECT quantity_kind, unit FROM measurement_channels WHERE channel_key = 'temperature.c'"
        ).fetchone()
        self.assertEqual(tuple(channel), ("temperature", "degC"))

    def test_pm3_permission_apply_reprobes_without_running_system_commands_in_test(self) -> None:
        ready_result = {"ready": True}
        output = io.StringIO()
        with mock.patch.object(
            sys,
            "argv",
            [
                str(rfid_vault.ROOT / "rfid_vault.py"),
                "--db",
                str(self.database_path),
                "pm3-fix-permissions",
                "--apply",
            ],
        ), mock.patch("rfid_device.probe", side_effect=[ready_result, ready_result]) as probe, mock.patch(
            "rfid_device.permission_repair_commands", return_value=[["safe-e2e-command"]]
        ), mock.patch("rfid_device.apply_permission_repair") as apply, mock.patch(
            "rfid_device.probe_lines", return_value=["READY: simulated"]
        ), contextlib.redirect_stdout(output):
            self.assertEqual(rfid_vault.main(), 0)

        self.assertEqual(probe.call_count, 2)
        apply.assert_called_once_with(ready_result)
        self.assertIn("READY: simulated", output.getvalue())

    def test_permission_repair_runs_argument_lists_without_shell(self) -> None:
        completed = mock.Mock(returncode=0)
        with mock.patch("rfid_device.permission_repair_commands", return_value=[["safe-e2e-command", "arg"]]), mock.patch(
            "rfid_device.subprocess.run", return_value=completed
        ) as run:
            self.assertEqual(rfid_device.apply_permission_repair({}), [["safe-e2e-command", "arg"]])

        run.assert_called_once_with(["safe-e2e-command", "arg"], check=False)


class RFIDVaultCLIEndToEndTests(unittest.TestCase):
    """Run each CLI family against an isolated database and a fake PM3 client."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary_directory.name)
        self.database_path = self.workspace / "e2e.sqlite3"
        self.timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        self.executed_commands: set[str] = set()
        self.fake_client = self.workspace / "fake-pm3.py"
        self.fake_client.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            "import sys\n"
            "arguments = sys.argv[1:]\n"
            "if '--dumpmem' in arguments:\n"
            "    output = Path(arguments[arguments.index('--dumpmem') + 1])\n"
            "    length = int(arguments[arguments.index('--dumplen') + 1])\n"
            "    output.write_bytes(b'P' * length)\n"
            "print('fake-pm3', ' '.join(arguments))\n",
            encoding="utf-8",
        )
        self.fake_client.chmod(0o700)
        script_handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=".e2e-device-script-",
            suffix=".sh",
            dir=rfid_vault.ROOT,
            delete=False,
        )
        self.device_script = Path(script_handle.name)
        script_handle.write(
            "#!/usr/bin/env bash\n"
            "if [[ \"${DEVICE_CLI_CONTEXT:-}\" != \"1\" || \"${DEVICE_CLI_SCRIPT_KEY:-}\" != \"sensor.e2e.read\" ]]; then\n"
            "  exit 2\n"
            "fi\n"
            "printf 'e2e-device-script'\n"
        )
        script_handle.close()
        self.device_script.chmod(0o700)
        self.run_cli("init")

    def tearDown(self) -> None:
        self.device_script.unlink(missing_ok=True)
        self.temporary_directory.cleanup()

    def run_cli(self, *arguments: str, expected_returncode: int = 0) -> subprocess.CompletedProcess[str]:
        if arguments and not arguments[0].startswith("-"):
            self.executed_commands.add(arguments[0])
        completed = subprocess.run(
            [
                sys.executable,
                str(rfid_vault.ROOT / "rfid_vault.py"),
                "--db",
                str(self.database_path),
                *arguments,
            ],
            cwd=rfid_vault.ROOT,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            expected_returncode,
            f"CLI failed: {' '.join(arguments)}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return completed

    def write_mfc_fixture(self, file_stem: str, uid: bytes) -> tuple[Path, Path, Path]:
        dump = bytearray(1024)
        dump[:4] = uid
        dump[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
        key_a = b"\xff" * 6
        key_b = b"\xff" * 6
        access = bytes.fromhex("FF078069")
        sector_keys: dict[str, dict[str, object]] = {}
        for sector in range(16):
            trailer_offset = (sector * 4 + 3) * 16
            dump[trailer_offset : trailer_offset + 6] = key_a
            dump[trailer_offset + 6 : trailer_offset + 10] = access
            dump[trailer_offset + 10 : trailer_offset + 16] = key_b
            sector_keys[str(sector)] = {
                "KeyA": key_a.hex().upper(),
                "KeyB": key_b.hex().upper(),
                "AccessConditions": access.hex().upper(),
                "AccessConditionsText": {"UserData": "00"},
            }
        document = {
            "FileType": "mfc v2",
            "Card": {"UID": uid.hex().upper(), "ATQA": "0004", "SAK": "08"},
            "blocks": {
                str(block_number): bytes(dump[block_number * 16 : (block_number + 1) * 16]).hex().upper()
                for block_number in range(64)
            },
            "SectorKeys": sector_keys,
        }
        dump_path = self.workspace / f"{file_stem}.bin"
        json_path = self.workspace / f"{file_stem}.json"
        keys_path = self.workspace / f"{file_stem}.keys"
        dump_path.write_bytes(dump)
        json_path.write_text(json.dumps(document), encoding="utf-8")
        keys_path.write_bytes(key_a * 16 + key_b * 16)
        return dump_path, json_path, keys_path

    def test_all_cli_families_end_to_end(self) -> None:
        project_key = "e2e-home"
        sensor_key = "sensor:e2e-temperature"
        gateway_key = "network:e2e-gateway"
        reader_key = "reader:e2e-pm3"
        clone_key = "rfid:e2e-clone"
        common_source = "e2e-test"
        expected_commands = {
            "init", "database-backup", "database-backups", "database-restore", "project-add", "projects",
            "device-add", "devices", "device-types", "device-type-add", "device-type-contract-set",
            "device-type-contracts", "device-show", "device-script-add", "device-scripts",
            "device-script-run", "device-identifier-add", "device-information-set",
            "device-information", "device-interface-set", "device-interfaces",
            "device-relation-add", "relation-type-add", "relation-types", "device-component-set", "rfid-profile-set",
            "measurement-channel-add", "measurement-add", "measurements", "measurement-retention",
            "audit-output-retention", "access-grant",
            "accesses", "access-check", "access-method-set", "access-methods", "pm3-probe",
            "pm3-fix-permissions", "pm3-commands", "pm3-command-add", "pm3-run",
            "pm3-firmware-backup", "pm3-firmware-flash", "pm3-history", "import-mfc",
            "clone-record", "clones", "list", "show", "verify",
        }
        subparser_action = next(
            action
            for action in rfid_vault.build_parser()._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        self.assertEqual(set(subparser_action.choices), expected_commands)

        self.assertIn("project-add", self.run_cli("--help").stdout)
        self.run_cli("projects")
        self.run_cli(
            "project-add",
            "--key", project_key,
            "--name", "E2E Home",
            "--description", "Isolated CLI end-to-end test project.",
            "--purpose", "home",
            "--owner", "e2e-test",
            "--authorization-policy", "Deny by default.",
            "--scope-notes", "Temporary test data.",
        )
        self.assertIn(project_key, self.run_cli("projects").stdout)
        self.run_cli("device-types")
        self.run_cli(
            "device-type-add",
            "--key", "sensor.e2e-temperature",
            "--category", "sensor",
            "--name", "E2E temperature sensor",
            "--kind", "embedded_device",
            "--description", "Temporary temperature sensor for CLI E2E tests.",
        )
        self.assertIn("sensor.e2e-temperature", self.run_cli("device-types").stdout)
        self.run_cli(
            "device-type-contract-set",
            "--type", "sensor.e2e-temperature",
            "--enforcement", "strict",
            "--capabilities-json", '["measure.temperature"]',
            "--information-schema-json",
            '{"calibration_offset_c":{"information_kinds":["configuration","observation"],"unit":"degC","value_type":"number"}}',
            "--measurement-schema-json",
            '{"temperature.c":{"maximum":125,"minimum":-55,"quantity_kind":"temperature","unit":"degC"}}',
            "--source", common_source,
        )
        self.assertIn(
            "sensor.e2e-temperature",
            self.run_cli("device-type-contracts", "--type", "sensor.e2e-temperature").stdout,
        )

        self.run_cli(
            "device-add",
            "--project", project_key,
            "--key", sensor_key,
            "--name", "E2E temperature sensor",
            "--kind", "embedded_device",
            "--type", "sensor.e2e-temperature",
            "--role", "support",
            "--ownership", "household_owned",
        )
        self.run_cli(
            "device-add",
            "--project", project_key,
            "--key", gateway_key,
            "--name", "E2E network gateway",
            "--kind", "network_device",
            "--role", "support",
            "--ownership", "household_owned",
        )
        self.assertIn(sensor_key, self.run_cli("devices", "--project", project_key).stdout)
        self.assertIn(sensor_key, self.run_cli("device-show", "--device", sensor_key).stdout)
        self.run_cli(
            "device-identifier-add",
            "--device", sensor_key,
            "--kind", "serial.number",
            "--value", "E2E-SENSOR-001",
            "--classification", "sensitive",
            "--source", common_source,
        )
        self.run_cli(
            "device-information-set",
            "--device", sensor_key,
            "--kind", "configuration",
            "--property", "calibration_offset_c",
            "--value-json", "0.1",
            "--unit", "degC",
            "--source", common_source,
            "--confidence", "verified",
        )
        self.run_cli(
            "device-information-set",
            "--device", sensor_key,
            "--kind", "observation",
            "--property", "calibration_offset_c",
            "--value-json", "0.0",
            "--unit", "degC",
            "--source", common_source,
            "--historical",
        )
        self.assertIn("calibration_offset_c", self.run_cli("device-information", "--device", sensor_key).stdout)
        self.assertIn("calibration_offset_c", self.run_cli("device-information", "--device", sensor_key, "--history").stdout)
        self.run_cli(
            "device-interface-set",
            "--device", sensor_key,
            "--key", "i2c.bus1",
            "--type", "i2c",
            "--address", "0x48",
            "--source", common_source,
        )
        self.assertIn("i2c.bus1", self.run_cli("device-interfaces", "--device", sensor_key).stdout)
        self.run_cli(
            "device-relation-add",
            "--source-device", sensor_key,
            "--target-device", gateway_key,
            "--type", "connected_to",
            "--source", common_source,
        )
        self.assertIn("connected_to", self.run_cli("relation-types").stdout)
        self.run_cli(
            "relation-type-add",
            "--type", "reports_to",
            "--name", "Reports to",
            "--description", "The source device reports data to the target device.",
        )
        self.run_cli(
            "device-component-set",
            "--device", sensor_key,
            "--key", "sensor.temperature",
            "--kind", "sensor_module",
            "--name", "E2E thermometer",
            "--details-json", "{\"bus\":\"i2c\"}",
            "--source", common_source,
        )
        self.run_cli(
            "measurement-channel-add",
            "--device", sensor_key,
            "--key", "temperature.c",
            "--name", "Temperature",
            "--quantity", "temperature",
            "--unit", "degC",
            "--minimum", "-40",
            "--maximum", "125",
            "--retention-days", "30",
            "--source", common_source,
        )
        self.run_cli(
            "measurement-add",
            "--device", sensor_key,
            "--channel", "temperature.c",
            "--observed-at", self.timestamp,
            "--value", "200",
            "--source", common_source,
            expected_returncode=1,
        )
        self.run_cli(
            "measurement-add",
            "--device", sensor_key,
            "--channel", "temperature.c",
            "--observed-at", self.timestamp,
            "--value", "200",
            "--quality", "invalid",
            "--source", common_source,
        )
        self.run_cli(
            "measurement-add",
            "--device", sensor_key,
            "--channel", "temperature.c",
            "--observed-at", self.timestamp,
            "--value", "22.5",
            "--source", common_source,
        )
        self.assertIn("22.5", self.run_cli("measurements", "--device", sensor_key, "--channel", "temperature.c").stdout)
        self.assertIn("Measurement retention preview", self.run_cli("measurement-retention").stdout)
        self.assertIn("Audit output retention preview", self.run_cli("audit-output-retention").stdout)

        self.assertIn(
            "NOT AUTHORIZED",
            self.run_cli("access-check", "--project", project_key, "--device", sensor_key, expected_returncode=2).stdout,
        )
        self.run_cli(
            "device-script-add",
            "--device", sensor_key,
            "--key", "sensor.e2e.read",
            "--name", "E2E sensor script",
            "--description", "Safe local CLI E2E script.",
            "--path", str(self.device_script),
            "--operation", "read",
            "--risk", "read_only",
            "--timeout", "10",
            "--non-interactive",
        )
        self.run_cli(
            "device-script-run", "sensor.e2e.read", "--project", project_key, "--device", sensor_key,
            expected_returncode=2,
        )
        self.run_cli(
            "access-grant",
            "--project", project_key,
            "--device", sensor_key,
            "--key", "authorization:e2e-sensor",
            "--subject", "e2e-test",
            "--basis", "household_owner",
            "--level", "read",
            "--operation", "read",
            "--purpose", "home",
            "--evidence", "e2e-test",
            "--valid-from", self.timestamp,
        )
        self.assertIn("AUTHORIZED", self.run_cli("access-check", "--project", project_key, "--device", sensor_key).stdout)
        self.assertIn(sensor_key, self.run_cli("accesses", "--project", project_key).stdout)
        self.run_cli(
            "access-method-set",
            "--project", project_key,
            "--device", sensor_key,
            "--key", "local-test",
            "--type", "local",
            "--endpoint", "local:test",
        )
        self.assertIn("local-test", self.run_cli("access-methods", "--project", project_key, "--device", sensor_key).stdout)
        self.assertIn("sensor.e2e.read", self.run_cli("device-scripts", "--device", sensor_key).stdout)
        self.assertIn(
            "e2e-device-script",
            self.run_cli("device-script-run", "sensor.e2e.read", "--project", project_key, "--device", sensor_key).stdout,
        )

        self.run_cli(
            "device-add",
            "--project", project_key,
            "--key", reader_key,
            "--name", "E2E PM3 reader",
            "--kind", "rfid_reader",
            "--role", "tool",
            "--ownership", "user_owned",
        )
        self.run_cli(
            "rfid-profile-set",
            "--device", reader_key,
            "--kind", "reader",
            "--frequency-mhz", "13.56",
            "--standard", "ISO/IEC 14443-A",
            "--technology", "MIFARE Classic",
            "--source", common_source,
        )
        self.run_cli(
            "access-grant",
            "--project", project_key,
            "--device", reader_key,
            "--key", "authorization:e2e-pm3",
            "--subject", "e2e-test",
            "--basis", "self_owned",
            "--level", "full",
            "--operation", "identify",
            "--operation", "inspect",
            "--operation", "read",
            "--operation", "analyze",
            "--operation", "test",
            "--operation", "write",
            "--operation", "configure",
            "--operation", "administer",
            "--purpose", "home",
            "--evidence", "e2e-test",
            "--valid-from", self.timestamp,
        )
        pm3_arguments = (
            "--project", project_key,
            "--device", reader_key,
            "--client", str(self.fake_client),
            "--port", "/dev/null",
        )
        self.assertIn("READY", self.run_cli("pm3-probe", *pm3_arguments).stdout)
        self.assertIn("\"ready\": true", self.run_cli("pm3-probe", *pm3_arguments, "--json").stdout)
        self.assertIn("Permission repair", self.run_cli("pm3-fix-permissions", *pm3_arguments).stdout)
        self.assertIn("pm3.hw-version", self.run_cli("pm3-commands").stdout)
        self.run_cli(
            "pm3-command-add",
            "--key", "pm3.e2e-noop",
            "--name", "E2E PM3 noop",
            "--description", "Fake PM3 command for CLI E2E testing.",
            "--command", "hw version",
            "--operation", "inspect",
            "--risk", "read_only",
            "--timeout", "10",
        )
        self.assertIn("pm3.e2e-noop", self.run_cli("pm3-commands").stdout)
        self.assertIn("fake-pm3", self.run_cli("pm3-run", "pm3.e2e-noop", *pm3_arguments).stdout)
        firmware_backup = self.workspace / "firmware-backup.bin"
        self.run_cli(
            "pm3-firmware-backup",
            *pm3_arguments,
            "--output", str(firmware_backup),
            "--length", "64",
            "--timeout", "10",
        )
        self.assertEqual(firmware_backup.stat().st_size, 64)
        firmware_image = self.workspace / "firmware.elf"
        firmware_image.write_bytes(b"\x7fELF-e2e")
        self.run_cli(
            "pm3-firmware-flash",
            *pm3_arguments,
            "--fullimage", str(firmware_image),
            "--confirm",
            "--force",
            "--timeout", "10",
        )
        self.assertIn("pm3.e2e-noop", self.run_cli("pm3-history").stdout)

        self.assertIn("No RFID elements", self.run_cli("list").stdout)
        source_dump, source_json, source_keys = self.write_mfc_fixture("source", b"\x11\x22\x33\x44")
        source_log = self.workspace / "source.log"
        source_log.write_text("fake source acquisition\n", encoding="utf-8")
        self.run_cli(
            "import-mfc",
            "--run-key", "read:e2e-source",
            "--read-at", self.timestamp,
            "--label", "E2E source fob",
            "--dump", str(source_dump),
            "--verification-dump", str(source_dump),
            "--json", str(source_json),
            "--verification-json", str(source_json),
            "--keys", str(source_keys),
            "--log", str(source_log),
        )
        self.assertIn("E2E source fob", self.run_cli("list").stdout)
        self.assertIn("E2E source fob", self.run_cli("show", "1", "--reveal-sensitive", "--reveal-keys").stdout)

        self.run_cli(
            "device-add",
            "--project", project_key,
            "--key", clone_key,
            "--name", "E2E clone target",
            "--kind", "rfid_key_fob",
            "--role", "credential",
            "--ownership", "user_owned",
        )
        factory_dump, factory_json, _unused_factory_keys = self.write_mfc_fixture("factory", b"\xA1\xB2\xC3\xD4")
        clone_log = self.workspace / "clone.log"
        clone_log.write_text("fake clone verification\n", encoding="utf-8")
        self.run_cli(
            "clone-record",
            "--run-key", "clone:e2e",
            "--executed-at", self.timestamp,
            "--source-device", "element:1",
            "--target-device", clone_key,
            "--source-read", "read:e2e-source",
            "--uid-before", "A1B2C3D4",
            "--uid-after", "11223344",
            "--factory-dump", str(factory_dump),
            "--factory-json", str(factory_json),
            "--magic-dump", str(source_dump),
            "--magic-json", str(source_json),
            "--standard-dump", str(source_dump),
            "--standard-json", str(source_json),
            "--log", str(clone_log),
            "--extra-artifact", str(source_log),
        )
        self.assertIn(clone_key, self.run_cli("clones").stdout)
        self.assertIn(clone_key, self.run_cli("device-show", "--device", clone_key).stdout)
        self.assertIn("OK:", self.run_cli("verify").stdout)
        database_backup = self.workspace / "backups" / "e2e-complete.sqlite3"
        self.assertIn(
            "Verified database backup",
            self.run_cli("database-backup", "--output", str(database_backup)).stdout,
        )
        self.assertIn("e2e-complete.sqlite3", self.run_cli("database-backups").stdout)
        self.assertIn(
            "Restored database",
            self.run_cli("database-restore", "--backup", str(database_backup), "--confirm").stdout,
        )
        self.assertIn("OK:", self.run_cli("verify").stdout)
        self.assertEqual(self.executed_commands, expected_commands)


if __name__ == "__main__":
    unittest.main()
