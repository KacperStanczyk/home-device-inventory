#!/usr/bin/env python3
"""Local SQLite inventory for authorized home devices and protected RFID records."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import re
import signal
import shlex
import sqlite3
import subprocess
import sys
import time
from typing import Any, Iterable

import rfid_device


ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "vault" / "rfid_inventory.sqlite3"
SCHEMA = ROOT / "schema.sql"
MIGRATION_V6 = ROOT / "migrations" / "006_managed_device_scripts.sql"
MIGRATION_V7 = ROOT / "migrations" / "007_future_ready_inventory.sql"
SCHEMA_VERSION = 7
DEFAULT_PROJECT_KEY = "rfid-home-lab"
HOME_PROJECT_KEY = "home-infrastructure"
FULL_AUTHORIZED_OPERATIONS = (
    "identify",
    "inspect",
    "read",
    "analyze",
    "test",
    "write",
    "configure",
    "administer",
)

DEFAULT_DEVICE_TYPES = {
    "rfid_reader": "rfid.reader",
    "rfid_tag": "rfid.tag",
    "rfid_card": "rfid.card",
    "rfid_key_fob": "rfid.key_fob",
    "access_controller": "access.controller",
    "lock": "access.lock",
    "computer": "computing.computer",
    "embedded_device": "embedded.device",
    "network_device": "network.device",
    "test_equipment": "test.equipment",
    "other": "generic.device",
}

SECRET_PROPERTY_RE = re.compile(r"(?:password|passwd|token|secret|private[._-]?key|credential|psk)", re.IGNORECASE)
MANAGED_SCRIPT_ROOTS = (ROOT.resolve(), (ROOT.parent / "Raspberry").resolve())
MANAGED_SCRIPT_GUARD_RE = re.compile(
    r"(?m)^\s*(?:if|elif)\b[^\n]*DEVICE_CLI_CONTEXT[^\n]*DEVICE_CLI_SCRIPT_KEY"
)


def local_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def normalize_hex(value: str, expected_bytes: int | None = None) -> str:
    result = "".join(value.split()).upper()
    if not result or len(result) % 2 or any(c not in "0123456789ABCDEF" for c in result):
        raise ValueError(f"Invalid hexadecimal value: {value!r}")
    if expected_bytes is not None and len(result) != expected_bytes * 2:
        raise ValueError(f"Expected {expected_bytes} bytes, got {len(result) // 2}")
    return result


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_offset_timestamp(value: str) -> str:
    if "T" not in value or not (value.endswith("Z") or "+" in value[10:] or "-" in value[10:]):
        raise ValueError("Timestamp must use ISO 8601 and include a time-zone offset")
    return value


def catalog_key(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{1,127}", value):
        raise ValueError(
            "A catalog key must contain 2-128 lowercase letters, numbers, dots, colons, underscores, or hyphens"
        )
    return value


def open_database(path: Path) -> sqlite3.Connection:
    parent_was_missing = not path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if parent_was_missing:
        os.chmod(path.parent, 0o700)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA secure_delete = ON")
    connection.execute("PRAGMA journal_mode = DELETE")
    return connection


def record_schema_migration(
    connection: sqlite3.Connection,
    *,
    migration_key: str,
    schema_version: int,
    script_path: Path,
    description: str,
    applied_at: str | None = None,
) -> None:
    """Record an applied schema script without changing historical records."""
    script_hash = sha256(script_path.read_bytes())
    connection.execute(
        """
        INSERT OR IGNORE INTO schema_migrations(
            migration_key, schema_version, script_sha256, applied_at, description
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            migration_key,
            schema_version,
            script_hash,
            utc_offset_timestamp(applied_at or local_timestamp()),
            description,
        ),
    )


def backfill_managed_script_integrity(connection: sqlite3.Connection) -> None:
    """Set the initial reviewed hash only for scripts that predate schema v7."""
    rows = connection.execute(
        "SELECT script_key, relative_path, script_sha256 FROM device_scripts WHERE script_sha256 = ''"
    ).fetchall()
    for row in rows:
        script_path = registered_managed_script_path(str(row["relative_path"]))
        connection.execute(
            "UPDATE device_scripts SET script_sha256 = ? WHERE script_key = ?",
            (sha256(script_path.read_bytes()), row["script_key"]),
        )


def initialize(connection: sqlite3.Connection) -> None:
    previous_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if previous_version == 0:
        connection.executescript(SCHEMA.read_text(encoding="utf-8"))
        record_schema_migration(
            connection,
            migration_key="schema-baseline-v7",
            schema_version=SCHEMA_VERSION,
            script_path=SCHEMA,
            description="New Home Device Inventory schema baseline.",
        )
    elif previous_version == 5:
        connection.executescript(MIGRATION_V6.read_text(encoding="utf-8"))
        connection.executescript(MIGRATION_V7.read_text(encoding="utf-8"))
        record_schema_migration(
            connection,
            migration_key="006_managed_device_scripts",
            schema_version=6,
            script_path=MIGRATION_V6,
            description="Managed device scripts and audited CLI execution.",
        )
        record_schema_migration(
            connection,
            migration_key="007_future_ready_inventory",
            schema_version=7,
            script_path=MIGRATION_V7,
            description="Script integrity, lifecycle retention, contracts, and backup registry.",
        )
    elif previous_version == 6:
        connection.executescript(MIGRATION_V7.read_text(encoding="utf-8"))
        record_schema_migration(
            connection,
            migration_key="007_future_ready_inventory",
            schema_version=7,
            script_path=MIGRATION_V7,
            description="Script integrity, lifecycle retention, contracts, and backup registry.",
        )
    elif previous_version != SCHEMA_VERSION:
        raise ValueError(
            f"Database schema version {previous_version} is not supported. "
            "Only the v5 to v6 and v6 to v7 migrations are available."
        )
    bootstrap_catalog(connection)
    backfill_managed_script_integrity(connection)
    if connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 0:
        record_schema_migration(
            connection,
            migration_key="schema-baseline-v7",
            schema_version=SCHEMA_VERSION,
            script_path=SCHEMA,
            description="Schema v7 was already present before migration history was enabled.",
        )
    connection.commit()


def get_project_id(connection: sqlite3.Connection, project_key: str) -> int:
    row = connection.execute(
        "SELECT id FROM projects WHERE project_key = ?", (catalog_key(project_key),)
    ).fetchone()
    if row is None:
        raise ValueError(f"Project {project_key!r} does not exist")
    return int(row[0])


def get_device_id(connection: sqlite3.Connection, device_key: str) -> int:
    row = connection.execute(
        "SELECT id FROM devices WHERE device_key = ?", (catalog_key(device_key),)
    ).fetchone()
    if row is None:
        raise ValueError(f"Device {device_key!r} does not exist")
    return int(row[0])


def get_device_type(connection: sqlite3.Connection, type_key: str, device_kind: str) -> str:
    normalized_key = catalog_key(type_key)
    row = connection.execute(
        "SELECT default_device_kind, status FROM device_types WHERE type_key = ?", (normalized_key,)
    ).fetchone()
    if row is None:
        raise ValueError(f"Device type {type_key!r} does not exist")
    if row["status"] != "active":
        raise ValueError(f"Device type {type_key!r} is not active")
    if row["default_device_kind"] != device_kind:
        raise ValueError(
            f"Device type {type_key!r} requires device kind {row['default_device_kind']!r}, "
            f"not {device_kind!r}"
        )
    return normalized_key


def create_project(
    connection: sqlite3.Connection,
    *,
    project_key: str,
    name: str,
    description: str,
    purpose: str,
    owner_subject: str,
    authorization_policy: str,
    scope_notes: str | None,
    status: str = "active",
    now: str | None = None,
) -> int:
    now = utc_offset_timestamp(now or local_timestamp())
    connection.execute(
        """
        INSERT INTO projects(
            project_key, name, description, purpose, owner_subject, status,
            authorization_policy, scope_notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(project_key) DO NOTHING
        """,
        (
            catalog_key(project_key),
            name,
            description,
            purpose,
            owner_subject,
            status,
            authorization_policy,
            scope_notes,
            now,
            now,
        ),
    )
    return get_project_id(connection, project_key)


def add_device(
    connection: sqlite3.Connection,
    *,
    project_key: str,
    device_key: str,
    name: str,
    device_kind: str,
    role: str,
    ownership_status: str,
    manufacturer: str | None = None,
    model: str | None = None,
    serial_number: str | None = None,
    interface: str | None = None,
    location_label: str | None = None,
    sensitivity: str = "sensitive",
    device_type_key: str | None = None,
    scope: str = "Pending explicit per-device authorization",
    now: str | None = None,
) -> int:
    now = utc_offset_timestamp(now or local_timestamp())
    project_id = get_project_id(connection, project_key)
    type_key = get_device_type(
        connection, device_type_key or DEFAULT_DEVICE_TYPES[device_kind], device_kind
    )
    connection.execute(
        """
        INSERT INTO devices(
            device_key, name, device_kind, role, manufacturer, model, serial_number,
            interface, location_label, ownership_status, lifecycle_status, sensitivity,
            device_type_key, metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, '{}', ?, ?)
        ON CONFLICT(device_key) DO UPDATE SET
            name=excluded.name,
            device_kind=excluded.device_kind,
            role=excluded.role,
            manufacturer=COALESCE(excluded.manufacturer, devices.manufacturer),
            model=COALESCE(excluded.model, devices.model),
            serial_number=COALESCE(excluded.serial_number, devices.serial_number),
            interface=COALESCE(excluded.interface, devices.interface),
            location_label=COALESCE(excluded.location_label, devices.location_label),
            ownership_status=excluded.ownership_status,
            sensitivity=excluded.sensitivity,
            device_type_key=excluded.device_type_key,
            updated_at=excluded.updated_at
        """,
        (
            catalog_key(device_key),
            name,
            device_kind,
            role,
            manufacturer,
            model,
            serial_number,
            interface,
            location_label,
            ownership_status,
            sensitivity,
            type_key,
            now,
            now,
        ),
    )
    device_id = get_device_id(connection, device_key)
    connection.execute(
        """
        INSERT INTO project_devices(
            project_id, device_id, role_in_project, scope, status, added_at, updated_at
        ) VALUES (?, ?, ?, ?, 'pending_authorization', ?, ?)
        ON CONFLICT(project_id, device_id) DO UPDATE SET
            role_in_project=excluded.role_in_project,
            scope=excluded.scope,
            updated_at=excluded.updated_at
        """,
        (project_id, device_id, role, scope, now, now),
    )
    connection.commit()
    return device_id


def grant_access(
    connection: sqlite3.Connection,
    *,
    project_key: str,
    device_key: str,
    authorization_key: str,
    subject: str,
    authorization_basis: str,
    access_level: str,
    operations: Iterable[str],
    purpose: str,
    evidence_reference: str,
    valid_from: str,
    valid_until: str | None = None,
    notes: str | None = None,
    now: str | None = None,
) -> int:
    now = utc_offset_timestamp(now or local_timestamp())
    valid_from = utc_offset_timestamp(valid_from)
    if valid_until is not None:
        valid_until = utc_offset_timestamp(valid_until)
    normalized_operations = sorted({operation.strip().lower() for operation in operations if operation.strip()})
    if not normalized_operations:
        raise ValueError("At least one allowed operation is required")
    unsupported_operations = set(normalized_operations).difference(FULL_AUTHORIZED_OPERATIONS)
    if unsupported_operations:
        raise ValueError(
            "Unsupported authorization operation(s): " + ", ".join(sorted(unsupported_operations))
        )
    project_id = get_project_id(connection, project_key)
    device_id = get_device_id(connection, device_key)
    mapping = connection.execute(
        "SELECT 1 FROM project_devices WHERE project_id = ? AND device_id = ?",
        (project_id, device_id),
    ).fetchone()
    if mapping is None:
        raise ValueError(f"Device {device_key!r} is not assigned to project {project_key!r}")
    device = connection.execute("SELECT device_kind FROM devices WHERE id = ?", (device_id,)).fetchone()
    if device["device_kind"] in {"rfid_reader", "rfid_tag", "rfid_card", "rfid_key_fob"}:
        if connection.execute("SELECT 1 FROM rfid_profiles WHERE device_id = ?", (device_id,)).fetchone() is None:
            raise ValueError("RFID device requires an RFID profile before an active authorization is granted")
    connection.execute(
        """
        INSERT INTO access_authorizations(
            authorization_key, project_id, device_id, subject, authorization_basis,
            access_level, allowed_operations_json, purpose, evidence_reference,
            status, valid_from, valid_until, authorized_at, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
        ON CONFLICT(authorization_key) DO UPDATE SET
            project_id=excluded.project_id,
            device_id=excluded.device_id,
            subject=excluded.subject,
            authorization_basis=excluded.authorization_basis,
            access_level=excluded.access_level,
            allowed_operations_json=excluded.allowed_operations_json,
            purpose=excluded.purpose,
            evidence_reference=excluded.evidence_reference,
            status='active',
            valid_from=excluded.valid_from,
            valid_until=excluded.valid_until,
            authorized_at=excluded.authorized_at,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        (
            catalog_key(authorization_key),
            project_id,
            device_id,
            subject,
            authorization_basis,
            access_level,
            json.dumps(normalized_operations, separators=(",", ":")),
            purpose,
            evidence_reference,
            valid_from,
            valid_until,
            now,
            notes,
            now,
            now,
        ),
    )
    connection.execute(
        """
        UPDATE project_devices
        SET status = 'in_scope', updated_at = ?
        WHERE project_id = ? AND device_id = ?
        """,
        (now, project_id, device_id),
    )
    authorization_id = int(
        connection.execute(
            "SELECT id FROM access_authorizations WHERE authorization_key = ?",
            (authorization_key,),
        ).fetchone()[0]
    )
    connection.execute(
        "DELETE FROM access_authorization_operations WHERE authorization_id = ?",
        (authorization_id,),
    )
    connection.executemany(
        """
        INSERT INTO access_authorization_operations(authorization_id, operation, created_at)
        VALUES (?, ?, ?)
        """,
        [(authorization_id, operation, now) for operation in normalized_operations],
    )
    connection.commit()
    return authorization_id


def canonical_json(value: str) -> str:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError("Value must be valid JSON") from error
    return json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def json_object(value: str, field_name: str) -> dict[str, Any]:
    parsed = json.loads(canonical_json(value))
    if not isinstance(parsed, dict):
        raise ValueError(f"{field_name} must be a JSON object")
    return parsed


def json_array(value: str, field_name: str) -> list[Any]:
    parsed = json.loads(canonical_json(value))
    if not isinstance(parsed, list):
        raise ValueError(f"{field_name} must be a JSON array")
    return parsed


def set_device_type_contract(
    connection: sqlite3.Connection,
    *,
    type_key: str,
    enforcement: str,
    capabilities_json: str,
    information_schema_json: str,
    measurement_schema_json: str,
    source_reference: str,
    notes: str | None = None,
    now: str | None = None,
) -> str:
    """Store one reviewed data contract for an extensible device type."""
    now = utc_offset_timestamp(now or local_timestamp())
    normalized_type = catalog_key(type_key)
    if connection.execute(
        "SELECT 1 FROM device_types WHERE type_key = ?", (normalized_type,)
    ).fetchone() is None:
        raise ValueError(f"Device type {type_key!r} does not exist")
    if enforcement not in {"advisory", "strict"}:
        raise ValueError("Device type contract enforcement must be advisory or strict")
    capabilities = json_array(capabilities_json, "Capabilities")
    if any(not isinstance(value, str) or catalog_key(value) != value for value in capabilities):
        raise ValueError("Each capability must be a catalog key")
    information_schema = json_object(information_schema_json, "Information schema")
    measurement_schema = json_object(measurement_schema_json, "Measurement schema")
    for property_key, rule in information_schema.items():
        catalog_key(property_key)
        if not isinstance(rule, dict):
            raise ValueError("Each information schema rule must be a JSON object")
    for channel_key, rule in measurement_schema.items():
        catalog_key(channel_key)
        if not isinstance(rule, dict):
            raise ValueError("Each measurement schema rule must be a JSON object")
    connection.execute(
        """
        INSERT INTO device_type_contracts(
            device_type_key, enforcement, capabilities_json, information_schema_json,
            measurement_schema_json, source_reference, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_type_key) DO UPDATE SET
            enforcement=excluded.enforcement,
            capabilities_json=excluded.capabilities_json,
            information_schema_json=excluded.information_schema_json,
            measurement_schema_json=excluded.measurement_schema_json,
            source_reference=excluded.source_reference,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        (
            normalized_type,
            enforcement,
            json.dumps(capabilities, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            json.dumps(information_schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            json.dumps(measurement_schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            source_reference,
            notes,
            now,
            now,
        ),
    )
    connection.commit()
    return normalized_type


def _device_type_contract(connection: sqlite3.Connection, device_id: int) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT contract.*
        FROM devices AS device
        JOIN device_type_contracts AS contract ON contract.device_type_key = device.device_type_key
        WHERE device.id = ?
        """,
        (device_id,),
    ).fetchone()


def _json_value_matches_type(value: Any, expected_type: str) -> bool:
    if expected_type == "null":
        return value is None
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "object":
        return isinstance(value, dict)
    raise ValueError(f"Unsupported contract JSON value type {expected_type!r}")


def validate_device_information_contract(
    connection: sqlite3.Connection,
    *,
    device_id: int,
    property_key: str,
    information_kind: str,
    value: Any,
    unit: str | None,
) -> None:
    contract = _device_type_contract(connection, device_id)
    if contract is None:
        return
    schema = json.loads(contract["information_schema_json"])
    rule = schema.get(property_key)
    if rule is None:
        if contract["enforcement"] == "strict" and schema:
            raise ValueError(
                f"Device type {contract['device_type_key']} does not allow information property {property_key!r}"
            )
        return
    expected_kinds = rule.get("information_kinds")
    if expected_kinds is not None and information_kind not in expected_kinds:
        raise ValueError(f"Information property {property_key!r} does not allow kind {information_kind!r}")
    expected_type = rule.get("value_type")
    if expected_type is not None and not _json_value_matches_type(value, expected_type):
        raise ValueError(f"Information property {property_key!r} must use JSON type {expected_type!r}")
    expected_unit = rule.get("unit")
    if expected_unit is not None and unit != expected_unit:
        raise ValueError(f"Information property {property_key!r} must use unit {expected_unit!r}")


def validate_measurement_channel_contract(
    connection: sqlite3.Connection,
    *,
    device_id: int,
    channel_key: str,
    quantity_kind: str,
    unit: str,
    minimum_value: float | None,
    maximum_value: float | None,
) -> None:
    contract = _device_type_contract(connection, device_id)
    if contract is None:
        return
    schema = json.loads(contract["measurement_schema_json"])
    rule = schema.get(channel_key)
    if rule is None:
        if contract["enforcement"] == "strict" and schema:
            raise ValueError(
                f"Device type {contract['device_type_key']} does not allow measurement channel {channel_key!r}"
            )
        return
    for field_name, actual_value in (("quantity_kind", quantity_kind), ("unit", unit)):
        expected_value = rule.get(field_name)
        if expected_value is not None and actual_value != expected_value:
            raise ValueError(
                f"Measurement channel {channel_key!r} must use {field_name} {expected_value!r}"
            )
    expected_minimum = rule.get("minimum")
    if expected_minimum is not None and (minimum_value is None or minimum_value < expected_minimum):
        raise ValueError(
            f"Measurement channel {channel_key!r} must use minimum greater than or equal to {expected_minimum!r}"
        )
    expected_maximum = rule.get("maximum")
    if expected_maximum is not None and (maximum_value is None or maximum_value > expected_maximum):
        raise ValueError(
            f"Measurement channel {channel_key!r} must use maximum less than or equal to {expected_maximum!r}"
        )


def add_device_type(
    connection: sqlite3.Connection,
    *,
    type_key: str,
    display_name: str,
    category: str,
    default_device_kind: str,
    description: str,
    now: str | None = None,
) -> str:
    now = utc_offset_timestamp(now or local_timestamp())
    normalized_key = catalog_key(type_key)
    connection.execute(
        """
        INSERT INTO device_types(
            type_key, display_name, category, default_device_kind, description, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
        ON CONFLICT(type_key) DO UPDATE SET
            display_name=excluded.display_name,
            category=excluded.category,
            default_device_kind=excluded.default_device_kind,
            description=excluded.description,
            status='active',
            updated_at=excluded.updated_at
        """,
        (normalized_key, display_name, category, default_device_kind, description, now, now),
    )
    connection.commit()
    return normalized_key


def add_device_identifier(
    connection: sqlite3.Connection,
    *,
    device_key: str,
    identifier_kind: str,
    identifier_value: str,
    identifier_scope: str = "",
    classification: str = "sensitive",
    source_reference: str,
    status: str = "active",
    observed_at: str | None = None,
    notes: str | None = None,
    now: str | None = None,
) -> int:
    now = utc_offset_timestamp(now or local_timestamp())
    observed_at = utc_offset_timestamp(observed_at or now)
    device_id = get_device_id(connection, device_key)
    connection.execute(
        """
        INSERT INTO device_identifiers(
            device_id, identifier_kind, identifier_value, identifier_scope, classification,
            source_reference, status, observed_at, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id, identifier_kind, identifier_value, identifier_scope) DO UPDATE SET
            classification=excluded.classification,
            source_reference=excluded.source_reference,
            status=excluded.status,
            observed_at=excluded.observed_at,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        (
            device_id,
            catalog_key(identifier_kind),
            identifier_value.strip(),
            identifier_scope.strip(),
            classification,
            source_reference,
            status,
            observed_at,
            notes,
            now,
            now,
        ),
    )
    identifier_id = int(
        connection.execute(
            """
            SELECT id FROM device_identifiers
            WHERE device_id = ? AND identifier_kind = ? AND identifier_value = ? AND identifier_scope = ?
            """,
            (device_id, catalog_key(identifier_kind), identifier_value.strip(), identifier_scope.strip()),
        ).fetchone()[0]
    )
    connection.commit()
    return identifier_id


def set_device_information(
    connection: sqlite3.Connection,
    *,
    device_key: str,
    information_kind: str,
    property_key: str,
    value_json: str,
    source_reference: str,
    confidence: str = "reported",
    classification: str = "normal",
    is_current: bool = True,
    unit: str | None = None,
    observed_at: str | None = None,
    notes: str | None = None,
    now: str | None = None,
) -> int:
    now = utc_offset_timestamp(now or local_timestamp())
    observed_at = utc_offset_timestamp(observed_at or now)
    normalized_property = catalog_key(property_key)
    if SECRET_PROPERTY_RE.search(normalized_property):
        raise ValueError("Do not store a secret as device information; use access-method-set --secret-reference")
    canonical_value = canonical_json(value_json)
    device_id = get_device_id(connection, device_key)
    validate_device_information_contract(
        connection,
        device_id=device_id,
        property_key=normalized_property,
        information_kind=information_kind,
        value=json.loads(canonical_value),
        unit=unit,
    )
    if is_current:
        connection.execute(
            "UPDATE device_information SET is_current = 0, updated_at = ? "
            "WHERE device_id = ? AND property_key = ? AND is_current = 1",
            (now, device_id, normalized_property),
        )
    information_key = "info:" + sha256(
        f"{device_id}\0{normalized_property}\0{observed_at}\0{canonical_value}".encode("utf-8")
    )[:24]
    connection.execute(
        """
        INSERT INTO device_information(
            information_key, device_id, information_kind, property_key, value_json, unit,
            source_reference, confidence, classification, is_current, observed_at, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(information_key) DO UPDATE SET
            information_kind=excluded.information_kind,
            value_json=excluded.value_json,
            unit=excluded.unit,
            source_reference=excluded.source_reference,
            confidence=excluded.confidence,
            classification=excluded.classification,
            is_current=excluded.is_current,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        (
            information_key,
            device_id,
            information_kind,
            normalized_property,
            canonical_value,
            unit,
            source_reference,
            confidence,
            classification,
            int(is_current),
            observed_at,
            notes,
            now,
            now,
        ),
    )
    information_id = int(
        connection.execute("SELECT id FROM device_information WHERE information_key = ?", (information_key,)).fetchone()[0]
    )
    connection.commit()
    return information_id


def set_device_interface(
    connection: sqlite3.Connection,
    *,
    device_key: str,
    interface_key: str,
    interface_type: str,
    source_reference: str,
    endpoint: str | None = None,
    address: str | None = None,
    authentication_type: str | None = None,
    secret_reference: str | None = None,
    status: str = "active",
    details_json: str = "{}",
    observed_at: str | None = None,
    notes: str | None = None,
    now: str | None = None,
) -> int:
    now = utc_offset_timestamp(now or local_timestamp())
    observed_at = utc_offset_timestamp(observed_at or now)
    if endpoint and re.search(r"://[^/@\s:]+:[^/@\s]+@", endpoint):
        raise ValueError("Endpoint must not contain embedded credentials")
    device_id = get_device_id(connection, device_key)
    normalized_key = catalog_key(interface_key)
    connection.execute(
        """
        INSERT INTO device_interfaces(
            device_id, interface_key, interface_type, endpoint, address, authentication_type,
            secret_reference, status, details_json, source_reference, observed_at, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id, interface_key) DO UPDATE SET
            interface_type=excluded.interface_type,
            endpoint=excluded.endpoint,
            address=excluded.address,
            authentication_type=excluded.authentication_type,
            secret_reference=excluded.secret_reference,
            status=excluded.status,
            details_json=excluded.details_json,
            source_reference=excluded.source_reference,
            observed_at=excluded.observed_at,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        (
            device_id,
            normalized_key,
            interface_type,
            endpoint,
            address,
            authentication_type,
            secret_reference,
            status,
            canonical_json(details_json),
            source_reference,
            observed_at,
            notes,
            now,
            now,
        ),
    )
    interface_id = int(
        connection.execute(
            "SELECT id FROM device_interfaces WHERE device_id = ? AND interface_key = ?",
            (device_id, normalized_key),
        ).fetchone()[0]
    )
    connection.commit()
    return interface_id


def set_access_method(
    connection: sqlite3.Connection,
    *,
    project_key: str,
    device_key: str,
    method_key: str,
    method_type: str,
    source_reference: str,
    endpoint: str | None = None,
    account_label: str | None = None,
    authentication_type: str | None = None,
    secret_reference: str | None = None,
    status: str = "active",
    notes: str | None = None,
    now: str | None = None,
) -> int:
    now = utc_offset_timestamp(now or local_timestamp())
    if endpoint and re.search(r"://[^/@\s:]+:[^/@\s]+@", endpoint):
        raise ValueError("Endpoint must not contain embedded credentials")
    project_id = get_project_id(connection, project_key)
    device_id = get_device_id(connection, device_key)
    if connection.execute(
        "SELECT 1 FROM project_devices WHERE project_id = ? AND device_id = ?", (project_id, device_id)
    ).fetchone() is None:
        raise ValueError(f"Device {device_key!r} is not assigned to project {project_key!r}")
    normalized_key = catalog_key(method_key)
    connection.execute(
        """
        INSERT INTO access_methods(
            project_id, device_id, method_key, method_type, endpoint, account_label,
            authentication_type, secret_reference, status, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(project_id, device_id, method_key) DO UPDATE SET
            method_type=excluded.method_type,
            endpoint=excluded.endpoint,
            account_label=excluded.account_label,
            authentication_type=excluded.authentication_type,
            secret_reference=excluded.secret_reference,
            status=excluded.status,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        (
            project_id, device_id, normalized_key, method_type, endpoint, account_label,
            authentication_type, secret_reference, status, notes, now, now,
        ),
    )
    method_id = int(
        connection.execute(
            "SELECT id FROM access_methods WHERE project_id = ? AND device_id = ? AND method_key = ?",
            (project_id, device_id, normalized_key),
        ).fetchone()[0]
    )
    connection.commit()
    return method_id


def add_device_relation(
    connection: sqlite3.Connection,
    *,
    source_device_key: str,
    target_device_key: str,
    relation_type: str,
    source_reference: str,
    status: str = "active",
    observed_at: str | None = None,
    notes: str | None = None,
    now: str | None = None,
) -> int:
    now = utc_offset_timestamp(now or local_timestamp())
    observed_at = utc_offset_timestamp(observed_at or now)
    source_device_id = get_device_id(connection, source_device_key)
    target_device_id = get_device_id(connection, target_device_key)
    if source_device_id == target_device_id:
        raise ValueError("A device relation must use two different devices")
    normalized_type = catalog_key(relation_type)
    type_row = connection.execute(
        "SELECT status FROM device_relation_types WHERE relation_type = ?", (normalized_type,)
    ).fetchone()
    if type_row is None or type_row["status"] != "active":
        raise ValueError(
            f"Device relation type {normalized_type!r} is not registered and active; use relation-type-add first"
        )
    connection.execute(
        """
        INSERT INTO device_relations(
            source_device_id, target_device_id, relation_type, source_reference, status,
            observed_at, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_device_id, target_device_id, relation_type) DO UPDATE SET
            source_reference=excluded.source_reference,
            status=excluded.status,
            observed_at=excluded.observed_at,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        (source_device_id, target_device_id, normalized_type, source_reference, status, observed_at, notes, now, now),
    )
    relation_id = int(connection.execute(
        "SELECT id FROM device_relations WHERE source_device_id = ? AND target_device_id = ? AND relation_type = ?",
        (source_device_id, target_device_id, normalized_type),
    ).fetchone()[0])
    connection.commit()
    return relation_id


def add_relation_type(
    connection: sqlite3.Connection,
    *,
    relation_type: str,
    display_name: str,
    description: str,
    directional: bool,
    now: str | None = None,
) -> str:
    """Register a controlled relation term before it is used by a device link."""
    now = utc_offset_timestamp(now or local_timestamp())
    normalized_type = catalog_key(relation_type)
    if not display_name.strip() or not description.strip():
        raise ValueError("Relation type name and description are required")
    connection.execute(
        """
        INSERT INTO device_relation_types(
            relation_type, display_name, description, directional, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'active', ?, ?)
        ON CONFLICT(relation_type) DO UPDATE SET
            display_name=excluded.display_name,
            description=excluded.description,
            directional=excluded.directional,
            status='active',
            updated_at=excluded.updated_at
        """,
        (normalized_type, display_name.strip(), description.strip(), int(directional), now, now),
    )
    connection.commit()
    return normalized_type


def list_relation_types(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    return connection.execute(
        """
        SELECT relation_type, display_name, description, directional, status
        FROM device_relation_types
        ORDER BY relation_type
        """
    ).fetchall()


def set_device_component(
    connection: sqlite3.Connection,
    *,
    device_key: str,
    component_key: str,
    component_kind: str,
    name: str,
    source_reference: str,
    version: str | None = None,
    status: str = "active",
    details_json: str = "{}",
    observed_at: str | None = None,
    notes: str | None = None,
    now: str | None = None,
) -> int:
    now = utc_offset_timestamp(now or local_timestamp())
    observed_at = utc_offset_timestamp(observed_at or now)
    device_id = get_device_id(connection, device_key)
    normalized_key = catalog_key(component_key)
    connection.execute(
        """
        INSERT INTO device_components(
            device_id, component_key, component_kind, name, version, status, details_json,
            source_reference, observed_at, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id, component_key) DO UPDATE SET
            component_kind=excluded.component_kind,
            name=excluded.name,
            version=excluded.version,
            status=excluded.status,
            details_json=excluded.details_json,
            source_reference=excluded.source_reference,
            observed_at=excluded.observed_at,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        (
            device_id, normalized_key, component_kind, name, version, status,
            canonical_json(details_json), source_reference, observed_at, notes, now, now,
        ),
    )
    component_id = int(connection.execute(
        "SELECT id FROM device_components WHERE device_id = ? AND component_key = ?",
        (device_id, normalized_key),
    ).fetchone()[0])
    connection.commit()
    return component_id


def set_rfid_profile(
    connection: sqlite3.Connection,
    *,
    device_key: str,
    profile_kind: str,
    source_reference: str,
    frequency_mhz: float | None = None,
    standard: str | None = None,
    technology: str | None = None,
    product_family: str | None = None,
    chip_vendor: str | None = None,
    chip_model: str | None = None,
    uid_identifier_id: int | None = None,
    legacy_reader_id: int | None = None,
    legacy_element_id: int | None = None,
    technical_json: str = "{}",
    observed_at: str | None = None,
    notes: str | None = None,
    now: str | None = None,
) -> int:
    now = utc_offset_timestamp(now or local_timestamp())
    observed_at = utc_offset_timestamp(observed_at or now)
    device_id = get_device_id(connection, device_key)
    row = connection.execute("SELECT device_kind FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row["device_kind"] not in {"rfid_reader", "rfid_tag", "rfid_card", "rfid_key_fob", "access_controller"}:
        raise ValueError("RFID profile requires an RFID or access-controller device")
    connection.execute(
        """
        INSERT INTO rfid_profiles(
            device_id, profile_kind, frequency_mhz, standard, technology, product_family,
            chip_vendor, chip_model, uid_identifier_id, legacy_reader_id, legacy_element_id,
            technical_json, source_reference, observed_at, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
            profile_kind=excluded.profile_kind,
            frequency_mhz=excluded.frequency_mhz,
            standard=excluded.standard,
            technology=excluded.technology,
            product_family=excluded.product_family,
            chip_vendor=excluded.chip_vendor,
            chip_model=excluded.chip_model,
            uid_identifier_id=excluded.uid_identifier_id,
            legacy_reader_id=excluded.legacy_reader_id,
            legacy_element_id=excluded.legacy_element_id,
            technical_json=excluded.technical_json,
            source_reference=excluded.source_reference,
            observed_at=excluded.observed_at,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        (
            device_id, profile_kind, frequency_mhz, standard, technology, product_family,
            chip_vendor, chip_model, uid_identifier_id, legacy_reader_id, legacy_element_id,
            canonical_json(technical_json), source_reference, observed_at, notes, now, now,
        ),
    )
    connection.commit()
    return device_id


def add_measurement_channel(
    connection: sqlite3.Connection,
    *,
    device_key: str,
    channel_key: str,
    display_name: str,
    quantity_kind: str,
    unit: str,
    source_reference: str,
    minimum_value: float | None = None,
    maximum_value: float | None = None,
    retention_days: int | None = None,
    observed_at: str | None = None,
    notes: str | None = None,
    now: str | None = None,
) -> int:
    if minimum_value is not None and maximum_value is not None and minimum_value > maximum_value:
        raise ValueError("Measurement minimum value must not exceed the maximum value")
    now = utc_offset_timestamp(now or local_timestamp())
    observed_at = utc_offset_timestamp(observed_at or now)
    device_id = get_device_id(connection, device_key)
    normalized_key = catalog_key(channel_key)
    validate_measurement_channel_contract(
        connection,
        device_id=device_id,
        channel_key=normalized_key,
        quantity_kind=quantity_kind,
        unit=unit,
        minimum_value=minimum_value,
        maximum_value=maximum_value,
    )
    connection.execute(
        """
        INSERT INTO measurement_channels(
            device_id, channel_key, display_name, quantity_kind, unit, minimum_value, maximum_value,
            retention_days, status, source_reference, observed_at, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
        ON CONFLICT(device_id, channel_key) DO UPDATE SET
            display_name=excluded.display_name,
            quantity_kind=excluded.quantity_kind,
            unit=excluded.unit,
            minimum_value=excluded.minimum_value,
            maximum_value=excluded.maximum_value,
            retention_days=excluded.retention_days,
            status='active',
            source_reference=excluded.source_reference,
            observed_at=excluded.observed_at,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        (
            device_id, normalized_key, display_name, quantity_kind, unit, minimum_value, maximum_value,
            retention_days, source_reference, observed_at, notes, now, now,
        ),
    )
    channel_id = int(connection.execute(
        "SELECT id FROM measurement_channels WHERE device_id = ? AND channel_key = ?",
        (device_id, normalized_key),
    ).fetchone()[0])
    connection.commit()
    return channel_id


def add_measurement_sample(
    connection: sqlite3.Connection,
    *,
    device_key: str,
    channel_key: str,
    observed_at: str,
    value_real: float,
    source_reference: str,
    quality: str = "valid",
    notes: str | None = None,
    now: str | None = None,
) -> int:
    now = utc_offset_timestamp(now or local_timestamp())
    observed_at = utc_offset_timestamp(observed_at)
    device_id = get_device_id(connection, device_key)
    channel = connection.execute(
        """
        SELECT id, status, minimum_value, maximum_value FROM measurement_channels
        WHERE device_id = ? AND channel_key = ?
        """,
        (device_id, catalog_key(channel_key)),
    ).fetchone()
    if channel is None:
        raise ValueError(f"Measurement channel {channel_key!r} does not exist for device {device_key!r}")
    if channel["status"] != "active":
        raise ValueError(f"Measurement channel {channel_key!r} is not active")
    outside_range = (
        (channel["minimum_value"] is not None and value_real < channel["minimum_value"])
        or (channel["maximum_value"] is not None and value_real > channel["maximum_value"])
    )
    if outside_range and quality == "valid":
        raise ValueError("Measurement is outside the declared range; store it with quality=invalid or estimated")
    connection.execute(
        """
        INSERT INTO measurement_samples(channel_id, observed_at, value_real, quality, source_reference, notes, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(channel_id, observed_at) DO UPDATE SET
            value_real=excluded.value_real,
            quality=excluded.quality,
            source_reference=excluded.source_reference,
            notes=excluded.notes,
            recorded_at=excluded.recorded_at
        """,
        (int(channel["id"]), observed_at, value_real, quality, source_reference, notes, now),
    )
    sample_id = int(connection.execute(
        "SELECT id FROM measurement_samples WHERE channel_id = ? AND observed_at = ?",
        (int(channel["id"]), observed_at),
    ).fetchone()[0])
    connection.commit()
    return sample_id


def run_measurement_retention(
    connection: sqlite3.Connection,
    *,
    apply: bool,
    now: str | None = None,
) -> dict[str, Any]:
    """Preview or delete only samples older than each declared channel policy."""
    executed_at = utc_offset_timestamp(now or local_timestamp())
    cutoff_base = datetime.fromisoformat(executed_at)
    run_key = f"retention:measurements:{sha256(os.urandom(16))[:24]}"
    results: list[dict[str, Any]] = []
    candidate_total = 0
    deleted_total = 0
    channels = connection.execute(
        """
        SELECT id, retention_days
        FROM measurement_channels
        WHERE retention_days IS NOT NULL
        ORDER BY id
        """
    ).fetchall()
    for channel in channels:
        cutoff_at = (cutoff_base - timedelta(days=int(channel["retention_days"]))).isoformat(timespec="seconds")
        candidate_count = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM measurement_samples
                WHERE channel_id = ? AND datetime(observed_at) < datetime(?)
                """,
                (channel["id"], cutoff_at),
            ).fetchone()[0]
        )
        deleted_count = 0
        if apply and candidate_count:
            cursor = connection.execute(
                """
                DELETE FROM measurement_samples
                WHERE channel_id = ? AND datetime(observed_at) < datetime(?)
                """,
                (channel["id"], cutoff_at),
            )
            deleted_count = max(0, cursor.rowcount)
        candidate_total += candidate_count
        deleted_total += deleted_count
        results.append(
            {
                "channel_id": int(channel["id"]),
                "cutoff_at": cutoff_at,
                "candidate_count": candidate_count,
                "deleted_count": deleted_count,
            }
        )
    mode = "applied" if apply else "preview"
    connection.execute(
        """
        INSERT INTO measurement_retention_runs(
            run_key, mode, executed_at, channel_count, candidate_count, deleted_count,
            status, notes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'succeeded', ?, ?)
        """,
        (
            run_key,
            mode,
            executed_at,
            len(results),
            candidate_total,
            deleted_total,
            "Samples are deleted only by an explicit --apply --confirm CLI invocation." if apply else "Preview only.",
            executed_at,
        ),
    )
    connection.executemany(
        """
        INSERT INTO measurement_retention_results(
            run_key, channel_id, cutoff_at, candidate_count, deleted_count
        ) VALUES (?, ?, ?, ?, ?)
        """,
        [
            (run_key, result["channel_id"], result["cutoff_at"], result["candidate_count"], result["deleted_count"])
            for result in results
        ],
    )
    connection.commit()
    return {
        "run_key": run_key,
        "mode": mode,
        "channel_count": len(results),
        "candidate_count": candidate_total,
        "deleted_count": deleted_total,
    }


def run_audit_output_retention(
    connection: sqlite3.Connection,
    *,
    apply: bool,
    now: str | None = None,
) -> dict[str, Any]:
    """Remove old command output while retaining its original SHA-256 evidence."""
    executed_at = utc_offset_timestamp(now or local_timestamp())
    retention_row = connection.execute(
        "SELECT value FROM schema_info WHERE key = 'audit_output_retention_days'"
    ).fetchone()
    default_days = int(retention_row["value"]) if retention_row is not None else 90
    candidates = connection.execute(
        """
        SELECT run.id
        FROM device_command_runs AS run
        LEFT JOIN device_commands AS command ON command.id = run.command_id
        WHERE run.output_purged_at IS NULL
          AND (length(run.stdout_content) > 0 OR length(run.stderr_content) > 0)
          AND datetime(run.started_at) < datetime(
              ?, '-' || COALESCE(command.output_retention_days, ?) || ' days'
          )
        ORDER BY run.id
        """,
        (executed_at, default_days),
    ).fetchall()
    candidate_count = len(candidates)
    purged_count = 0
    if apply and candidates:
        empty_hash = sha256(b"")
        for row in candidates:
            cursor = connection.execute(
                """
                UPDATE device_command_runs
                SET stdout_original_sha256=COALESCE(stdout_original_sha256, stdout_sha256),
                    stderr_original_sha256=COALESCE(stderr_original_sha256, stderr_sha256),
                    stdout_sha256=?, stderr_sha256=?, stdout_content=X'', stderr_content=X'',
                    output_purged_at=?
                WHERE id = ? AND output_purged_at IS NULL
                """,
                (empty_hash, empty_hash, executed_at, row["id"]),
            )
            purged_count += max(0, cursor.rowcount)
    mode = "applied" if apply else "preview"
    run_key = f"retention:audit-output:{sha256(os.urandom(16))[:24]}"
    connection.execute(
        """
        INSERT INTO audit_output_retention_runs(
            run_key, mode, executed_at, candidate_count, purged_count, status, notes, created_at
        ) VALUES (?, ?, ?, ?, ?, 'succeeded', ?, ?)
        """,
        (
            run_key,
            mode,
            executed_at,
            candidate_count,
            purged_count,
            "Output content was removed; the original SHA-256 values remain." if apply else "Preview only.",
            executed_at,
        ),
    )
    connection.commit()
    return {
        "run_key": run_key,
        "mode": mode,
        "candidate_count": candidate_count,
        "purged_count": purged_count,
    }


def connection_database_path(connection: sqlite3.Connection) -> Path:
    row = connection.execute("PRAGMA database_list").fetchone()
    if row is None or not row[2]:
        raise ValueError("The SQLite database path is unavailable")
    return Path(row[2]).resolve()


def database_backup_directory(database_path: Path) -> Path:
    return database_path.resolve().parent / "backups"


def managed_database_backup_path(database_path: Path, output_path: Path | None) -> Path:
    backup_directory = database_backup_directory(database_path)
    backup_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(backup_directory, 0o700)
    if output_path is None:
        stamp = datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
        suffix = sha256(os.urandom(16))[:10]
        candidate = backup_directory / f"inventory-{stamp}-{suffix}-schema-v{SCHEMA_VERSION}.sqlite3"
    else:
        candidate = output_path.expanduser().resolve()
    try:
        candidate.relative_to(backup_directory.resolve())
    except ValueError as error:
        raise ValueError(f"Database backup must be stored below {backup_directory}") from error
    if candidate.suffix != ".sqlite3":
        raise ValueError("Database backup file must use the .sqlite3 suffix")
    if candidate.exists() or backup_manifest_path(candidate).exists():
        raise ValueError(f"Database backup path already exists: {candidate}")
    return candidate


def backup_manifest_path(backup_path: Path) -> Path:
    return backup_path.with_suffix(backup_path.suffix + ".manifest.json")


def _write_private_text(path: Path, content: str) -> None:
    temporary_path = path.with_name(f".{path.name}.{sha256(os.urandom(16))[:12]}.tmp")
    temporary_path.write_text(content, encoding="utf-8")
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, path)
    os.chmod(path, 0o600)


def _verify_sqlite_file(path: Path) -> int:
    if not path.is_file():
        raise ValueError(f"SQLite file does not exist: {path}")
    verification = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        if verification.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("SQLite backup integrity_check did not return ok")
        return int(verification.execute("PRAGMA user_version").fetchone()[0])
    finally:
        verification.close()


def create_database_backup(
    connection: sqlite3.Connection,
    *,
    output_path: Path | None = None,
    notes: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """Create, hash, verify, and register a private SQLite backup plus sidecar manifest."""
    created_at = utc_offset_timestamp(now or local_timestamp())
    source_path = connection_database_path(connection)
    destination = managed_database_backup_path(source_path, output_path)
    temporary_destination = destination.with_name(f".{destination.name}.{sha256(os.urandom(16))[:12]}.tmp")
    connection.commit()
    copied = sqlite3.connect(temporary_destination)
    try:
        connection.backup(copied)
    finally:
        copied.close()
    os.chmod(temporary_destination, 0o600)
    schema_version = _verify_sqlite_file(temporary_destination)
    if schema_version != SCHEMA_VERSION:
        temporary_destination.unlink(missing_ok=True)
        raise ValueError(f"Backup schema version {schema_version} is not supported")
    os.replace(temporary_destination, destination)
    os.chmod(destination, 0o600)
    file_hash = sha256(destination.read_bytes())
    relative_path = str(destination.relative_to(source_path.parent))
    manifest_path = backup_manifest_path(destination)
    manifest_relative_path = str(manifest_path.relative_to(source_path.parent))
    backup_key = f"backup:{sha256(os.urandom(16))[:24]}"
    manifest = {
        "backup_key": backup_key,
        "created_at": created_at,
        "relative_path": relative_path,
        "schema_version": schema_version,
        "sha256": file_hash,
        "size_bytes": destination.stat().st_size,
    }
    _write_private_text(
        manifest_path,
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )
    connection.execute(
        """
        INSERT INTO database_backups(
            backup_key, relative_path, manifest_relative_path, size_bytes, sha256,
            schema_version, status, created_at, verified_at, notes
        ) VALUES (?, ?, ?, ?, ?, ?, 'verified', ?, ?, ?)
        """,
        (
            backup_key,
            relative_path,
            manifest_relative_path,
            destination.stat().st_size,
            file_hash,
            schema_version,
            created_at,
            created_at,
            notes,
        ),
    )
    connection.commit()
    return {**manifest, "path": destination, "manifest_path": manifest_path}


def load_database_backup_manifest(database_path: Path, backup_path: Path) -> tuple[Path, dict[str, Any]]:
    source_path = database_path.resolve()
    backup_directory = database_backup_directory(source_path).resolve()
    resolved_backup = backup_path.expanduser().resolve()
    try:
        resolved_backup.relative_to(backup_directory)
    except ValueError as error:
        raise ValueError(f"Database backup must be below {backup_directory}") from error
    manifest_file = backup_manifest_path(resolved_backup)
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Database backup manifest is unavailable or invalid") from error
    if not isinstance(manifest, dict):
        raise ValueError("Database backup manifest must be a JSON object")
    required = {"backup_key", "created_at", "relative_path", "schema_version", "sha256", "size_bytes"}
    if not required.issubset(manifest):
        raise ValueError("Database backup manifest is incomplete")
    expected_relative = str(resolved_backup.relative_to(source_path.parent))
    if manifest["relative_path"] != expected_relative:
        raise ValueError("Database backup manifest does not match the selected file")
    if sha256(resolved_backup.read_bytes()) != manifest["sha256"]:
        raise ValueError("Database backup SHA-256 does not match its manifest")
    if resolved_backup.stat().st_size != manifest["size_bytes"]:
        raise ValueError("Database backup size does not match its manifest")
    if _verify_sqlite_file(resolved_backup) != SCHEMA_VERSION:
        raise ValueError("Database backup schema version is not supported")
    return resolved_backup, manifest


def restore_database_backup(database_path: Path, backup_path: Path) -> dict[str, Any]:
    """Atomically replace a database only after the sidecar-verified backup passes checks."""
    destination = database_path.resolve()
    verified_backup, manifest = load_database_backup_manifest(destination, backup_path)
    temporary_destination = destination.with_name(f".{destination.name}.{sha256(os.urandom(16))[:12]}.restore")
    source = sqlite3.connect(f"file:{verified_backup}?mode=ro", uri=True)
    restored = sqlite3.connect(temporary_destination)
    try:
        source.backup(restored)
    finally:
        restored.close()
        source.close()
    os.chmod(temporary_destination, 0o600)
    if _verify_sqlite_file(temporary_destination) != SCHEMA_VERSION:
        temporary_destination.unlink(missing_ok=True)
        raise ValueError("Restored database verification failed")
    os.replace(temporary_destination, destination)
    os.chmod(destination, 0o600)
    return {**manifest, "path": verified_backup, "restored_to": destination}


def link_catalog_device(
    connection: sqlite3.Connection,
    *,
    project_id: int,
    device_key: str,
    name: str,
    device_kind: str,
    role: str,
    manufacturer: str | None,
    model: str | None,
    serial_number: str | None,
    interface: str | None,
    ownership_status: str,
    legacy_reader_id: int | None,
    legacy_element_id: int | None,
    notes: str | None,
    now: str,
) -> int:
    type_key = get_device_type(connection, DEFAULT_DEVICE_TYPES[device_kind], device_kind)
    connection.execute(
        """
        INSERT INTO devices(
            device_key, name, device_kind, role, manufacturer, model, serial_number,
            interface, ownership_status, lifecycle_status, sensitivity, device_type_key,
            legacy_reader_id, legacy_element_id, metadata_json, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 'sensitive', ?, ?, ?, '{}', ?, ?, ?)
        ON CONFLICT(device_key) DO UPDATE SET
            name=excluded.name,
            device_kind=excluded.device_kind,
            role=excluded.role,
            manufacturer=excluded.manufacturer,
            model=excluded.model,
            serial_number=excluded.serial_number,
            interface=excluded.interface,
            ownership_status=excluded.ownership_status,
            device_type_key=excluded.device_type_key,
            legacy_reader_id=excluded.legacy_reader_id,
            legacy_element_id=excluded.legacy_element_id,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        (
            catalog_key(device_key),
            name,
            device_kind,
            role,
            manufacturer,
            model,
            serial_number,
            interface,
            ownership_status,
            type_key,
            legacy_reader_id,
            legacy_element_id,
            notes,
            now,
            now,
        ),
    )
    device_id = get_device_id(connection, device_key)
    connection.execute(
        """
        INSERT INTO project_devices(
            project_id, device_id, role_in_project, scope, status, added_at, updated_at
        ) VALUES (?, ?, ?, ?, 'pending_authorization', ?, ?)
        ON CONFLICT(project_id, device_id) DO UPDATE SET
            role_in_project=excluded.role_in_project,
            scope=excluded.scope,
            updated_at=excluded.updated_at
        """,
        (
            project_id,
            device_id,
            role,
            "Authorized RFID learning and home work; exact operations are stored in access_authorizations",
            now,
            now,
        ),
    )
    return device_id


def synchronize_legacy_devices(
    connection: sqlite3.Connection,
    *,
    project_id: int,
    now: str,
) -> None:
    for reader in connection.execute("SELECT * FROM readers ORDER BY id").fetchall():
        stable_part = reader["usb_serial"] or str(reader["id"])
        device_key = f"reader:{stable_part.lower()}"
        device_id = link_catalog_device(
            connection,
            project_id=project_id,
            device_key=device_key,
            name=reader["name"],
            device_kind="rfid_reader",
            role="tool",
            manufacturer="proxmark.org",
            model=reader["hardware_model"],
            serial_number=reader["usb_serial"],
            interface=reader["connection"],
            ownership_status="user_authorized",
            legacy_reader_id=int(reader["id"]),
            legacy_element_id=None,
            notes="Imported from the legacy readers table.",
            now=now,
        )
        connection.execute(
            """
            INSERT INTO access_methods(
                project_id, device_id, method_key, method_type, endpoint,
                authentication_type, status, notes, created_at, updated_at
            ) VALUES (?, ?, 'usb', 'usb_serial', ?, 'operating_system_device_permissions',
                      'active', 'No password is stored in SQLite.', ?, ?)
            ON CONFLICT(project_id, device_id, method_key) DO UPDATE SET
                endpoint=excluded.endpoint,
                authentication_type=excluded.authentication_type,
                status=excluded.status,
                notes=excluded.notes,
                updated_at=excluded.updated_at
            """,
            (project_id, device_id, reader["device_path"], now, now),
        )

    element_kind_map = {
        "card": "rfid_card",
        "tag": "rfid_tag",
        "key_fob": "rfid_key_fob",
    }
    for element in connection.execute("SELECT * FROM elements ORDER BY id").fetchall():
        device_key = f"element:{element['id']}"
        ownership = (
            "user_owned"
            if element["ownership"] == "user_confirmed_private_property"
            else "user_authorized"
        )
        link_catalog_device(
            connection,
            project_id=project_id,
            device_key=device_key,
            name=element["label"],
            device_kind=element_kind_map.get(element["element_kind"], "rfid_tag"),
            role="credential",
            manufacturer=element["chip_vendor"],
            model=element["chip_model"],
            serial_number=None,
            interface=element["standard"],
            ownership_status=ownership,
            legacy_reader_id=None,
            legacy_element_id=int(element["id"]),
            notes="Imported from the legacy elements table. UID remains in the protected legacy record.",
            now=now,
        )
    synchronize_rfid_profiles(connection, now=now)


def synchronize_rfid_profiles(connection: sqlite3.Connection, *, now: str) -> None:
    """Link protected legacy RFID records to the current device catalog."""
    for row in connection.execute(
        """
        SELECT d.device_key, e.*
        FROM devices AS d
        JOIN elements AS e ON e.id = d.legacy_element_id
        ORDER BY e.id
        """
    ).fetchall():
        identifier_id = add_device_identifier(
            connection,
            device_key=row["device_key"],
            identifier_kind="rfid.uid",
            identifier_value=row["uid_hex"],
            identifier_scope=row["technology"],
            classification="sensitive",
            source_reference="rfid:elements",
            observed_at=row["updated_at"],
            notes="Protected RFID UID imported from the element record.",
            now=now,
        )
        profile_kind = {"card": "card", "key_fob": "key_fob"}.get(row["element_kind"], "tag")
        set_rfid_profile(
            connection,
            device_key=row["device_key"],
            profile_kind=profile_kind,
            frequency_mhz=row["frequency_mhz"],
            standard=row["standard"],
            technology=row["technology"],
            product_family=row["product_family"],
            chip_vendor=row["chip_vendor"],
            chip_model=row["chip_model"],
            uid_identifier_id=identifier_id,
            legacy_element_id=int(row["id"]),
            source_reference="rfid:elements",
            observed_at=row["updated_at"],
            notes="Linked to protected RFID element data.",
            now=now,
        )
    for row in connection.execute(
        """
        SELECT d.device_key, r.*
        FROM devices AS d
        JOIN readers AS r ON r.id = d.legacy_reader_id
        ORDER BY r.id
        """
    ).fetchall():
        set_rfid_profile(
            connection,
            device_key=row["device_key"],
            profile_kind="reader",
            chip_vendor="proxmark.org",
            chip_model=row["hardware_model"],
            legacy_reader_id=int(row["id"]),
            technical_json=row["metadata_json"],
            source_reference="rfid:readers",
            observed_at=row["updated_at"],
            notes="Linked to protected RFID reader data.",
            now=now,
        )


def synchronize_clone_profiles(connection: sqlite3.Connection, *, now: str) -> None:
    """Give each verified RFID clone its own profile and protected UID identifier."""
    for row in connection.execute(
        """
        SELECT target.device_key, c.uid_after_hex, e.element_kind, e.frequency_mhz, e.standard,
               e.technology, e.product_family, e.chip_vendor, e.chip_model, c.executed_at
        FROM clone_operations AS c
        JOIN devices AS target ON target.id = c.target_device_id
        JOIN reads AS source_read ON source_read.id = c.source_read_id
        JOIN elements AS e ON e.id = source_read.element_id
        WHERE c.status = 'verified' AND c.byte_identical = 1
        ORDER BY c.id
        """
    ).fetchall():
        identifier_id = add_device_identifier(
            connection,
            device_key=row["device_key"],
            identifier_kind="rfid.uid",
            identifier_value=row["uid_after_hex"],
            identifier_scope=row["technology"],
            classification="sensitive",
            source_reference="rfid:clone-operation",
            observed_at=row["executed_at"],
            notes="Protected RFID UID verified during a clone operation.",
            now=now,
        )
        profile_kind = {"card": "card", "key_fob": "key_fob"}.get(row["element_kind"], "tag")
        set_rfid_profile(
            connection,
            device_key=row["device_key"],
            profile_kind=profile_kind,
            frequency_mhz=row["frequency_mhz"],
            standard=row["standard"],
            technology=row["technology"],
            product_family=row["product_family"],
            chip_vendor=row["chip_vendor"],
            chip_model=row["chip_model"],
            uid_identifier_id=identifier_id,
            source_reference="rfid:clone-operation",
            observed_at=row["executed_at"],
            notes="RFID profile verified from the source read and clone verification.",
            now=now,
        )


def managed_script_path(script_path: Path) -> tuple[Path, str]:
    """Return one executable script path that is inside an approved local module."""
    try:
        resolved_path = script_path.expanduser().resolve(strict=True)
    except OSError as error:
        raise ValueError("Managed script path does not exist") from error
    if not resolved_path.is_file():
        raise ValueError("Managed script path must be a regular file")
    if not os.access(resolved_path, os.X_OK):
        raise ValueError("Managed script path must be executable")
    for allowed_root in MANAGED_SCRIPT_ROOTS:
        try:
            resolved_path.relative_to(allowed_root)
        except ValueError:
            continue
        return resolved_path, os.path.relpath(resolved_path, ROOT)
    raise ValueError("Managed script path is outside the approved device modules")


def require_managed_script_guard(script_path: Path) -> None:
    """Require each registered script to reject normal direct execution."""
    try:
        source = script_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Managed device script must be UTF-8 text") from error
    except OSError as error:
        raise ValueError("Managed device script source is unavailable") from error
    if not MANAGED_SCRIPT_GUARD_RE.search(source):
        raise ValueError(
            "Managed device script must use an if guard for DEVICE_CLI_CONTEXT and DEVICE_CLI_SCRIPT_KEY"
        )


def managed_script_sha256(script_path: Path) -> str:
    """Return the reviewed file hash after the direct-execution guard is checked."""
    require_managed_script_guard(script_path)
    return sha256(script_path.read_bytes())


def registered_managed_script_path(relative_path: str) -> Path:
    """Resolve a stored script path and reject a changed or escaped path."""
    resolved_path, normalized_path = managed_script_path(ROOT / relative_path)
    if normalized_path != relative_path:
        raise ValueError("Registered managed script path is not normalized")
    require_managed_script_guard(resolved_path)
    return resolved_path


def add_device_script(
    connection: sqlite3.Connection,
    *,
    script_key: str,
    device_key: str,
    display_name: str,
    description: str,
    script_path: Path,
    required_operation: str,
    risk_level: str,
    timeout_seconds: int,
    interactive: bool,
    now: str | None = None,
) -> int:
    """Register one reviewed, executable device script for CLI-only execution."""
    if required_operation not in FULL_AUTHORIZED_OPERATIONS:
        raise ValueError("Managed script operation is not supported")
    if risk_level not in {"read_only", "state_change", "destructive"}:
        raise ValueError("Managed script risk level is not supported")
    if not 1 <= timeout_seconds <= 3600:
        raise ValueError("Managed script timeout must be between 1 and 3600 seconds")
    if not display_name.strip() or not description.strip():
        raise ValueError("Managed script name and description are required")
    now = utc_offset_timestamp(now or local_timestamp())
    resolved_path, relative_path = managed_script_path(script_path)
    script_hash = managed_script_sha256(resolved_path)
    device_id = get_device_id(connection, device_key)
    normalized_key = catalog_key(script_key)
    connection.execute(
        """
        INSERT INTO device_scripts(
            script_key, device_id, display_name, description, relative_path,
            required_operation, risk_level, timeout_seconds, enabled, interactive,
            script_sha256, script_revision, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1, ?, ?)
        ON CONFLICT(script_key) DO UPDATE SET
            device_id=excluded.device_id,
            display_name=excluded.display_name,
            description=excluded.description,
            relative_path=excluded.relative_path,
            required_operation=excluded.required_operation,
            risk_level=excluded.risk_level,
            timeout_seconds=excluded.timeout_seconds,
            enabled=1,
            interactive=excluded.interactive,
            script_sha256=excluded.script_sha256,
            script_revision=CASE
                WHEN device_scripts.script_sha256 <> excluded.script_sha256
                THEN device_scripts.script_revision + 1
                ELSE device_scripts.script_revision
            END,
            updated_at=excluded.updated_at
        """,
        (
            normalized_key,
            device_id,
            display_name.strip(),
            description.strip(),
            relative_path,
            required_operation,
            risk_level,
            timeout_seconds,
            int(interactive),
            script_hash,
            now,
            now,
        ),
    )
    script_id = int(
        connection.execute("SELECT id FROM device_scripts WHERE script_key = ?", (normalized_key,)).fetchone()[0]
    )
    connection.commit()
    return script_id


def list_device_scripts(connection: sqlite3.Connection, device_key: str) -> list[sqlite3.Row]:
    device_id = get_device_id(connection, device_key)
    return connection.execute(
        """
        SELECT script_key, display_name, description, relative_path,
               required_operation, risk_level, timeout_seconds, interactive,
               script_sha256, script_revision
        FROM device_scripts
        WHERE device_id = ? AND enabled = 1
        ORDER BY script_key
        """,
        (device_id,),
    ).fetchall()


def _record_managed_script_run(
    connection: sqlite3.Connection,
    *,
    project_id: int,
    device_id: int,
    script_key: str,
    required_operation: str,
    script_path: Path | None,
    started_at: str,
    completed_at: str,
    duration_ms: int,
    status_value: str,
    exit_code: int | None,
    error_message: str | None,
    executed_script_sha256: str | None,
) -> str:
    """Store metadata only. Script output can contain sensitive device data."""
    run_key = f"script:{sha256(os.urandom(16))[:24]}"
    empty_output = b""
    connection.execute(
        """
        INSERT INTO device_command_runs(
            run_key, project_id, device_id, command_id, command_text,
            required_operation, client_path, endpoint, started_at, completed_at,
            duration_ms, status, exit_code, stdout_sha256, stderr_sha256,
            stdout_content, stderr_content, executed_script_sha256, error_message, created_at
        ) VALUES (?, ?, ?, NULL, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_key,
            project_id,
            device_id,
            f"managed-script {script_key}",
            required_operation,
            str(script_path) if script_path is not None else None,
            started_at,
            completed_at,
            duration_ms,
            status_value,
            exit_code,
            sha256(empty_output),
            sha256(empty_output),
            empty_output,
            empty_output,
            executed_script_sha256,
            error_message,
            completed_at,
        ),
    )
    connection.commit()
    return run_key


def _managed_script_access_problem(
    connection: sqlite3.Connection,
    *,
    project_key: str,
    device_key: str,
    project_id: int,
    device_id: int,
    required_operation: str,
) -> str | None:
    mapping = connection.execute(
        "SELECT 1 FROM project_devices WHERE project_id = ? AND device_id = ?",
        (project_id, device_id),
    ).fetchone()
    if mapping is None:
        return "Registered device is not assigned to the selected project."
    rows = connection.execute(
        """
        SELECT allowed_operations_json
        FROM active_authorized_devices
        WHERE project_key = ? AND device_key = ?
        """,
        (project_key, device_key),
    ).fetchall()
    if not rows:
        return "No active authorization exists for the selected project and device."
    allowed_operations = {
        operation
        for row in rows
        for operation in json.loads(row["allowed_operations_json"])
    }
    if required_operation not in allowed_operations:
        return f"Authorization does not allow operation {required_operation!r}."
    return None


def run_device_script(
    connection: sqlite3.Connection,
    *,
    script_key: str,
    project_key: str,
    device_key: str,
) -> dict[str, Any]:
    """Run one registered script through the audited device CLI path."""
    normalized_script_key = catalog_key(script_key)
    normalized_project_key = catalog_key(project_key)
    normalized_device_key = catalog_key(device_key)
    script = connection.execute(
        "SELECT * FROM device_scripts WHERE script_key = ? AND enabled = 1",
        (normalized_script_key,),
    ).fetchone()
    if script is None:
        raise ValueError(f"Managed device script {script_key!r} does not exist or is disabled")
    script_device = connection.execute(
        "SELECT device_key FROM devices WHERE id = ?", (script["device_id"],)
    ).fetchone()
    if script_device is None or script_device["device_key"] != normalized_device_key:
        raise ValueError("Managed device script does not belong to the selected device")

    project_id = get_project_id(connection, normalized_project_key)
    device_id = get_device_id(connection, normalized_device_key)
    required_operation = str(script["required_operation"])
    started_at = local_timestamp()
    start = time.monotonic()
    try:
        script_path = registered_managed_script_path(str(script["relative_path"]))
    except ValueError:
        completed_at = local_timestamp()
        run_key = _record_managed_script_run(
            connection,
            project_id=project_id,
            device_id=device_id,
            script_key=normalized_script_key,
            required_operation=required_operation,
            script_path=None,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=max(0, int((time.monotonic() - start) * 1000)),
            status_value="failed",
            exit_code=None,
            error_message="Registered managed script path is unavailable.",
            executed_script_sha256=None,
        )
        return {"run_key": run_key, "status": "failed", "exit_code": None, "error_message": "Registered managed script path is unavailable."}

    actual_script_hash = managed_script_sha256(script_path)
    if actual_script_hash != script["script_sha256"]:
        completed_at = local_timestamp()
        error_message = (
            "Managed script content changed after review. Re-register it with device-script-add before execution."
        )
        run_key = _record_managed_script_run(
            connection,
            project_id=project_id,
            device_id=device_id,
            script_key=normalized_script_key,
            required_operation=required_operation,
            script_path=script_path,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=max(0, int((time.monotonic() - start) * 1000)),
            status_value="blocked",
            exit_code=None,
            error_message=error_message,
            executed_script_sha256=actual_script_hash,
        )
        return {"run_key": run_key, "status": "blocked", "exit_code": None, "error_message": error_message}

    access_problem = _managed_script_access_problem(
        connection,
        project_key=normalized_project_key,
        device_key=normalized_device_key,
        project_id=project_id,
        device_id=device_id,
        required_operation=required_operation,
    )
    if access_problem is not None:
        completed_at = local_timestamp()
        run_key = _record_managed_script_run(
            connection,
            project_id=project_id,
            device_id=device_id,
            script_key=normalized_script_key,
            required_operation=required_operation,
            script_path=script_path,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=max(0, int((time.monotonic() - start) * 1000)),
            status_value="blocked",
            exit_code=None,
            error_message=access_problem,
            executed_script_sha256=actual_script_hash,
        )
        return {"run_key": run_key, "status": "blocked", "exit_code": None, "error_message": access_problem}

    environment = os.environ.copy()
    environment["DEVICE_CLI_CONTEXT"] = "1"
    environment["DEVICE_CLI_SCRIPT_KEY"] = normalized_script_key
    interface = connection.execute(
        """
        SELECT endpoint, address
        FROM device_interfaces
        WHERE device_id = ? AND status = 'active'
        ORDER BY CASE WHEN interface_type = 'ssh' THEN 0 ELSE 1 END, id
        LIMIT 1
        """,
        (device_id,),
    ).fetchone()
    if interface is not None:
        if interface["endpoint"]:
            environment["DEVICE_CLI_DEVICE_ENDPOINT"] = str(interface["endpoint"])
        if interface["address"]:
            environment["DEVICE_CLI_DEVICE_ADDRESS"] = str(interface["address"])
    # Older Raspberry scripts use RASPBERRY_HOST. Use the verified active
    # inventory address when mDNS is not available on the control computer.
    if normalized_device_key == "computer:raspberry-pi-3" and "RASPBERRY_HOST" not in environment:
        raspberry_address = environment.get("DEVICE_CLI_DEVICE_ADDRESS")
        if raspberry_address:
            environment["RASPBERRY_HOST"] = raspberry_address
    process: subprocess.Popen[bytes] | None = None
    timeout_seconds = int(script["timeout_seconds"])
    try:
        process = subprocess.Popen(
            [str(script_path)],
            cwd=script_path.parent,
            env=environment,
            start_new_session=True,
        )
        exit_code = process.wait(timeout=timeout_seconds)
        status_value = "succeeded" if exit_code == 0 else "failed"
        error_message = None if exit_code == 0 else f"Registered script exited with code {exit_code}."
    except subprocess.TimeoutExpired:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
        exit_code = None
        status_value = "timed_out"
        error_message = f"Registered script exceeded timeout of {timeout_seconds} seconds."
    except OSError:
        exit_code = None
        status_value = "failed"
        error_message = "Registered script could not start."
    completed_at = local_timestamp()
    run_key = _record_managed_script_run(
        connection,
        project_id=project_id,
        device_id=device_id,
        script_key=normalized_script_key,
        required_operation=required_operation,
        script_path=script_path,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=max(0, int((time.monotonic() - start) * 1000)),
        status_value=status_value,
        exit_code=exit_code,
        error_message=error_message,
        executed_script_sha256=actual_script_hash,
    )
    return {"run_key": run_key, "status": status_value, "exit_code": exit_code, "error_message": error_message}


def bootstrap_raspberry_scripts(connection: sqlite3.Connection, *, now: str) -> None:
    """Register the private Raspberry action only when its local script exists."""
    if connection.execute(
        "SELECT 1 FROM device_scripts WHERE script_key = 'raspberry.credentials.sync'"
    ).fetchone() is not None:
        return
    script_path = ROOT.parent / "Raspberry" / "save-raspberry-passwords.sh"
    if not script_path.is_file():
        return
    add_device_script(
        connection,
        script_key="raspberry.credentials.sync",
        device_key="computer:raspberry-pi-3",
        display_name="Synchronize Raspberry credential inventory",
        description=(
            "Read protected Raspberry configuration into the local root-only credential inventory. "
            "The CLI never stores this script output in SQLite."
        ),
        script_path=script_path,
        required_operation="administer",
        risk_level="destructive",
        timeout_seconds=180,
        interactive=True,
        now=now,
    )


def bootstrap_raspberry_pi(connection: sqlite3.Connection, *, now: str) -> None:
    """Register public example Raspberry Pi facts without treating them as live probes."""
    create_project(
        connection,
        project_key=HOME_PROJECT_KEY,
        name="Home Infrastructure",
        description="Local inventory and audit for authorized home computers, sensors, and network equipment.",
        purpose="home",
        owner_subject="project_owner",
        authorization_policy=(
            "Deny by default. Device communication requires an active project assignment and "
            "a valid per-device authorization."
        ),
        scope_notes="Documented local home infrastructure. Confirm each device authorization before contact.",
        now=now,
    )
    device_key = "computer:raspberry-pi-3"
    try:
        get_device_id(connection, device_key)
    except ValueError:
        pass
    else:
        bootstrap_raspberry_scripts(connection, now=now)
        return
    add_device(
        connection,
        project_key=HOME_PROJECT_KEY,
        device_key=device_key,
        name="Example Raspberry Pi 3 host",
        device_kind="computer",
        device_type_key="computing.raspberry_pi_3",
        role="support",
        ownership_status="household_owned",
        manufacturer="Raspberry Pi Foundation",
        model="Raspberry Pi 3 Model B Rev 1.2",
        location_label="Example private network",
        sensitivity="sensitive",
        scope="Example host. Explicit per-device authorization is required before remote contact.",
        now=now,
    )
    source = "public-example-configuration"
    add_device_identifier(
        connection,
        device_key=device_key,
        identifier_kind="ssh.host_key_ed25519",
        identifier_value="SHA256:example-host-key-not-a-real-fingerprint",
        classification="sensitive",
        source_reference=source,
        observed_at=now,
        notes="Example host-key fingerprint. Replace it before SSH use.",
        now=now,
    )
    set_device_interface(
        connection,
        device_key=device_key,
        interface_key="ssh.wifi",
        interface_type="ssh",
        endpoint="raspberry.example.invalid:22",
        address="192.0.2.82",
        authentication_type="ssh_public_key",
        source_reference=source,
        details_json='{"network":"wifi"}',
        observed_at=now,
        notes="Example Wi-Fi SSH path. It is not a live reachability result.",
        now=now,
    )
    set_device_interface(
        connection,
        device_key=device_key,
        interface_key="ethernet.direct",
        interface_type="ethernet",
        address="198.51.100.31",
        status="historical",
        source_reference=source,
        details_json='{"network":"direct_ethernet"}',
        observed_at=now,
        notes="Example direct Ethernet address.",
        now=now,
    )
    set_access_method(
        connection,
        project_key=HOME_PROJECT_KEY,
        device_key=device_key,
        method_key="ssh",
        method_type="ssh",
        endpoint="raspberry.example.invalid:22",
        account_label="inventory-user",
        authentication_type="ssh_public_key",
        source_reference=source,
        notes="Example public-key SSH method. SQLite stores no password or private key.",
        now=now,
    )
    set_device_information(
        connection,
        device_key=device_key,
        information_kind="configuration",
        property_key="ssh_hardening",
        value_json='{"password_login":false,"root_login":false,"max_auth_tries":3}',
        source_reference=source,
        confidence="reported",
        classification="sensitive",
        observed_at=now,
        notes="Documented SSH hardening state; verify again after a configuration change.",
        now=now,
    )
    for key, name, port in (
        ("service.example-dns", "Example DNS service", 53),
        ("service.example-monitor", "Example monitor", 3001),
    ):
        set_device_component(
            connection,
            device_key=device_key,
            component_key=key,
            component_kind="service",
            name=name,
            source_reference=source,
            details_json=json.dumps({"documented_port": port}),
            observed_at=now,
            notes="Example service configuration. It is not a live service check.",
            now=now,
        )
    bootstrap_raspberry_scripts(connection, now=now)


def bootstrap_catalog(connection: sqlite3.Connection) -> None:
    now = local_timestamp()
    project_id = create_project(
        connection,
        project_key=DEFAULT_PROJECT_KEY,
        name="RFID Home Lab",
        description="Local inventory and audit vault for authorized RFID learning and home work.",
        purpose="education_and_home",
        owner_subject="project_owner",
        authorization_policy=(
            "Deny by default. Work is allowed only when the project, device assignment, "
            "device, and per-device authorization are active. Ask the owner when scope is unclear."
        ),
        scope_notes=(
            "The owner states full authorization for registered devices. The work is limited "
            "to education, professional learning, and the owner's home environment."
        ),
        now=now,
    )
    synchronize_legacy_devices(
        connection,
        project_id=project_id,
        now=now,
    )
    synchronize_clone_profiles(connection, now=now)
    bootstrap_raspberry_pi(connection, now=now)
    rfid_device.seed_builtin_commands(connection, now)


def require_schema(connection: sqlite3.Connection) -> None:
    try:
        row = connection.execute(
            "SELECT value FROM schema_info WHERE key = 'schema_version'"
        ).fetchone()
    except sqlite3.OperationalError as error:
        raise ValueError("Database is not initialized") from error
    if row is None or row[0] != str(SCHEMA_VERSION):
        raise ValueError("Database schema version is not supported")


def printable(data: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data)


def validate_mfc_files(dump_path: Path, json_path: Path, key_path: Path) -> dict[str, Any]:
    dump = dump_path.read_bytes()
    document = json.loads(json_path.read_text(encoding="utf-8"))
    keys = key_path.read_bytes()

    if len(dump) != 1024:
        raise ValueError(f"A MIFARE Classic 1K dump must have 1024 bytes, got {len(dump)}")
    if len(keys) != 192:
        raise ValueError(f"A 1K Proxmark key file must have 192 bytes, got {len(keys)}")
    if document.get("FileType") != "mfc v2":
        raise ValueError("Unsupported Proxmark JSON format")

    blocks = document.get("blocks", {})
    if set(blocks) != {str(index) for index in range(64)}:
        raise ValueError("JSON must contain exactly blocks 0 through 63")
    for block_number in range(64):
        documented = bytes.fromhex(normalize_hex(blocks[str(block_number)], 16))
        actual = dump[block_number * 16 : (block_number + 1) * 16]
        if documented != actual:
            raise ValueError(f"JSON and binary dump differ at block {block_number}")

    card = document.get("Card", {})
    uid = bytes.fromhex(normalize_hex(card["UID"]))
    if dump[: len(uid)] != uid:
        raise ValueError("UID in JSON does not match manufacturer block")
    if len(uid) == 4 and dump[4] != uid[0] ^ uid[1] ^ uid[2] ^ uid[3]:
        raise ValueError("Manufacturer block has an invalid UID BCC")

    sector_keys = document.get("SectorKeys", {})
    if set(sector_keys) != {str(index) for index in range(16)}:
        raise ValueError("JSON must contain exactly sectors 0 through 15")
    for sector in range(16):
        trailer = dump[(sector * 4 + 3) * 16 : (sector * 4 + 4) * 16]
        entry = sector_keys[str(sector)]
        key_a = bytes.fromhex(normalize_hex(entry["KeyA"], 6))
        key_b = bytes.fromhex(normalize_hex(entry["KeyB"], 6))
        access = bytes.fromhex(normalize_hex(entry["AccessConditions"], 4))
        if trailer[:6] != key_a or trailer[6:10] != access or trailer[10:] != key_b:
            raise ValueError(f"Sector metadata and trailer differ in sector {sector}")
        if keys[sector * 6 : sector * 6 + 6] != key_a:
            raise ValueError(f"Key file and JSON Key A differ in sector {sector}")
        key_b_offset = 16 * 6 + sector * 6
        if keys[key_b_offset : key_b_offset + 6] != key_b:
            raise ValueError(f"Key file and JSON Key B differ in sector {sector}")

    return {"dump": dump, "document": document, "keys": keys, "uid": uid}


def validate_dump_pair(dump_path: Path, json_path: Path) -> dict[str, Any]:
    dump = dump_path.read_bytes()
    document = json.loads(json_path.read_text(encoding="utf-8"))
    if len(dump) != 1024:
        raise ValueError(f"A MIFARE Classic 1K dump must have 1024 bytes, got {len(dump)}")
    if document.get("FileType") != "mfc v2":
        raise ValueError("Unsupported Proxmark JSON format")
    blocks = document.get("blocks", {})
    if set(blocks) != {str(index) for index in range(64)}:
        raise ValueError("JSON must contain exactly blocks 0 through 63")
    for block_number in range(64):
        documented = bytes.fromhex(normalize_hex(blocks[str(block_number)], 16))
        actual = dump[block_number * 16 : (block_number + 1) * 16]
        if documented != actual:
            raise ValueError(f"JSON and binary dump differ at block {block_number}")
    uid = bytes.fromhex(normalize_hex(document["Card"]["UID"]))
    if dump[: len(uid)] != uid:
        raise ValueError("UID in JSON does not match manufacturer block")
    if len(uid) == 4 and dump[4] != uid[0] ^ uid[1] ^ uid[2] ^ uid[3]:
        raise ValueError("Manufacturer block has an invalid UID BCC")
    return {"dump": dump, "document": document, "uid": uid}


def upsert_reader(connection: sqlite3.Connection, now: str) -> int:
    values = {
        "name": "Example Proxmark3 reader",
        "device_path": "/dev/ttyACM0",
        "connection": "USB-CDC",
        "usb_vendor_id": "9AC4",
        "usb_product_id": "4B8F",
        "usb_serial": "example-proxmark3-reader",
        "kernel_driver": "cdc_acm",
        "client_name": "RRG Proxmark3",
        "client_version": "v4.20728",
        "firmware_bootrom": "not_recorded",
        "firmware_os": "not_recorded",
        "fpga_hf": "not_recorded",
        "hardware_model": "Example reader configuration. Run pm3-probe to record current values.",
        "mcu": "not_recorded",
        "metadata_json": json.dumps(
            {
                "usb_manufacturer": "proxmark.org",
                "external_flash": True,
                "smartcard_reader": False,
                "firmware_changed_during_read": False,
            },
            sort_keys=True,
        ),
        "created_at": now,
        "updated_at": now,
    }
    connection.execute(
        """
        INSERT INTO readers(
            name, device_path, connection, usb_vendor_id, usb_product_id, usb_serial,
            kernel_driver, client_name, client_version, firmware_bootrom, firmware_os,
            fpga_hf, hardware_model, mcu, metadata_json, created_at, updated_at
        ) VALUES (
            :name, :device_path, :connection, :usb_vendor_id, :usb_product_id, :usb_serial,
            :kernel_driver, :client_name, :client_version, :firmware_bootrom, :firmware_os,
            :fpga_hf, :hardware_model, :mcu, :metadata_json, :created_at, :updated_at
        )
        ON CONFLICT(usb_serial) DO UPDATE SET
            name=excluded.name,
            device_path=excluded.device_path,
            connection=excluded.connection,
            client_version=excluded.client_version,
            firmware_bootrom=excluded.firmware_bootrom,
            firmware_os=excluded.firmware_os,
            fpga_hf=excluded.fpga_hf,
            hardware_model=excluded.hardware_model,
            mcu=excluded.mcu,
            metadata_json=excluded.metadata_json,
            updated_at=excluded.updated_at
        """,
        values,
    )
    return int(
        connection.execute("SELECT id FROM readers WHERE usb_serial = ?", (values["usb_serial"],)).fetchone()[0]
    )


def upsert_element(
    connection: sqlite3.Connection,
    document: dict[str, Any],
    dump: bytes,
    uid: bytes,
    label: str,
    now: str,
) -> int:
    card = document["Card"]
    atqa_storage = bytes.fromhex(normalize_hex(card["ATQA"], 2))
    values = {
        "label": label,
        "element_kind": "key_fob",
        "ownership": "user_confirmed_private_property",
        "authorized_use": "Private home door access",
        "frequency_mhz": 13.56,
        "standard": "ISO/IEC 14443-A",
        "technology": "MIFARE Classic",
        "product_family": "MIFARE Classic 1K compatible",
        "chip_vendor": "Fudan Microelectronics",
        "chip_model": "FM11RF08",
        "uid_hex": uid.hex().upper(),
        "uid_bytes": uid,
        "uid_length": len(uid),
        "uid_observation": "ONUID, re-used",
        "atqa_hex": atqa_storage[::-1].hex().upper(),
        "sak_hex": normalize_hex(card["SAK"], 1),
        "capacity_bytes": 1024,
        "sector_count": 16,
        "block_count": 64,
        "block_size": 16,
        "prng": "weak",
        "magic_uid_writable": 0,
        "manufacturer_block_hex": dump[:16].hex().upper(),
        "notes": "Original key fob. Read-only acquisition. No tag data was changed.",
        "created_at": now,
        "updated_at": now,
    }
    connection.execute(
        """
        INSERT INTO elements(
            label, element_kind, ownership, authorized_use, frequency_mhz, standard,
            technology, product_family, chip_vendor, chip_model, uid_hex, uid_bytes,
            uid_length, uid_observation, atqa_hex, sak_hex, capacity_bytes, sector_count,
            block_count, block_size, prng, magic_uid_writable, manufacturer_block_hex,
            notes, created_at, updated_at
        ) VALUES (
            :label, :element_kind, :ownership, :authorized_use, :frequency_mhz, :standard,
            :technology, :product_family, :chip_vendor, :chip_model, :uid_hex, :uid_bytes,
            :uid_length, :uid_observation, :atqa_hex, :sak_hex, :capacity_bytes, :sector_count,
            :block_count, :block_size, :prng, :magic_uid_writable, :manufacturer_block_hex,
            :notes, :created_at, :updated_at
        )
        ON CONFLICT(technology, uid_hex) DO UPDATE SET
            label=excluded.label,
            ownership=excluded.ownership,
            authorized_use=excluded.authorized_use,
            product_family=excluded.product_family,
            chip_vendor=excluded.chip_vendor,
            chip_model=excluded.chip_model,
            uid_bytes=excluded.uid_bytes,
            uid_length=excluded.uid_length,
            uid_observation=excluded.uid_observation,
            atqa_hex=excluded.atqa_hex,
            sak_hex=excluded.sak_hex,
            manufacturer_block_hex=excluded.manufacturer_block_hex,
            notes=excluded.notes,
            updated_at=excluded.updated_at
        """,
        values,
    )
    return int(
        connection.execute(
            "SELECT id FROM elements WHERE technology = ? AND uid_hex = ?",
            (values["technology"], values["uid_hex"]),
        ).fetchone()[0]
    )


def artifact_media_type(path: Path) -> str:
    if path.suffix == ".bin":
        return "application/octet-stream"
    if path.suffix == ".log":
        return "text/plain"
    return mimetypes.guess_type(path.name)[0] or "application/octet-stream"


def import_mfc(
    connection: sqlite3.Connection,
    *,
    run_key: str,
    read_at: str,
    label: str,
    dump_path: Path,
    verification_dump_path: Path,
    json_path: Path,
    verification_json_path: Path,
    key_path: Path,
    log_paths: Iterable[Path],
) -> int:
    read_at = utc_offset_timestamp(read_at)
    validated = validate_mfc_files(dump_path, json_path, key_path)
    verified = validate_mfc_files(verification_dump_path, verification_json_path, key_path)
    dump = validated["dump"]
    document = validated["document"]
    keys = validated["keys"]
    if dump != verified["dump"] or document != verified["document"]:
        raise ValueError("The primary and verification reads are not identical")

    reader_id = upsert_reader(connection, read_at)
    element_id = upsert_element(connection, document, dump, validated["uid"], label, read_at)
    connection.execute(
        """
        INSERT INTO reads(
            run_key, element_id, reader_id, read_at, status, method, tool_command,
            complete, verified, verification_method, dump_size, dump_sha256,
            key_file_sha256, raw_dump, raw_json, notes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_key) DO UPDATE SET
            element_id=excluded.element_id,
            reader_id=excluded.reader_id,
            read_at=excluded.read_at,
            status=excluded.status,
            method=excluded.method,
            tool_command=excluded.tool_command,
            complete=excluded.complete,
            verified=excluded.verified,
            verification_method=excluded.verification_method,
            dump_size=excluded.dump_size,
            dump_sha256=excluded.dump_sha256,
            key_file_sha256=excluded.key_file_sha256,
            raw_dump=excluded.raw_dump,
            raw_json=excluded.raw_json,
            notes=excluded.notes
        """,
        (
            run_key,
            element_id,
            reader_id,
            read_at,
            "complete",
            "Proxmark3 hf mf autopwn followed by an independent hf mf dump",
            "hf mf autopwn --1k -s 0 -a -k FFFFFFFFFFFF; hf mf dump --1k --keys <key-file>",
            1,
            1,
            "Two independent 1024-byte reads are byte-identical",
            len(dump),
            sha256(dump),
            sha256(keys),
            dump,
            json.dumps(document, sort_keys=True, separators=(",", ":")),
            "All 64 blocks and all 32 sector keys were read. No write command was used.",
            read_at,
        ),
    )
    read_id = int(connection.execute("SELECT id FROM reads WHERE run_key = ?", (run_key,)).fetchone()[0])
    connection.execute("DELETE FROM sectors WHERE read_id = ?", (read_id,))
    connection.execute("DELETE FROM blocks WHERE read_id = ?", (read_id,))
    connection.execute("DELETE FROM artifacts WHERE read_id = ?", (read_id,))
    connection.execute("DELETE FROM observations WHERE read_id = ?", (read_id,))

    for sector in range(16):
        entry = document["SectorKeys"][str(sector)]
        connection.execute(
            """
            INSERT INTO sectors(
                read_id, sector_number, first_block, trailer_block, key_a_hex,
                key_b_hex, key_a_source, key_b_source, access_conditions_hex,
                access_conditions_json, user_data_hex
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                read_id,
                sector,
                sector * 4,
                sector * 4 + 3,
                normalize_hex(entry["KeyA"], 6),
                normalize_hex(entry["KeyB"], 6),
                "Proxmark default dictionary",
                "Proxmark default dictionary",
                normalize_hex(entry["AccessConditions"], 4),
                json.dumps(entry["AccessConditionsText"], sort_keys=True),
                normalize_hex(entry["AccessConditionsText"]["UserData"], 1),
            ),
        )

    for block_number in range(64):
        data = dump[block_number * 16 : (block_number + 1) * 16]
        block_in_sector = block_number % 4
        if block_number == 0:
            role = "manufacturer"
        elif block_in_sector == 3:
            role = "sector_trailer"
        else:
            role = "data"
        connection.execute(
            """
            INSERT INTO blocks(
                read_id, block_number, sector_number, block_in_sector, block_role,
                data, data_hex, data_sha256, ascii_view, all_zero
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                read_id,
                block_number,
                block_number // 4,
                block_in_sector,
                role,
                data,
                data.hex().upper(),
                sha256(data),
                printable(data),
                int(not any(data)),
            ),
        )

    artifact_specs = [
        ("primary_dump_binary", dump_path),
        ("verification_dump_binary", verification_dump_path),
        ("primary_dump_json", json_path),
        ("verification_dump_json", verification_json_path),
        ("sector_keys_binary", key_path),
    ]
    artifact_specs.extend(("proxmark_session_log", path) for path in log_paths)
    for kind, path in artifact_specs:
        content = path.read_bytes()
        try:
            relative_path = str(path.resolve().relative_to(ROOT))
        except ValueError:
            relative_path = str(path.resolve())
        connection.execute(
            """
            INSERT INTO artifacts(
                read_id, artifact_kind, relative_path, file_name, media_type,
                size_bytes, sha256, content, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                read_id,
                kind,
                relative_path,
                path.name,
                artifact_media_type(path),
                len(content),
                sha256(content),
                content,
                read_at,
            ),
        )

    data_block_numbers = [
        block for block in range(1, 64) if block % 4 != 3 and any(dump[block * 16 : (block + 1) * 16])
    ]
    observations = {
        "all_sector_keys_recovered": (True, "measured", "confirmed"),
        "all_keys_use_factory_default_ffffffffffff": (True, "measured", "confirmed"),
        "application_data_nonzero_blocks": (data_block_numbers, "measured", "confirmed"),
        "chip_backdoor_key_hex": ("A31667A8CEC1", "measured", "confirmed"),
        "chip_fingerprint": ("Fudan FM11RF08", "measured", "confirmed"),
        "tag_write_performed": (False, "operation_log", "confirmed"),
        "firmware_write_performed": (False, "operation_log", "confirmed"),
        "rats_supported": (False, "measured", "confirmed"),
        "magic_tag_information": ("n/a", "measured", "confirmed"),
        "proxmark_json_atqa_storage_order": (
            normalize_hex(document["Card"]["ATQA"], 2),
            "source_file",
            "confirmed",
        ),
        "possible_access_system_behavior": (
            "The door system can use only the UID. Verify this at the reader before treating it as confirmed.",
            "inference",
            "low",
        ),
    }
    for key, (value, evidence_type, confidence) in observations.items():
        connection.execute(
            """
            INSERT INTO observations(read_id, observation_key, value_json, evidence_type, confidence)
            VALUES (?, ?, ?, ?, ?)
            """,
            (read_id, key, json.dumps(value, sort_keys=True), evidence_type, confidence),
        )

    synchronize_legacy_devices(
        connection,
        project_id=get_project_id(connection, DEFAULT_PROJECT_KEY),
        now=read_at,
    )
    connection.commit()
    return read_id


def record_clone(
    connection: sqlite3.Connection,
    *,
    run_key: str,
    executed_at: str,
    source_device_key: str,
    target_device_key: str,
    source_read_run_key: str,
    uid_before_hex: str,
    uid_after_hex: str,
    factory_dump_path: Path,
    factory_json_path: Path,
    magic_dump_path: Path,
    magic_json_path: Path,
    standard_dump_path: Path,
    standard_json_path: Path,
    log_paths: Iterable[Path],
    extra_artifact_paths: Iterable[Path],
) -> int:
    executed_at = utc_offset_timestamp(executed_at)
    uid_before_hex = normalize_hex(uid_before_hex, 4)
    uid_after_hex = normalize_hex(uid_after_hex, 4)
    source_device_id = get_device_id(connection, source_device_key)
    target_device_id = get_device_id(connection, target_device_key)
    source_read = connection.execute(
        "SELECT id, element_id, dump_sha256, raw_dump FROM reads WHERE run_key = ?",
        (source_read_run_key,),
    ).fetchone()
    if source_read is None:
        raise ValueError(f"Source read {source_read_run_key!r} does not exist")

    factory = validate_dump_pair(factory_dump_path, factory_json_path)
    magic = validate_dump_pair(magic_dump_path, magic_json_path)
    standard = validate_dump_pair(standard_dump_path, standard_json_path)
    source_dump = bytes(source_read["raw_dump"])
    if factory["uid"].hex().upper() != uid_before_hex:
        raise ValueError("Factory backup UID does not match --uid-before")
    if magic["uid"].hex().upper() != uid_after_hex or standard["uid"].hex().upper() != uid_after_hex:
        raise ValueError("Verification UID does not match --uid-after")
    if sha256(source_dump) != source_read["dump_sha256"]:
        raise ValueError("Source read SHA-256 does not match its stored dump")
    if source_dump != magic["dump"] or source_dump != standard["dump"]:
        raise ValueError("Clone verification dumps are not byte-identical to the source")

    metadata_row = connection.execute(
        "SELECT metadata_json FROM devices WHERE id = ?", (target_device_id,)
    ).fetchone()
    metadata = json.loads(metadata_row[0]) if metadata_row and metadata_row[0] else {}
    metadata.update(
        {
            "credential_element_id": int(source_read["element_id"]),
            "factory_uid_hex": uid_before_hex,
            "current_uid_hex": uid_after_hex,
            "atqa_hex": "0004",
            "sak_hex": "08",
            "technology": "MIFARE Classic 1K",
            "magic_generation": "Gen 1a",
            "uid_writable": True,
            "static_nonce": "009080A2",
            "source_device_key": source_device_key,
            "source_read_run_key": source_read_run_key,
            "clone_verified": True,
            "clone_verified_at": executed_at,
            "source_dump_sha256": sha256(source_dump),
            "factory_backup_sha256": sha256(factory["dump"]),
        }
    )
    connection.execute(
        """
        UPDATE devices
        SET manufacturer = 'Fudan-compatible',
            model = 'MIFARE Classic 1K Magic Gen 1a',
            serial_number = ?,
            interface = 'ISO/IEC 14443-A, 13.56 MHz',
            metadata_json = ?,
            notes = 'Verified physical clone. Factory image is stored for rollback.',
            updated_at = ?
        WHERE id = ?
        """,
        (uid_before_hex, json.dumps(metadata, sort_keys=True), executed_at, target_device_id),
    )
    values = (
        catalog_key(run_key),
        source_device_id,
        target_device_id,
        int(source_read["id"]),
        executed_at,
        "verified",
        "Full 64-block write to MIFARE Classic 1K Magic Gen 1a",
        "hf mf cload --1k --file <source-dump>",
        64,
        uid_before_hex,
        uid_after_hex,
        sha256(source_dump),
        sha256(factory["dump"]),
        sha256(magic["dump"]),
        sha256(standard["dump"]),
        1,
        "Magic backdoor read and normal authenticated read both match the source byte for byte.",
        executed_at,
    )
    connection.execute(
        """
        INSERT INTO clone_operations(
            run_key, source_device_id, target_device_id, source_read_id, executed_at,
            status, method, tool_command, blocks_written, uid_before_hex, uid_after_hex,
            source_dump_sha256, prewrite_backup_sha256, magic_read_sha256,
            standard_read_sha256, byte_identical, notes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_key) DO UPDATE SET
            source_device_id=excluded.source_device_id,
            target_device_id=excluded.target_device_id,
            source_read_id=excluded.source_read_id,
            executed_at=excluded.executed_at,
            status=excluded.status,
            method=excluded.method,
            tool_command=excluded.tool_command,
            blocks_written=excluded.blocks_written,
            uid_before_hex=excluded.uid_before_hex,
            uid_after_hex=excluded.uid_after_hex,
            source_dump_sha256=excluded.source_dump_sha256,
            prewrite_backup_sha256=excluded.prewrite_backup_sha256,
            magic_read_sha256=excluded.magic_read_sha256,
            standard_read_sha256=excluded.standard_read_sha256,
            byte_identical=excluded.byte_identical,
            notes=excluded.notes
        """,
        values,
    )
    operation_id = int(
        connection.execute("SELECT id FROM clone_operations WHERE run_key = ?", (run_key,)).fetchone()[0]
    )
    connection.execute("DELETE FROM operation_artifacts WHERE clone_operation_id = ?", (operation_id,))
    artifact_specs = [
        ("factory_dump_binary", factory_dump_path),
        ("factory_dump_json", factory_json_path),
        ("magic_verification_binary", magic_dump_path),
        ("magic_verification_json", magic_json_path),
        ("standard_verification_binary", standard_dump_path),
        ("standard_verification_json", standard_json_path),
    ]
    artifact_specs.extend(("proxmark_session_log", path) for path in log_paths)
    artifact_specs.extend(("followup_verification", path) for path in extra_artifact_paths)
    for kind, path in artifact_specs:
        content = path.read_bytes()
        try:
            relative_path = str(path.resolve().relative_to(ROOT))
        except ValueError:
            relative_path = str(path.resolve())
        connection.execute(
            """
            INSERT INTO operation_artifacts(
                clone_operation_id, artifact_kind, relative_path, file_name,
                media_type, size_bytes, sha256, content, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                operation_id,
                kind,
                relative_path,
                path.name,
                artifact_media_type(path),
                len(content),
                sha256(content),
                content,
                executed_at,
            ),
        )
    connection.commit()
    synchronize_clone_profiles(connection, now=executed_at)
    return operation_id


def verify_database(connection: sqlite3.Connection) -> list[str]:
    problems: list[str] = []
    schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if schema_version != SCHEMA_VERSION:
        problems.append(f"Expected schema version {SCHEMA_VERSION}, got {schema_version}")
    integrity_check = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity_check != "ok":
        problems.append(f"SQLite integrity_check: {integrity_check}")
    foreign_key_problems = connection.execute("PRAGMA foreign_key_check").fetchall()
    if foreign_key_problems:
        problems.append(f"SQLite foreign_key_check found {len(foreign_key_problems)} problem(s)")
    try:
        migration_rows = connection.execute(
            "SELECT migration_key, schema_version, script_sha256 FROM schema_migrations"
        ).fetchall()
    except sqlite3.OperationalError:
        problems.append("Schema migration history table is missing")
        migration_rows = []
    if not any(row["schema_version"] == SCHEMA_VERSION for row in migration_rows):
        problems.append(f"Schema migration history has no entry for version {SCHEMA_VERSION}")
    for row in migration_rows:
        if not re.fullmatch(r"[0-9a-f]{64}", row["script_sha256"]):
            problems.append(f"Schema migration {row['migration_key']}: invalid script SHA-256")

    for row in connection.execute(
        """
        SELECT d.device_key, d.device_kind, d.device_type_key, t.default_device_kind
        FROM devices AS d
        LEFT JOIN device_types AS t ON t.type_key = d.device_type_key
        """
    ):
        if row["device_type_key"] is None or row["default_device_kind"] is None:
            problems.append(f"Device {row['device_key']}: no registered device type")
        elif row["device_kind"] != row["default_device_kind"]:
            problems.append(
                f"Device {row['device_key']}: type {row['device_type_key']} does not match kind {row['device_kind']}"
            )

    for row in connection.execute(
        "SELECT device_id, property_key FROM device_information"
    ):
        if SECRET_PROPERTY_RE.search(row["property_key"]):
            problems.append(f"Device information {row['property_key']}: possible plaintext secret property")

    for row in connection.execute(
        """
        SELECT information.*, device.device_key
        FROM device_information AS information
        JOIN devices AS device ON device.id = information.device_id
        """
    ):
        try:
            validate_device_information_contract(
                connection,
                device_id=int(row["device_id"]),
                property_key=row["property_key"],
                information_kind=row["information_kind"],
                value=json.loads(row["value_json"]),
                unit=row["unit"],
            )
        except ValueError as error:
            problems.append(f"Device {row['device_key']} information {row['property_key']}: {error}")

    for row in connection.execute(
        """
        SELECT channel.*, device.device_key
        FROM measurement_channels AS channel
        JOIN devices AS device ON device.id = channel.device_id
        """
    ):
        try:
            validate_measurement_channel_contract(
                connection,
                device_id=int(row["device_id"]),
                channel_key=row["channel_key"],
                quantity_kind=row["quantity_kind"],
                unit=row["unit"],
                minimum_value=row["minimum_value"],
                maximum_value=row["maximum_value"],
            )
        except ValueError as error:
            problems.append(f"Device {row['device_key']} channel {row['channel_key']}: {error}")

    for row in connection.execute(
        "SELECT id, endpoint FROM device_interfaces WHERE endpoint IS NOT NULL"
    ):
        if re.search(r"://[^/@\s:]+:[^/@\s]+@", row["endpoint"]):
            problems.append(f"Device interface {row['id']}: endpoint contains embedded credentials")

    for row in connection.execute("SELECT script_key, relative_path, script_sha256 FROM device_scripts"):
        try:
            script_path = registered_managed_script_path(str(row["relative_path"]))
            if managed_script_sha256(script_path) != row["script_sha256"]:
                problems.append(f"Managed device script {row['script_key']}: content changed after review")
        except ValueError:
            problems.append(f"Managed device script {row['script_key']}: registered path is unavailable or invalid")

    for row in connection.execute(
        """
        SELECT relation.id, relation.relation_type
        FROM device_relations AS relation
        LEFT JOIN device_relation_types AS type ON type.relation_type = relation.relation_type
        WHERE type.relation_type IS NULL OR type.status <> 'active'
        """
    ):
        problems.append(f"Device relation {row['id']}: type {row['relation_type']} is not active")

    for row in connection.execute(
        "SELECT id, authorization_key, allowed_operations_json FROM access_authorizations"
    ):
        try:
            legacy_operations = sorted(json.loads(row["allowed_operations_json"]))
        except (TypeError, json.JSONDecodeError):
            problems.append(f"Authorization {row['authorization_key']}: operation JSON is invalid")
            continue
        normalized_operations = [
            operation["operation"]
            for operation in connection.execute(
                """
                SELECT operation FROM access_authorization_operations
                WHERE authorization_id = ? ORDER BY operation
                """,
                (row["id"],),
            )
        ]
        if legacy_operations != normalized_operations:
            problems.append(
                f"Authorization {row['authorization_key']}: JSON operations do not match normalized operations"
            )

    for row in connection.execute(
        """
        SELECT d.device_key
        FROM devices AS d
        JOIN project_devices AS pd ON pd.device_id = d.id
        LEFT JOIN rfid_profiles AS profile ON profile.device_id = d.id
        WHERE d.device_kind IN ('rfid_reader', 'rfid_tag', 'rfid_card', 'rfid_key_fob')
          AND d.lifecycle_status = 'active'
          AND pd.status = 'in_scope'
          AND profile.device_id IS NULL
        """
    ):
        problems.append(f"In-scope RFID device {row['device_key']} has no RFID profile")

    for row in connection.execute(
        """
        SELECT c.id, c.minimum_value, c.maximum_value, s.value_real, s.quality
        FROM measurement_samples AS s
        JOIN measurement_channels AS c ON c.id = s.channel_id
        WHERE s.quality = 'valid'
        """
    ):
        if (
            (row["minimum_value"] is not None and row["value_real"] < row["minimum_value"])
            or (row["maximum_value"] is not None and row["value_real"] > row["maximum_value"])
        ):
            problems.append(f"Measurement channel {row['id']}: valid sample is outside the declared range")

    for read in connection.execute("SELECT id, dump_size, dump_sha256, raw_dump FROM reads"):
        raw_dump = bytes(read["raw_dump"])
        if len(raw_dump) != read["dump_size"]:
            problems.append(f"Read {read['id']}: dump size does not match")
        if sha256(raw_dump) != read["dump_sha256"]:
            problems.append(f"Read {read['id']}: dump SHA-256 does not match")
        block_rows = connection.execute(
            "SELECT block_number, data, data_sha256 FROM blocks WHERE read_id = ? ORDER BY block_number",
            (read["id"],),
        ).fetchall()
        if len(block_rows) != 64:
            problems.append(f"Read {read['id']}: expected 64 blocks, got {len(block_rows)}")
        else:
            reconstructed = b"".join(bytes(row["data"]) for row in block_rows)
            if reconstructed != raw_dump:
                problems.append(f"Read {read['id']}: block data does not reconstruct the raw dump")
            for row in block_rows:
                if sha256(bytes(row["data"])) != row["data_sha256"]:
                    problems.append(f"Read {read['id']}, block {row['block_number']}: SHA-256 does not match")

    for artifact in connection.execute(
        "SELECT id, relative_path, size_bytes, sha256, content FROM artifacts"
    ):
        content = bytes(artifact["content"])
        if len(content) != artifact["size_bytes"] or sha256(content) != artifact["sha256"]:
            problems.append(f"Artifact {artifact['id']}: stored content does not match metadata")
        artifact_path = Path(artifact["relative_path"])
        if not artifact_path.is_absolute():
            artifact_path = ROOT / artifact_path
        if not artifact_path.is_file():
            problems.append(f"Artifact {artifact['id']}: source file is missing")
        elif artifact_path.read_bytes() != content:
            problems.append(f"Artifact {artifact['id']}: source file differs from stored content")

    for operation in connection.execute(
        """
        SELECT c.*, r.dump_sha256 AS read_dump_sha256, r.raw_dump AS read_raw_dump
        FROM clone_operations AS c
        JOIN reads AS r ON r.id = c.source_read_id
        """
    ):
        source_dump = bytes(operation["read_raw_dump"])
        source_hash = sha256(source_dump)
        if operation["status"] != "verified" or operation["byte_identical"] != 1:
            problems.append(f"Clone operation {operation['id']}: operation is not verified")
        if source_hash != operation["read_dump_sha256"] or source_hash != operation["source_dump_sha256"]:
            problems.append(f"Clone operation {operation['id']}: source dump SHA-256 does not match")
        if operation["magic_read_sha256"] != source_hash:
            problems.append(f"Clone operation {operation['id']}: magic read SHA-256 does not match source")
        if operation["standard_read_sha256"] != source_hash:
            problems.append(f"Clone operation {operation['id']}: standard read SHA-256 does not match source")

    for artifact in connection.execute(
        "SELECT id, relative_path, size_bytes, sha256, content FROM operation_artifacts"
    ):
        content = bytes(artifact["content"])
        if len(content) != artifact["size_bytes"] or sha256(content) != artifact["sha256"]:
            problems.append(f"Operation artifact {artifact['id']}: stored content does not match metadata")
        artifact_path = Path(artifact["relative_path"])
        if not artifact_path.is_absolute():
            artifact_path = ROOT / artifact_path
        if not artifact_path.is_file():
            problems.append(f"Operation artifact {artifact['id']}: source file is missing")
        elif artifact_path.read_bytes() != content:
            problems.append(f"Operation artifact {artifact['id']}: source file differs from stored content")

    for run in connection.execute(
        """
        SELECT id, stdout_sha256, stderr_sha256, stdout_content, stderr_content,
               stdout_original_sha256, stderr_original_sha256, output_purged_at
        FROM device_command_runs
        """
    ):
        if sha256(bytes(run["stdout_content"])) != run["stdout_sha256"]:
            problems.append(f"Device command run {run['id']}: stdout SHA-256 does not match")
        if sha256(bytes(run["stderr_content"])) != run["stderr_sha256"]:
            problems.append(f"Device command run {run['id']}: stderr SHA-256 does not match")
        if run["output_purged_at"] is not None:
            if run["stdout_original_sha256"] is None or run["stderr_original_sha256"] is None:
                problems.append(f"Device command run {run['id']}: purged output has no original SHA-256")
            if bytes(run["stdout_content"]) or bytes(run["stderr_content"]):
                problems.append(f"Device command run {run['id']}: purged output content is not empty")

    try:
        database_path = connection_database_path(connection)
        for backup in connection.execute(
            "SELECT backup_key, relative_path, manifest_relative_path, size_bytes, sha256 FROM database_backups"
        ):
            backup_path = database_path.parent / backup["relative_path"]
            manifest_path = database_path.parent / backup["manifest_relative_path"]
            try:
                loaded_path, manifest = load_database_backup_manifest(database_path, backup_path)
                if manifest_path != backup_manifest_path(loaded_path):
                    raise ValueError("registered manifest path does not match backup file")
                if manifest["sha256"] != backup["sha256"] or manifest["size_bytes"] != backup["size_bytes"]:
                    raise ValueError("registered metadata does not match sidecar manifest")
            except ValueError as error:
                problems.append(f"Database backup {backup['backup_key']}: {error}")
    except sqlite3.OperationalError:
        problems.append("Database backup registry table is missing")

    missing_authorizations = connection.execute(
        """
        SELECT p.project_key, d.device_key
        FROM project_devices AS pd
        JOIN projects AS p ON p.id = pd.project_id
        JOIN devices AS d ON d.id = pd.device_id
        LEFT JOIN active_authorized_devices AS active
          ON active.project_key = p.project_key AND active.device_key = d.device_key
        WHERE p.status = 'active'
          AND d.lifecycle_status = 'active'
          AND pd.status = 'in_scope'
          AND active.authorization_key IS NULL
        ORDER BY p.project_key, d.device_key
        """
    ).fetchall()
    for row in missing_authorizations:
        problems.append(
            f"In-scope device {row['device_key']} in project {row['project_key']} has no active authorization"
        )
    return problems


def print_list(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT e.id, e.label, e.uid_hex, e.technology, e.chip_model,
               COUNT(r.id) AS read_count, MAX(r.read_at) AS last_read
        FROM elements e
        LEFT JOIN reads r ON r.element_id = e.id
        GROUP BY e.id
        ORDER BY e.id
        """
    ).fetchall()
    if not rows:
        print("No RFID elements are stored.")
        return
    for row in rows:
        print(
            f"{row['id']}: {row['label']} | UID [stored] | "
            f"{row['technology']} {row['chip_model']} | reads {row['read_count']} | {row['last_read']}"
        )


def print_element(
    connection: sqlite3.Connection, element_id: int, reveal_keys: bool, reveal_sensitive: bool
) -> None:
    element = connection.execute("SELECT * FROM elements WHERE id = ?", (element_id,)).fetchone()
    if element is None:
        raise ValueError(f"Element {element_id} does not exist")
    result: dict[str, Any] = {"element": dict(element), "reads": []}
    result["element"].pop("uid_bytes", None)
    if not reveal_sensitive:
        result["element"]["uid_hex"] = "[stored]"
        result["element"]["manufacturer_block_hex"] = "[stored]"
    for read in connection.execute(
        "SELECT * FROM reads WHERE element_id = ? ORDER BY read_at", (element_id,)
    ).fetchall():
        item = dict(read)
        item.pop("raw_dump", None)
        item.pop("raw_json", None)
        sectors = [dict(row) for row in connection.execute(
            "SELECT * FROM sectors WHERE read_id = ? ORDER BY sector_number", (read["id"],)
        )]
        if not reveal_keys:
            for sector in sectors:
                sector["key_a_hex"] = "[stored]"
                sector["key_b_hex"] = "[stored]"
        item["sectors"] = sectors
        item["observations"] = [dict(row) for row in connection.execute(
            "SELECT observation_key, value_json, evidence_type, confidence FROM observations WHERE read_id = ? ORDER BY observation_key",
            (read["id"],),
        )]
        item["artifacts"] = [dict(row) for row in connection.execute(
            "SELECT artifact_kind, relative_path, size_bytes, sha256 FROM artifacts WHERE read_id = ? ORDER BY id",
            (read["id"],),
        )]
        result["reads"].append(item)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def print_projects(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT p.project_key, p.name, p.purpose, p.status,
               COUNT(DISTINCT pd.device_id) AS device_count,
               COUNT(DISTINCT active.device_key) AS active_authorization_count
        FROM projects AS p
        LEFT JOIN project_devices AS pd ON pd.project_id = p.id
        LEFT JOIN active_authorized_devices AS active
          ON active.project_key = p.project_key AND active.device_key = (
              SELECT device_key FROM devices WHERE id = pd.device_id
          )
        GROUP BY p.id
        ORDER BY p.project_key
        """
    ).fetchall()
    if not rows:
        print("No projects are stored.")
        return
    for row in rows:
        print(
            f"{row['project_key']}: {row['name']} | {row['purpose']} | {row['status']} | "
            f"devices {row['device_count']} | active authorizations {row['active_authorization_count']}"
        )


def print_devices(connection: sqlite3.Connection, project_key: str | None) -> None:
    parameters: tuple[Any, ...] = ()
    condition = ""
    if project_key:
        condition = "WHERE p.project_key = ?"
        parameters = (catalog_key(project_key),)
    rows = connection.execute(
        f"""
        SELECT p.project_key, d.device_key, d.name, d.device_kind, d.device_type_key, d.role,
               d.ownership_status, d.lifecycle_status, pd.status AS scope_status,
               CASE WHEN active.device_key IS NULL THEN 0 ELSE 1 END AS authorized
        FROM project_devices AS pd
        JOIN projects AS p ON p.id = pd.project_id
        JOIN devices AS d ON d.id = pd.device_id
        LEFT JOIN active_authorized_devices AS active
          ON active.project_key = p.project_key AND active.device_key = d.device_key
        {condition}
        GROUP BY p.project_key, d.device_key
        ORDER BY p.project_key, d.device_key
        """,
        parameters,
    ).fetchall()
    if not rows:
        print("No devices are stored for the selected project.")
        return
    for row in rows:
        authorization = "authorized" if row["authorized"] else "not-authorized"
        print(
            f"{row['project_key']} / {row['device_key']}: {row['name']} | "
            f"{row['device_kind']} / {row['device_type_key']} / {row['role']} | {row['ownership_status']} | "
            f"{row['lifecycle_status']} | {row['scope_status']} | {authorization}"
        )


def _display_value(value: Any, classification: str, reveal_sensitive: bool) -> Any:
    if classification != "normal" and not reveal_sensitive:
        return "[stored]"
    return value


def print_device_types(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT type.type_key, type.display_name, type.category, type.default_device_kind, type.status,
               contract.enforcement
        FROM device_types AS type
        LEFT JOIN device_type_contracts AS contract ON contract.device_type_key = type.type_key
        ORDER BY type.type_key
        """
    ).fetchall()
    for row in rows:
        contract = f" | contract={row['enforcement']}" if row["enforcement"] else ""
        print(
            f"{row['type_key']}: {row['display_name']} | {row['category']} | "
            f"kind={row['default_device_kind']} | {row['status']}{contract}"
        )


def print_device_type_contracts(connection: sqlite3.Connection, type_key: str | None) -> None:
    parameters: tuple[Any, ...] = ()
    query = "SELECT * FROM device_type_contracts"
    if type_key is not None:
        query += " WHERE device_type_key = ?"
        parameters = (catalog_key(type_key),)
    rows = connection.execute(query + " ORDER BY device_type_key", parameters).fetchall()
    if not rows:
        print("No device type contracts are registered.")
        return
    for row in rows:
        print(
            f"{row['device_type_key']}: enforcement={row['enforcement']} | "
            f"capabilities={row['capabilities_json']} | "
            f"information={row['information_schema_json']} | measurements={row['measurement_schema_json']}"
        )


def print_relation_types(connection: sqlite3.Connection) -> None:
    rows = list_relation_types(connection)
    if not rows:
        print("No device relation types are registered.")
        return
    for row in rows:
        direction = "directional" if row["directional"] else "bidirectional"
        print(
            f"{row['relation_type']}: {row['display_name']} | {direction} | {row['status']} | "
            f"{row['description']}"
        )


def print_device_detail(connection: sqlite3.Connection, device_key: str, reveal_sensitive: bool) -> None:
    device_id = get_device_id(connection, device_key)
    device = connection.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    result: dict[str, Any] = {"device": dict(device), "identifiers": [], "information": [], "interfaces": [], "components": [], "rfid_profile": None}
    result["device"].pop("metadata_json", None)
    result["device"].pop("legacy_reader_id", None)
    result["device"].pop("legacy_element_id", None)
    if result["device"]["sensitivity"] != "normal" and not reveal_sensitive:
        result["device"]["serial_number"] = "[stored]" if result["device"]["serial_number"] else None
        result["device"]["asset_identifier"] = "[stored]" if result["device"]["asset_identifier"] else None
    for row in connection.execute(
        "SELECT identifier_kind, identifier_value, identifier_scope, classification, status, source_reference, observed_at "
        "FROM device_identifiers WHERE device_id = ? ORDER BY identifier_kind, id",
        (device_id,),
    ):
        entry = dict(row)
        entry["identifier_value"] = _display_value(
            entry["identifier_value"], entry.pop("classification"), reveal_sensitive
        )
        result["identifiers"].append(entry)
    for row in connection.execute(
        "SELECT information_kind, property_key, value_json, unit, classification, confidence, is_current, source_reference, observed_at "
        "FROM device_information WHERE device_id = ? ORDER BY property_key, observed_at DESC",
        (device_id,),
    ):
        entry = dict(row)
        value = json.loads(entry["value_json"])
        entry["value"] = _display_value(value, entry.pop("classification"), reveal_sensitive)
        entry.pop("value_json")
        result["information"].append(entry)
    for row in connection.execute(
        "SELECT interface_key, interface_type, endpoint, address, authentication_type, secret_reference, status, details_json, source_reference, observed_at "
        "FROM device_interfaces WHERE device_id = ? ORDER BY interface_key",
        (device_id,),
    ):
        entry = dict(row)
        entry["secret_reference"] = "[configured]" if entry["secret_reference"] else None
        entry["details"] = json.loads(entry.pop("details_json"))
        result["interfaces"].append(entry)
    for row in connection.execute(
        "SELECT component_key, component_kind, name, version, status, details_json, source_reference, observed_at "
        "FROM device_components WHERE device_id = ? ORDER BY component_key",
        (device_id,),
    ):
        entry = dict(row)
        entry["details"] = json.loads(entry.pop("details_json"))
        result["components"].append(entry)
    profile = connection.execute(
        "SELECT profile_kind, frequency_mhz, standard, technology, product_family, chip_vendor, chip_model, source_reference, observed_at "
        "FROM rfid_profiles WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    if profile is not None:
        result["rfid_profile"] = dict(profile)
    result["projects"] = [dict(row) for row in connection.execute(
        "SELECT p.project_key, pd.role_in_project, pd.status, pd.scope FROM project_devices AS pd "
        "JOIN projects AS p ON p.id = pd.project_id WHERE pd.device_id = ? ORDER BY p.project_key",
        (device_id,),
    )]
    result["relations"] = [dict(row) for row in connection.execute(
        "SELECT source.device_key AS source, target.device_key AS target, r.relation_type, r.status, r.source_reference, r.observed_at "
        "FROM device_relations AS r JOIN devices AS source ON source.id = r.source_device_id "
        "JOIN devices AS target ON target.id = r.target_device_id "
        "WHERE r.source_device_id = ? OR r.target_device_id = ? ORDER BY r.id",
        (device_id, device_id),
    )]
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


def print_device_scripts(connection: sqlite3.Connection, device_key: str) -> None:
    rows = list_device_scripts(connection, device_key)
    if not rows:
        print("No managed device scripts are registered.")
        return
    for row in rows:
        interactive = "interactive" if row["interactive"] else "non-interactive"
        print(
            f"{row['script_key']}: {row['display_name']} | operation={row['required_operation']} | "
            f"risk={row['risk_level']} | timeout={row['timeout_seconds']}s | {interactive} | "
            f"revision={row['script_revision']} | SHA-256={row['script_sha256']}"
        )


def print_database_backups(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT backup_key, relative_path, size_bytes, sha256, schema_version, status, created_at
        FROM database_backups ORDER BY created_at DESC
        """
    ).fetchall()
    if not rows:
        print("No database backups are registered.")
        return
    for row in rows:
        print(
            f"{row['backup_key']}: {row['relative_path']} | size={row['size_bytes']} | "
            f"schema=v{row['schema_version']} | {row['status']} | SHA-256 {row['sha256']} | {row['created_at']}"
        )


def print_device_information(connection: sqlite3.Connection, device_key: str, include_history: bool) -> None:
    device_id = get_device_id(connection, device_key)
    condition = "" if include_history else "AND is_current = 1"
    rows = connection.execute(
        f"SELECT property_key, information_kind, value_json, unit, confidence, classification, observed_at, source_reference "
        f"FROM device_information WHERE device_id = ? {condition} ORDER BY property_key, observed_at DESC",
        (device_id,),
    ).fetchall()
    for row in rows:
        value = _display_value(json.loads(row["value_json"]), row["classification"], False)
        print(
            f"{row['property_key']}: {json.dumps(value, ensure_ascii=False)} | {row['information_kind']} | "
            f"{row['confidence']} | {row['observed_at']} | source={row['source_reference']}"
        )


def print_device_interfaces(connection: sqlite3.Connection, device_key: str) -> None:
    device_id = get_device_id(connection, device_key)
    rows = connection.execute(
        "SELECT interface_key, interface_type, endpoint, address, authentication_type, secret_reference, status, observed_at "
        "FROM device_interfaces WHERE device_id = ? ORDER BY interface_key",
        (device_id,),
    ).fetchall()
    for row in rows:
        secret = "configured" if row["secret_reference"] else "none"
        print(
            f"{row['interface_key']}: {row['interface_type']} | {row['endpoint'] or row['address'] or '-'} | "
            f"auth={row['authentication_type'] or '-'} | secret={secret} | {row['status']} | {row['observed_at']}"
        )


def print_access_methods(connection: sqlite3.Connection, project_key: str, device_key: str) -> None:
    project_id = get_project_id(connection, project_key)
    device_id = get_device_id(connection, device_key)
    rows = connection.execute(
        "SELECT method_key, method_type, endpoint, account_label, authentication_type, secret_reference, status "
        "FROM access_methods WHERE project_id = ? AND device_id = ? ORDER BY method_key",
        (project_id, device_id),
    ).fetchall()
    for row in rows:
        secret = "configured" if row["secret_reference"] else "none"
        print(
            f"{row['method_key']}: {row['method_type']} | {row['endpoint'] or '-'} | "
            f"account={row['account_label'] or '-'} | auth={row['authentication_type'] or '-'} | "
            f"secret={secret} | {row['status']}"
        )


def print_measurements(connection: sqlite3.Connection, device_key: str, channel_key: str, limit: int) -> None:
    device_id = get_device_id(connection, device_key)
    channel = connection.execute(
        "SELECT id, display_name, unit FROM measurement_channels WHERE device_id = ? AND channel_key = ?",
        (device_id, catalog_key(channel_key)),
    ).fetchone()
    if channel is None:
        raise ValueError(f"Measurement channel {channel_key!r} does not exist for device {device_key!r}")
    for row in connection.execute(
        "SELECT observed_at, value_real, quality, source_reference FROM measurement_samples "
        "WHERE channel_id = ? ORDER BY observed_at DESC LIMIT ?",
        (channel["id"], limit),
    ):
        print(
            f"{row['observed_at']}: {row['value_real']} {channel['unit']} | {row['quality']} | "
            f"source={row['source_reference']}"
        )


def print_accesses(connection: sqlite3.Connection, project_key: str | None) -> None:
    parameters: tuple[Any, ...] = ()
    condition = ""
    if project_key:
        condition = "WHERE p.project_key = ?"
        parameters = (catalog_key(project_key),)
    rows = connection.execute(
        f"""
        SELECT p.project_key, d.device_key, d.name, a.authorization_key,
               a.subject, a.authorization_basis, a.access_level,
               a.allowed_operations_json, a.purpose, a.evidence_reference,
               a.status, a.valid_from, a.valid_until
        FROM access_authorizations AS a
        JOIN projects AS p ON p.id = a.project_id
        JOIN devices AS d ON d.id = a.device_id
        {condition}
        ORDER BY p.project_key, d.device_key, a.id
        """,
        parameters,
    ).fetchall()
    if not rows:
        print("No access authorizations are stored for the selected project.")
        return
    for row in rows:
        valid_until = row["valid_until"] or "no-expiry"
        operations = ",".join(json.loads(row["allowed_operations_json"]))
        print(
            f"{row['project_key']} / {row['device_key']}: {row['access_level']} | "
            f"{row['status']} | {row['authorization_basis']} | {row['purpose']} | "
            f"operations [{operations}] | {row['valid_from']} -> {valid_until} | "
            f"evidence {row['evidence_reference']}"
        )


def check_access(connection: sqlite3.Connection, project_key: str, device_key: str) -> bool:
    row = connection.execute(
        """
        SELECT access_level, allowed_operations_json, evidence_reference, valid_until
        FROM active_authorized_devices
        WHERE project_key = ? AND device_key = ?
        ORDER BY authorization_key
        LIMIT 1
        """,
        (catalog_key(project_key), catalog_key(device_key)),
    ).fetchone()
    if row is None:
        print(f"NOT AUTHORIZED: {project_key} / {device_key}")
        return False
    operations = ",".join(json.loads(row["allowed_operations_json"]))
    valid_until = row["valid_until"] or "no-expiry"
    print(
        f"AUTHORIZED: {project_key} / {device_key} | {row['access_level']} | "
        f"operations [{operations}] | until {valid_until} | evidence {row['evidence_reference']}"
    )
    return True


def print_clones(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT c.id, c.run_key, source.device_key AS source_key, target.device_key AS target_key,
               c.executed_at, c.status, c.uid_before_hex, c.uid_after_hex,
               c.blocks_written, c.source_dump_sha256, c.byte_identical
        FROM clone_operations AS c
        JOIN devices AS source ON source.id = c.source_device_id
        JOIN devices AS target ON target.id = c.target_device_id
        ORDER BY c.executed_at, c.id
        """
    ).fetchall()
    if not rows:
        print("No clone operations are stored.")
        return
    for row in rows:
        match = "byte-identical" if row["byte_identical"] else "not-identical"
        print(
            f"{row['id']}: {row['run_key']} | {row['source_key']} -> {row['target_key']} | "
            f"UID {row['uid_before_hex']} -> {row['uid_after_hex']} | "
            f"blocks {row['blocks_written']} | {row['status']} | {match} | "
            f"SHA-256 {row['source_dump_sha256']} | {row['executed_at']}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite database path")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init", help="Create or update the schema")
    database_backup = subparsers.add_parser(
        "database-backup", help="Create a verified private SQLite backup and sidecar manifest"
    )
    database_backup.add_argument("--output", type=Path)
    database_backup.add_argument("--notes")
    subparsers.add_parser("database-backups", help="List verified SQLite backups")
    database_restore = subparsers.add_parser(
        "database-restore", help="Restore a sidecar-verified backup after creating a guard backup"
    )
    database_restore.add_argument("--backup", type=Path, required=True)
    database_restore.add_argument("--confirm", action="store_true")

    project_add = subparsers.add_parser("project-add", help="Add a project")
    project_add.add_argument("--key", required=True)
    project_add.add_argument("--name", required=True)
    project_add.add_argument("--description", required=True)
    project_add.add_argument(
        "--purpose", choices=("education", "home", "education_and_home"), required=True
    )
    project_add.add_argument("--owner", required=True)
    project_add.add_argument("--authorization-policy", required=True)
    project_add.add_argument("--scope-notes")
    subparsers.add_parser("projects", help="List projects")

    device_add = subparsers.add_parser("device-add", help="Register a device without granting access")
    device_add.add_argument("--project", default=DEFAULT_PROJECT_KEY)
    device_add.add_argument("--key", required=True)
    device_add.add_argument("--name", required=True)
    device_add.add_argument(
        "--kind",
        choices=(
            "rfid_reader",
            "rfid_tag",
            "rfid_card",
            "rfid_key_fob",
            "access_controller",
            "lock",
            "computer",
            "embedded_device",
            "network_device",
            "test_equipment",
            "other",
        ),
        required=True,
    )
    device_add.add_argument("--role", choices=("tool", "target", "credential", "support"), required=True)
    device_add.add_argument(
        "--ownership",
        choices=("user_owned", "household_owned", "authorized_external", "user_authorized", "unspecified"),
        required=True,
    )
    device_add.add_argument("--manufacturer")
    device_add.add_argument("--model")
    device_add.add_argument("--type", dest="device_type", help="Registered device type key; defaults from --kind")
    device_add.add_argument("--serial")
    device_add.add_argument("--interface")
    device_add.add_argument("--location")
    device_add.add_argument("--sensitivity", choices=("normal", "sensitive", "critical"), default="sensitive")
    device_add.add_argument("--scope", default="Pending explicit per-device authorization")
    devices = subparsers.add_parser("devices", help="List registered devices")
    devices.add_argument("--project")
    subparsers.add_parser("device-types", help="List registered device types")
    device_type_add = subparsers.add_parser("device-type-add", help="Add or update a device type")
    device_type_add.add_argument("--key", required=True)
    device_type_add.add_argument(
        "--category", choices=("rfid", "access", "computing", "embedded", "sensor", "network", "test", "generic"), required=True
    )
    device_type_add.add_argument("--name", required=True)
    device_type_add.add_argument("--kind", choices=tuple(DEFAULT_DEVICE_TYPES), required=True)
    device_type_add.add_argument("--description", required=True)
    device_type_contract_set = subparsers.add_parser(
        "device-type-contract-set", help="Set an advisory or strict data contract for one device type"
    )
    device_type_contract_set.add_argument("--type", required=True)
    device_type_contract_set.add_argument("--enforcement", choices=("advisory", "strict"), required=True)
    device_type_contract_set.add_argument("--capabilities-json", required=True)
    device_type_contract_set.add_argument("--information-schema-json", required=True)
    device_type_contract_set.add_argument("--measurement-schema-json", required=True)
    device_type_contract_set.add_argument("--source", required=True)
    device_type_contract_set.add_argument("--notes")
    device_type_contracts = subparsers.add_parser(
        "device-type-contracts", help="List registered device type data contracts"
    )
    device_type_contracts.add_argument("--type")
    device_show = subparsers.add_parser("device-show", help="Show one device without secrets")
    device_show.add_argument("--device", required=True)
    device_show.add_argument("--reveal-sensitive", action="store_true")

    device_script_add = subparsers.add_parser(
        "device-script-add", help="Register one reviewed device script for CLI-only execution"
    )
    device_script_add.add_argument("--device", required=True)
    device_script_add.add_argument("--key", required=True)
    device_script_add.add_argument("--name", required=True)
    device_script_add.add_argument("--description", required=True)
    device_script_add.add_argument("--path", type=Path, required=True)
    device_script_add.add_argument("--operation", choices=FULL_AUTHORIZED_OPERATIONS, required=True)
    device_script_add.add_argument(
        "--risk", choices=("read_only", "state_change", "destructive"), required=True
    )
    device_script_add.add_argument("--timeout", type=int, default=60)
    device_script_add.add_argument("--non-interactive", action="store_true")
    device_scripts = subparsers.add_parser("device-scripts", help="List registered device scripts")
    device_scripts.add_argument("--device", required=True)
    device_script_run = subparsers.add_parser(
        "device-script-run", help="Run one registered device script through the audited CLI"
    )
    device_script_run.add_argument("script_key")
    device_script_run.add_argument("--project", required=True)
    device_script_run.add_argument("--device", required=True)

    identifier_add = subparsers.add_parser("device-identifier-add", help="Store one device identifier")
    identifier_add.add_argument("--device", required=True)
    identifier_add.add_argument("--kind", required=True)
    identifier_add.add_argument("--value", required=True)
    identifier_add.add_argument("--scope", default="")
    identifier_add.add_argument("--classification", choices=("normal", "sensitive", "critical"), default="sensitive")
    identifier_add.add_argument("--source", required=True)
    identifier_add.add_argument("--status", choices=("active", "historical", "revoked"), default="active")
    identifier_add.add_argument("--observed-at")
    identifier_add.add_argument("--notes")

    information_set = subparsers.add_parser("device-information-set", help="Store one sourced device fact or observation")
    information_set.add_argument("--device", required=True)
    information_set.add_argument("--kind", choices=("configuration", "fact", "observation", "service"), required=True)
    information_set.add_argument("--property", required=True)
    information_set.add_argument("--value-json", required=True)
    information_set.add_argument("--unit")
    information_set.add_argument("--source", required=True)
    information_set.add_argument("--confidence", choices=("reported", "observed", "verified", "low"), default="reported")
    information_set.add_argument("--classification", choices=("normal", "sensitive", "critical"), default="normal")
    information_set.add_argument("--historical", action="store_true")
    information_set.add_argument("--observed-at")
    information_set.add_argument("--notes")
    information = subparsers.add_parser("device-information", help="List current sourced device information")
    information.add_argument("--device", required=True)
    information.add_argument("--history", action="store_true")

    interface_set = subparsers.add_parser("device-interface-set", help="Store one non-secret device interface")
    interface_set.add_argument("--device", required=True)
    interface_set.add_argument("--key", required=True)
    interface_set.add_argument("--type", dest="interface_type", required=True)
    interface_set.add_argument("--endpoint")
    interface_set.add_argument("--address")
    interface_set.add_argument("--authentication-type")
    interface_set.add_argument("--secret-reference")
    interface_set.add_argument("--status", choices=("active", "inactive", "historical"), default="active")
    interface_set.add_argument("--details-json", default="{}")
    interface_set.add_argument("--source", required=True)
    interface_set.add_argument("--observed-at")
    interface_set.add_argument("--notes")
    interfaces = subparsers.add_parser("device-interfaces", help="List device interfaces without secret references")
    interfaces.add_argument("--device", required=True)

    relation_add = subparsers.add_parser("device-relation-add", help="Link two different registered devices")
    relation_add.add_argument("--source-device", required=True)
    relation_add.add_argument("--target-device", required=True)
    relation_add.add_argument("--type", dest="relation_type", required=True)
    relation_add.add_argument("--source", required=True)
    relation_add.add_argument("--status", choices=("active", "historical", "removed"), default="active")
    relation_add.add_argument("--observed-at")
    relation_add.add_argument("--notes")
    relation_type_add = subparsers.add_parser(
        "relation-type-add", help="Register or update a controlled device relation type"
    )
    relation_type_add.add_argument("--type", required=True)
    relation_type_add.add_argument("--name", required=True)
    relation_type_add.add_argument("--description", required=True)
    relation_type_add.add_argument("--bidirectional", action="store_true")
    subparsers.add_parser("relation-types", help="List controlled device relation types")

    component_set = subparsers.add_parser("device-component-set", help="Store one device component or service")
    component_set.add_argument("--device", required=True)
    component_set.add_argument("--key", required=True)
    component_set.add_argument("--kind", choices=("hardware", "firmware", "software", "service", "sensor_module", "other"), required=True)
    component_set.add_argument("--name", required=True)
    component_set.add_argument("--version")
    component_set.add_argument("--status", choices=("active", "inactive", "historical"), default="active")
    component_set.add_argument("--details-json", default="{}")
    component_set.add_argument("--source", required=True)
    component_set.add_argument("--observed-at")
    component_set.add_argument("--notes")

    rfid_profile = subparsers.add_parser("rfid-profile-set", help="Store RFID-specific data for one RFID device")
    rfid_profile.add_argument("--device", required=True)
    rfid_profile.add_argument("--kind", choices=("reader", "tag", "card", "key_fob", "controller", "other"), required=True)
    rfid_profile.add_argument("--frequency-mhz", type=float)
    rfid_profile.add_argument("--standard")
    rfid_profile.add_argument("--technology")
    rfid_profile.add_argument("--product-family")
    rfid_profile.add_argument("--chip-vendor")
    rfid_profile.add_argument("--chip-model")
    rfid_profile.add_argument("--technical-json", default="{}")
    rfid_profile.add_argument("--source", required=True)
    rfid_profile.add_argument("--observed-at")
    rfid_profile.add_argument("--notes")

    channel_add = subparsers.add_parser("measurement-channel-add", help="Register one numeric device measurement channel")
    channel_add.add_argument("--device", required=True)
    channel_add.add_argument("--key", required=True)
    channel_add.add_argument("--name", required=True)
    channel_add.add_argument("--quantity", required=True)
    channel_add.add_argument("--unit", required=True)
    channel_add.add_argument("--minimum", type=float)
    channel_add.add_argument("--maximum", type=float)
    channel_add.add_argument("--retention-days", type=int)
    channel_add.add_argument("--source", required=True)
    channel_add.add_argument("--observed-at")
    channel_add.add_argument("--notes")
    measurement_add = subparsers.add_parser("measurement-add", help="Store one sourced numeric measurement")
    measurement_add.add_argument("--device", required=True)
    measurement_add.add_argument("--channel", required=True)
    measurement_add.add_argument("--observed-at", required=True)
    measurement_add.add_argument("--value", type=float, required=True)
    measurement_add.add_argument("--quality", choices=("valid", "estimated", "invalid"), default="valid")
    measurement_add.add_argument("--source", required=True)
    measurement_add.add_argument("--notes")
    measurements = subparsers.add_parser("measurements", help="List stored device measurements")
    measurements.add_argument("--device", required=True)
    measurements.add_argument("--channel", required=True)
    measurements.add_argument("--limit", type=int, default=20)
    measurement_retention = subparsers.add_parser(
        "measurement-retention", help="Preview or apply declared measurement retention policies"
    )
    measurement_retention.add_argument("--apply", action="store_true")
    measurement_retention.add_argument("--confirm", action="store_true")
    audit_output_retention = subparsers.add_parser(
        "audit-output-retention", help="Preview or purge old audited command output"
    )
    audit_output_retention.add_argument("--apply", action="store_true")
    audit_output_retention.add_argument("--confirm", action="store_true")

    access_grant = subparsers.add_parser("access-grant", help="Grant access to one registered device")
    access_grant.add_argument("--project", default=DEFAULT_PROJECT_KEY)
    access_grant.add_argument("--device", required=True)
    access_grant.add_argument("--key", required=True)
    access_grant.add_argument("--subject", required=True)
    access_grant.add_argument(
        "--basis",
        choices=(
            "user_declaration",
            "self_owned",
            "household_owner",
            "explicit_permission",
            "contract",
            "employer_authorization",
        ),
        required=True,
    )
    access_grant.add_argument(
        "--level", choices=("observe", "read", "test", "write", "admin", "full"), required=True
    )
    access_grant.add_argument("--operation", action="append", required=True)
    access_grant.add_argument(
        "--purpose", choices=("education", "home", "education_and_home"), required=True
    )
    access_grant.add_argument("--evidence", required=True)
    access_grant.add_argument("--valid-from", required=True)
    access_grant.add_argument("--valid-until")
    access_grant.add_argument("--notes")
    accesses = subparsers.add_parser("accesses", help="List device authorizations")
    accesses.add_argument("--project")
    access_check = subparsers.add_parser("access-check", help="Check active access for one device")
    access_check.add_argument("--project", default=DEFAULT_PROJECT_KEY)
    access_check.add_argument("--device", required=True)
    access_method_set = subparsers.add_parser("access-method-set", help="Store one technical access method without a secret")
    access_method_set.add_argument("--project", default=DEFAULT_PROJECT_KEY)
    access_method_set.add_argument("--device", required=True)
    access_method_set.add_argument("--key", required=True)
    access_method_set.add_argument("--type", choices=("usb_serial", "local", "ssh", "web", "api", "rfid", "bluetooth", "other"), required=True)
    access_method_set.add_argument("--endpoint")
    access_method_set.add_argument("--account-label")
    access_method_set.add_argument("--authentication-type")
    access_method_set.add_argument("--secret-reference")
    access_method_set.add_argument("--status", choices=("active", "inactive", "blocked"), default="active")
    access_method_set.add_argument("--notes")
    access_methods = subparsers.add_parser("access-methods", help="List technical access methods without secret references")
    access_methods.add_argument("--project", default=DEFAULT_PROJECT_KEY)
    access_methods.add_argument("--device", required=True)

    pm3_probe = subparsers.add_parser("pm3-probe", help="Check the registered Proxmark3 access path")
    pm3_probe.add_argument("--project", default=DEFAULT_PROJECT_KEY)
    pm3_probe.add_argument("--device", default=rfid_device.DEFAULT_READER_KEY)
    pm3_probe.add_argument("--client", type=Path)
    pm3_probe.add_argument("--port", type=Path)
    pm3_probe.add_argument("--via", choices=("local", "raspberry-ssh"), default="local")
    pm3_probe.add_argument("--bridge-project", default="home-infrastructure")
    pm3_probe.add_argument("--bridge-device", default="computer:raspberry-pi-3")
    pm3_probe.add_argument("--json", action="store_true")

    pm3_fix = subparsers.add_parser(
        "pm3-fix-permissions",
        help="Show or interactively apply the Proxmark3 Linux permission repair",
    )
    pm3_fix.add_argument("--project", default=DEFAULT_PROJECT_KEY)
    pm3_fix.add_argument("--device", default=rfid_device.DEFAULT_READER_KEY)
    pm3_fix.add_argument("--client", type=Path)
    pm3_fix.add_argument("--port", type=Path)
    pm3_fix.add_argument("--apply", action="store_true")

    subparsers.add_parser("pm3-commands", help="List reusable Proxmark3 commands")
    pm3_command_add = subparsers.add_parser(
        "pm3-command-add", help="Add a reusable Proxmark3 command to SQLite"
    )
    pm3_command_add.add_argument("--key", required=True)
    pm3_command_add.add_argument("--name", required=True)
    pm3_command_add.add_argument("--description", required=True)
    pm3_command_add.add_argument("--command", dest="command_text", required=True)
    pm3_command_add.add_argument(
        "--operation",
        choices=("identify", "inspect", "read", "analyze", "test", "write", "configure", "administer"),
        required=True,
    )
    pm3_command_add.add_argument(
        "--risk", choices=("read_only", "state_change", "destructive"), required=True
    )
    pm3_command_add.add_argument("--timeout", type=int, default=60)

    pm3_run = subparsers.add_parser("pm3-run", help="Run one reusable Proxmark3 command")
    pm3_run.add_argument("command_key")
    pm3_run.add_argument("--project", default=DEFAULT_PROJECT_KEY)
    pm3_run.add_argument("--device", default=rfid_device.DEFAULT_READER_KEY)
    pm3_run.add_argument("--client", type=Path)
    pm3_run.add_argument("--port", type=Path)
    pm3_run.add_argument("--timeout", type=int)
    pm3_run.add_argument("--via", choices=("local", "raspberry-ssh"), default="local")
    pm3_run.add_argument("--bridge-project", default="home-infrastructure")
    pm3_run.add_argument("--bridge-device", default="computer:raspberry-pi-3")

    pm3_backup = subparsers.add_parser(
        "pm3-firmware-backup",
        help="Create an audited read-only backup of the Proxmark3 MCU flash",
    )
    pm3_backup.add_argument("--project", default=DEFAULT_PROJECT_KEY)
    pm3_backup.add_argument("--device", default=rfid_device.DEFAULT_READER_KEY)
    pm3_backup.add_argument("--client", type=Path)
    pm3_backup.add_argument("--port", type=Path)
    pm3_backup.add_argument("--output", type=Path, required=True)
    pm3_backup.add_argument("--length", type=int, default=512 * 1024)
    pm3_backup.add_argument("--timeout", type=int, default=120)

    pm3_flash = subparsers.add_parser(
        "pm3-firmware-flash",
        help="Flash audited Proxmark3 ELF images after an explicit confirmation",
    )
    pm3_flash.add_argument("--project", default=DEFAULT_PROJECT_KEY)
    pm3_flash.add_argument("--device", default=rfid_device.DEFAULT_READER_KEY)
    pm3_flash.add_argument("--client", type=Path)
    pm3_flash.add_argument("--port", type=Path)
    pm3_flash.add_argument("--fullimage", type=Path)
    pm3_flash.add_argument("--bootrom", type=Path)
    pm3_flash.add_argument("--timeout", type=int, default=180)
    pm3_flash.add_argument(
        "--force",
        action="store_true",
        help="Allow a deliberate client and firmware version transition",
    )
    pm3_flash.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm that the selected firmware image may change the device",
    )

    pm3_history = subparsers.add_parser("pm3-history", help="List audited Proxmark3 CLI runs")
    pm3_history.add_argument("--limit", type=int, default=20)

    importer = subparsers.add_parser("import-mfc", help="Import one verified MIFARE Classic 1K read")
    importer.add_argument("--run-key", required=True)
    importer.add_argument("--read-at", required=True)
    importer.add_argument("--label", required=True)
    importer.add_argument("--dump", type=Path, required=True)
    importer.add_argument("--verification-dump", type=Path, required=True)
    importer.add_argument("--json", type=Path, required=True)
    importer.add_argument("--verification-json", type=Path, required=True)
    importer.add_argument("--keys", type=Path, required=True)
    importer.add_argument("--log", type=Path, action="append", default=[])

    clone_record = subparsers.add_parser("clone-record", help="Store one verified RFID clone operation")
    clone_record.add_argument("--run-key", required=True)
    clone_record.add_argument("--executed-at", required=True)
    clone_record.add_argument("--source-device", required=True)
    clone_record.add_argument("--target-device", required=True)
    clone_record.add_argument("--source-read", required=True)
    clone_record.add_argument("--uid-before", required=True)
    clone_record.add_argument("--uid-after", required=True)
    clone_record.add_argument("--factory-dump", type=Path, required=True)
    clone_record.add_argument("--factory-json", type=Path, required=True)
    clone_record.add_argument("--magic-dump", type=Path, required=True)
    clone_record.add_argument("--magic-json", type=Path, required=True)
    clone_record.add_argument("--standard-dump", type=Path, required=True)
    clone_record.add_argument("--standard-json", type=Path, required=True)
    clone_record.add_argument("--log", type=Path, action="append", default=[])
    clone_record.add_argument("--extra-artifact", type=Path, action="append", default=[])
    subparsers.add_parser("clones", help="List stored clone operations")

    subparsers.add_parser("list", help="List stored RFID elements")
    show = subparsers.add_parser("show", help="Show one stored element")
    show.add_argument("element_id", type=int)
    show.add_argument("--reveal-keys", action="store_true")
    show.add_argument("--reveal-sensitive", action="store_true")
    subparsers.add_parser("verify", help="Verify SQLite and stored content hashes")
    return parser


def main() -> int:
    os.umask(0o077)
    args = build_parser().parse_args()
    connection = open_database(args.db)
    try:
        if args.command in {"init", "import-mfc", "clone-record"}:
            initialize(connection)
        else:
            require_schema(connection)
        if args.command == "import-mfc":
            read_id = import_mfc(
                connection,
                run_key=args.run_key,
                read_at=args.read_at,
                label=args.label,
                dump_path=args.dump,
                verification_dump_path=args.verification_dump,
                json_path=args.json,
                verification_json_path=args.verification_json,
                key_path=args.keys,
                log_paths=args.log,
            )
            print(f"Imported verified read {read_id} into {args.db}")
        elif args.command == "clone-record":
            operation_id = record_clone(
                connection,
                run_key=args.run_key,
                executed_at=args.executed_at,
                source_device_key=args.source_device,
                target_device_key=args.target_device,
                source_read_run_key=args.source_read,
                uid_before_hex=args.uid_before,
                uid_after_hex=args.uid_after,
                factory_dump_path=args.factory_dump,
                factory_json_path=args.factory_json,
                magic_dump_path=args.magic_dump,
                magic_json_path=args.magic_json,
                standard_dump_path=args.standard_dump,
                standard_json_path=args.standard_json,
                log_paths=args.log,
                extra_artifact_paths=args.extra_artifact,
            )
            print(f"Stored verified clone operation {operation_id} in {args.db}")
        elif args.command == "database-backup":
            backup = create_database_backup(
                connection,
                output_path=args.output,
                notes=args.notes,
            )
            print(
                f"Verified database backup: {backup['path']} | size={backup['size_bytes']} | "
                f"SHA-256 {backup['sha256']} | manifest={backup['manifest_path']}"
            )
        elif args.command == "database-backups":
            print_database_backups(connection)
        elif args.command == "database-restore":
            if not args.confirm:
                raise ValueError("Database restore is destructive; rerun with --confirm after selecting the backup")
            database_path = connection_database_path(connection)
            guard_backup = create_database_backup(
                connection,
                notes="Automatic guard backup before database restore.",
            )
            connection.close()
            restored = restore_database_backup(database_path, args.backup)
            print(
                f"Restored database from {restored['path']} to {restored['restored_to']} | "
                f"guard backup={guard_backup['path']}"
            )
            return 0
        elif args.command == "project-add":
            project_id = create_project(
                connection,
                project_key=args.key,
                name=args.name,
                description=args.description,
                purpose=args.purpose,
                owner_subject=args.owner,
                authorization_policy=args.authorization_policy,
                scope_notes=args.scope_notes,
            )
            connection.commit()
            print(f"Stored project {project_id}: {args.key}")
        elif args.command == "projects":
            print_projects(connection)
        elif args.command == "device-add":
            device_id = add_device(
                connection,
                project_key=args.project,
                device_key=args.key,
                name=args.name,
                device_kind=args.kind,
                role=args.role,
                ownership_status=args.ownership,
                manufacturer=args.manufacturer,
                model=args.model,
                serial_number=args.serial,
                interface=args.interface,
                location_label=args.location,
                sensitivity=args.sensitivity,
                device_type_key=args.device_type,
                scope=args.scope,
            )
            authorization = connection.execute(
                "SELECT 1 FROM active_authorized_devices WHERE project_key = ? AND device_key = ?",
                (catalog_key(args.project), catalog_key(args.key)),
            ).fetchone()
            authorization_status = "active" if authorization is not None else "pending"
            print(f"Stored device {device_id}: {args.key}; authorization is {authorization_status}")
        elif args.command == "devices":
            print_devices(connection, args.project)
        elif args.command == "device-types":
            print_device_types(connection)
        elif args.command == "device-type-add":
            type_key = add_device_type(
                connection,
                type_key=args.key,
                display_name=args.name,
                category=args.category,
                default_device_kind=args.kind,
                description=args.description,
            )
            print(f"Stored device type: {type_key}")
        elif args.command == "device-type-contract-set":
            type_key = set_device_type_contract(
                connection,
                type_key=args.type,
                enforcement=args.enforcement,
                capabilities_json=args.capabilities_json,
                information_schema_json=args.information_schema_json,
                measurement_schema_json=args.measurement_schema_json,
                source_reference=args.source,
                notes=args.notes,
            )
            print(f"Stored device type contract: {type_key}")
        elif args.command == "device-type-contracts":
            print_device_type_contracts(connection, args.type)
        elif args.command == "device-show":
            print_device_detail(connection, args.device, args.reveal_sensitive)
        elif args.command == "device-script-add":
            script_id = add_device_script(
                connection,
                script_key=args.key,
                device_key=args.device,
                display_name=args.name,
                description=args.description,
                script_path=args.path,
                required_operation=args.operation,
                risk_level=args.risk,
                timeout_seconds=args.timeout,
                interactive=not args.non_interactive,
            )
            print(f"Stored managed device script {script_id}: {args.key}")
        elif args.command == "device-scripts":
            print_device_scripts(connection, args.device)
        elif args.command == "device-script-run":
            result = run_device_script(
                connection,
                script_key=args.script_key,
                project_key=args.project,
                device_key=args.device,
            )
            print(
                f"Audit run: {result['run_key']} | status={result['status']} | exit={result['exit_code']}",
                file=sys.stderr,
            )
            if result["error_message"]:
                print(f"CLI diagnosis: {result['error_message']}", file=sys.stderr)
            if result["status"] != "succeeded":
                return 2 if result["status"] == "blocked" else result["exit_code"] or 1
        elif args.command == "device-identifier-add":
            identifier_id = add_device_identifier(
                connection,
                device_key=args.device,
                identifier_kind=args.kind,
                identifier_value=args.value,
                identifier_scope=args.scope,
                classification=args.classification,
                source_reference=args.source,
                status=args.status,
                observed_at=args.observed_at,
                notes=args.notes,
            )
            print(f"Stored device identifier {identifier_id}")
        elif args.command == "device-information-set":
            information_id = set_device_information(
                connection,
                device_key=args.device,
                information_kind=args.kind,
                property_key=args.property,
                value_json=args.value_json,
                unit=args.unit,
                source_reference=args.source,
                confidence=args.confidence,
                classification=args.classification,
                is_current=not args.historical,
                observed_at=args.observed_at,
                notes=args.notes,
            )
            print(f"Stored device information {information_id}")
        elif args.command == "device-information":
            print_device_information(connection, args.device, args.history)
        elif args.command == "device-interface-set":
            interface_id = set_device_interface(
                connection,
                device_key=args.device,
                interface_key=args.key,
                interface_type=args.interface_type,
                endpoint=args.endpoint,
                address=args.address,
                authentication_type=args.authentication_type,
                secret_reference=args.secret_reference,
                status=args.status,
                details_json=args.details_json,
                source_reference=args.source,
                observed_at=args.observed_at,
                notes=args.notes,
            )
            print(f"Stored device interface {interface_id}")
        elif args.command == "device-interfaces":
            print_device_interfaces(connection, args.device)
        elif args.command == "device-relation-add":
            relation_id = add_device_relation(
                connection,
                source_device_key=args.source_device,
                target_device_key=args.target_device,
                relation_type=args.relation_type,
                source_reference=args.source,
                status=args.status,
                observed_at=args.observed_at,
                notes=args.notes,
            )
            print(f"Stored device relation {relation_id}")
        elif args.command == "relation-type-add":
            relation_type = add_relation_type(
                connection,
                relation_type=args.type,
                display_name=args.name,
                description=args.description,
                directional=not args.bidirectional,
            )
            print(f"Stored device relation type: {relation_type}")
        elif args.command == "relation-types":
            print_relation_types(connection)
        elif args.command == "device-component-set":
            component_id = set_device_component(
                connection,
                device_key=args.device,
                component_key=args.key,
                component_kind=args.kind,
                name=args.name,
                version=args.version,
                status=args.status,
                details_json=args.details_json,
                source_reference=args.source,
                observed_at=args.observed_at,
                notes=args.notes,
            )
            print(f"Stored device component {component_id}")
        elif args.command == "rfid-profile-set":
            device_id = set_rfid_profile(
                connection,
                device_key=args.device,
                profile_kind=args.kind,
                frequency_mhz=args.frequency_mhz,
                standard=args.standard,
                technology=args.technology,
                product_family=args.product_family,
                chip_vendor=args.chip_vendor,
                chip_model=args.chip_model,
                technical_json=args.technical_json,
                source_reference=args.source,
                observed_at=args.observed_at,
                notes=args.notes,
            )
            print(f"Stored RFID profile for device {device_id}")
        elif args.command == "measurement-channel-add":
            channel_id = add_measurement_channel(
                connection,
                device_key=args.device,
                channel_key=args.key,
                display_name=args.name,
                quantity_kind=args.quantity,
                unit=args.unit,
                minimum_value=args.minimum,
                maximum_value=args.maximum,
                retention_days=args.retention_days,
                source_reference=args.source,
                observed_at=args.observed_at,
                notes=args.notes,
            )
            print(f"Stored measurement channel {channel_id}")
        elif args.command == "measurement-add":
            sample_id = add_measurement_sample(
                connection,
                device_key=args.device,
                channel_key=args.channel,
                observed_at=args.observed_at,
                value_real=args.value,
                quality=args.quality,
                source_reference=args.source,
                notes=args.notes,
            )
            print(f"Stored measurement sample {sample_id}")
        elif args.command == "measurements":
            if args.limit < 1 or args.limit > 1000:
                raise ValueError("Measurement limit must be between 1 and 1000")
            print_measurements(connection, args.device, args.channel, args.limit)
        elif args.command == "measurement-retention":
            if args.apply and not args.confirm:
                raise ValueError("Measurement retention deletes data; rerun with --apply --confirm")
            result = run_measurement_retention(connection, apply=args.apply)
            print(
                f"Measurement retention {result['mode']}: channels={result['channel_count']} | "
                f"candidates={result['candidate_count']} | deleted={result['deleted_count']} | "
                f"audit={result['run_key']}"
            )
        elif args.command == "audit-output-retention":
            if args.apply and not args.confirm:
                raise ValueError("Audit output retention deletes stored output; rerun with --apply --confirm")
            result = run_audit_output_retention(connection, apply=args.apply)
            print(
                f"Audit output retention {result['mode']}: candidates={result['candidate_count']} | "
                f"purged={result['purged_count']} | audit={result['run_key']}"
            )
        elif args.command == "access-grant":
            authorization_id = grant_access(
                connection,
                project_key=args.project,
                device_key=args.device,
                authorization_key=args.key,
                subject=args.subject,
                authorization_basis=args.basis,
                access_level=args.level,
                operations=args.operation,
                purpose=args.purpose,
                evidence_reference=args.evidence,
                valid_from=args.valid_from,
                valid_until=args.valid_until,
                notes=args.notes,
            )
            print(f"Stored active authorization {authorization_id}: {args.key}")
        elif args.command == "accesses":
            print_accesses(connection, args.project)
        elif args.command == "access-check":
            if not check_access(connection, args.project, args.device):
                return 2
        elif args.command == "access-method-set":
            method_id = set_access_method(
                connection,
                project_key=args.project,
                device_key=args.device,
                method_key=args.key,
                method_type=args.type,
                endpoint=args.endpoint,
                account_label=args.account_label,
                authentication_type=args.authentication_type,
                secret_reference=args.secret_reference,
                status=args.status,
                notes=args.notes,
                source_reference="cli:access-method-set",
            )
            print(f"Stored access method {method_id}")
        elif args.command == "access-methods":
            print_access_methods(connection, args.project, args.device)
        elif args.command == "pm3-probe":
            result = rfid_device.probe(
                connection,
                project_key=args.project,
                device_key=args.device,
                client_path=args.client,
                port_path=args.port,
                transport=args.via,
                bridge_project_key=args.bridge_project,
                bridge_device_key=args.bridge_device,
            )
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
            else:
                for line in rfid_device.probe_lines(result):
                    print(line)
            if not result["ready"]:
                return 2
        elif args.command == "pm3-fix-permissions":
            result = rfid_device.probe(
                connection,
                project_key=args.project,
                device_key=args.device,
                client_path=args.client,
                port_path=args.port,
            )
            commands = rfid_device.permission_repair_commands(result)
            if not commands:
                print("No permission repair is required.")
            elif not args.apply:
                print("Permission repair plan:")
                for command in commands:
                    print(shlex.join(command))
                print("Run this command again with --apply in an interactive terminal to apply the plan.")
            else:
                rfid_device.apply_permission_repair(result)
                refreshed = rfid_device.probe(
                    connection,
                    project_key=args.project,
                    device_key=args.device,
                    client_path=args.client,
                    port_path=args.port,
                )
                for line in rfid_device.probe_lines(refreshed):
                    print(line)
                if not refreshed["ready"]:
                    return 2
        elif args.command == "pm3-commands":
            for command in rfid_device.list_commands(connection):
                builtin = "builtin" if command["builtin"] else "custom"
                print(
                    f"{command['command_key']}: {command['command_text']} | "
                    f"operation={command['required_operation']} | risk={command['risk_level']} | "
                    f"timeout={command['timeout_seconds']}s | {builtin}"
                )
        elif args.command == "pm3-command-add":
            command_id = rfid_device.add_command(
                connection,
                key=args.key,
                name=args.name,
                description=args.description,
                text=args.command_text,
                operation=args.operation,
                risk_level=args.risk,
                timeout_seconds=args.timeout,
            )
            print(f"Stored reusable Proxmark3 command {command_id}: {args.key}")
        elif args.command == "pm3-run":
            result = rfid_device.run_named_command(
                connection,
                key=args.command_key,
                project_key=args.project,
                device_key=args.device,
                client_path=args.client,
                port_path=args.port,
                timeout_seconds=args.timeout,
                transport=args.via,
                bridge_project_key=args.bridge_project,
                bridge_device_key=args.bridge_device,
            )
            if result["stdout"]:
                sys.stdout.buffer.write(result["stdout"])
                sys.stdout.buffer.flush()
            if result["stderr"]:
                sys.stderr.buffer.write(result["stderr"])
                sys.stderr.buffer.flush()
            print(
                f"Audit run: {result['run_key']} | status={result['status']} | exit={result['exit_code']}",
                file=sys.stderr,
            )
            if result["error_message"]:
                print(f"CLI diagnosis: {result['error_message']}", file=sys.stderr)
            if result["status"] != "succeeded":
                return result["exit_code"] or 1
        elif args.command == "pm3-firmware-backup":
            result = rfid_device.backup_device_memory(
                connection,
                output_path=args.output,
                project_key=args.project,
                device_key=args.device,
                client_path=args.client,
                port_path=args.port,
                length=args.length,
                timeout_seconds=args.timeout,
            )
            if result["stdout"]:
                sys.stdout.buffer.write(result["stdout"])
                sys.stdout.buffer.flush()
            if result["stderr"]:
                sys.stderr.buffer.write(result["stderr"])
                sys.stderr.buffer.flush()
            print(
                f"Audit run: {result['run_key']} | status={result['status']} | exit={result['exit_code']}",
                file=sys.stderr,
            )
            if result["error_message"]:
                print(f"CLI diagnosis: {result['error_message']}", file=sys.stderr)
            if result["status"] != "succeeded":
                return result["exit_code"] or 1
            print(
                f"Firmware backup: {result['path']} | size={result['size']} | SHA-256 {result['sha256']}"
            )
        elif args.command == "pm3-firmware-flash":
            result = rfid_device.flash_firmware(
                connection,
                fullimage_path=args.fullimage,
                bootrom_path=args.bootrom,
                confirmed=args.confirm,
                force=args.force,
                project_key=args.project,
                device_key=args.device,
                client_path=args.client,
                port_path=args.port,
                timeout_seconds=args.timeout,
            )
            if result["stdout"]:
                sys.stdout.buffer.write(result["stdout"])
                sys.stdout.buffer.flush()
            if result["stderr"]:
                sys.stderr.buffer.write(result["stderr"])
                sys.stderr.buffer.flush()
            print(
                f"Audit run: {result['run_key']} | status={result['status']} | exit={result['exit_code']}",
                file=sys.stderr,
            )
            if result["error_message"]:
                print(f"CLI diagnosis: {result['error_message']}", file=sys.stderr)
            if result["status"] != "succeeded":
                return result["exit_code"] or 1
        elif args.command == "pm3-history":
            for run in rfid_device.run_history(connection, args.limit):
                print(
                    f"{run['run_key']}: {run['project_key']} / {run['device_key']} | "
                    f"{run['command_key'] or run['command_text']} | {run['required_operation']} | "
                    f"{run['status']} exit={run['exit_code']} | {run['duration_ms']}ms | {run['started_at']}"
                )
        elif args.command == "clones":
            print_clones(connection)
        elif args.command == "list":
            print_list(connection)
        elif args.command == "show":
            print_element(connection, args.element_id, args.reveal_keys, args.reveal_sensitive)
        elif args.command == "verify":
            problems = verify_database(connection)
            if problems:
                for problem in problems:
                    print(problem, file=sys.stderr)
                return 1
            print("OK: SQLite integrity, foreign keys, source files, and all stored hashes are valid.")
        elif args.command == "init":
            print(f"Initialized {args.db}")
    finally:
        connection.close()
        if args.db.exists():
            os.chmod(args.db, 0o600)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError, sqlite3.Error) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
