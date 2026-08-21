PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS schema_migrations (
    migration_key TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK(schema_version BETWEEN 1 AND 9999),
    script_sha256 TEXT NOT NULL CHECK(length(script_sha256) = 64),
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS device_type_contracts (
    device_type_key TEXT PRIMARY KEY REFERENCES device_types(type_key) ON DELETE RESTRICT,
    enforcement TEXT NOT NULL CHECK(enforcement IN ('advisory', 'strict')),
    capabilities_json TEXT NOT NULL DEFAULT '[]' CHECK(
        json_valid(capabilities_json) AND json_type(capabilities_json) = 'array'
    ),
    information_schema_json TEXT NOT NULL DEFAULT '{}' CHECK(
        json_valid(information_schema_json) AND json_type(information_schema_json) = 'object'
    ),
    measurement_schema_json TEXT NOT NULL DEFAULT '{}' CHECK(
        json_valid(measurement_schema_json) AND json_type(measurement_schema_json) = 'object'
    ),
    source_reference TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

INSERT OR IGNORE INTO device_type_contracts(
    device_type_key, enforcement, capabilities_json, information_schema_json,
    measurement_schema_json, source_reference, notes, created_at, updated_at
) VALUES (
    'sensor.temperature',
    'strict',
    '["measure.temperature"]',
    '{"calibration_offset_c":{"information_kinds":["configuration","fact"],"unit":"degC","value_type":"number"},"measurement_precision_c":{"information_kinds":["fact"],"unit":"degC","value_type":"number"}}',
    '{"temperature.c":{"maximum":125,"minimum":-55,"quantity_kind":"temperature","unit":"degC"}}',
    'schema:007_future_ready_inventory',
    'Standard contract for a temperature sensor.',
    '2026-08-15T00:00:00+02:00',
    '2026-08-15T00:00:00+02:00'
);

CREATE TABLE IF NOT EXISTS device_relation_types (
    relation_type TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    directional INTEGER NOT NULL CHECK(directional IN (0, 1)),
    status TEXT NOT NULL CHECK(status IN ('active', 'retired')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

INSERT OR IGNORE INTO device_relation_types(
    relation_type, display_name, description, directional, status, created_at, updated_at
) VALUES
    ('connected_to', 'Connected to', 'The source device has a physical or logical connection to the target device.', 1, 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('controlled_by', 'Controlled by', 'The target device controls the source device.', 1, 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('hosts', 'Hosts', 'The source device hosts a service or workload on the target device.', 1, 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('powered_by', 'Powered by', 'The source device receives power from the target device.', 1, 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('reads', 'Reads', 'The source device reads the target credential or RFID medium.', 1, 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('routes_for', 'Routes for', 'The source network device routes traffic for the target device.', 1, 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00');

INSERT OR IGNORE INTO device_relation_types(
    relation_type, display_name, description, directional, status, created_at, updated_at
)
SELECT DISTINCT relation_type, relation_type, 'Historical relation retained during schema v7 migration.',
       1, 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'
FROM device_relations;

CREATE TRIGGER IF NOT EXISTS device_relations_relation_type_insert
BEFORE INSERT ON device_relations
WHEN NOT EXISTS (
    SELECT 1 FROM device_relation_types
    WHERE relation_type = NEW.relation_type AND status = 'active'
)
BEGIN
    SELECT RAISE(ABORT, 'Device relation type is not active');
END;

CREATE TRIGGER IF NOT EXISTS device_relations_relation_type_update
BEFORE UPDATE OF relation_type ON device_relations
WHEN NOT EXISTS (
    SELECT 1 FROM device_relation_types
    WHERE relation_type = NEW.relation_type AND status = 'active'
)
BEGIN
    SELECT RAISE(ABORT, 'Device relation type is not active');
END;

ALTER TABLE device_scripts ADD COLUMN script_sha256 TEXT NOT NULL DEFAULT '' CHECK(
    length(script_sha256) = 0 OR length(script_sha256) = 64
);
ALTER TABLE device_scripts ADD COLUMN script_revision INTEGER NOT NULL DEFAULT 1 CHECK(script_revision >= 1);
ALTER TABLE device_commands ADD COLUMN output_retention_days INTEGER NOT NULL DEFAULT 90 CHECK(
    output_retention_days BETWEEN 1 AND 36500
);
ALTER TABLE device_command_runs ADD COLUMN executed_script_sha256 TEXT CHECK(
    executed_script_sha256 IS NULL OR length(executed_script_sha256) = 64
);
ALTER TABLE device_command_runs ADD COLUMN stdout_original_sha256 TEXT CHECK(
    stdout_original_sha256 IS NULL OR length(stdout_original_sha256) = 64
);
ALTER TABLE device_command_runs ADD COLUMN stderr_original_sha256 TEXT CHECK(
    stderr_original_sha256 IS NULL OR length(stderr_original_sha256) = 64
);
ALTER TABLE device_command_runs ADD COLUMN output_purged_at TEXT;

CREATE TABLE IF NOT EXISTS access_authorization_operations (
    authorization_id INTEGER NOT NULL REFERENCES access_authorizations(id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN (
        'identify', 'inspect', 'read', 'analyze', 'test', 'write', 'configure', 'administer'
    )),
    created_at TEXT NOT NULL,
    PRIMARY KEY(authorization_id, operation)
) STRICT;

INSERT OR IGNORE INTO access_authorization_operations(authorization_id, operation, created_at)
SELECT authorization.id, operation.value, authorization.created_at
FROM access_authorizations AS authorization
JOIN json_each(authorization.allowed_operations_json) AS operation
WHERE operation.value IN (
    'identify', 'inspect', 'read', 'analyze', 'test', 'write', 'configure', 'administer'
);

CREATE TABLE IF NOT EXISTS measurement_retention_runs (
    run_key TEXT PRIMARY KEY,
    mode TEXT NOT NULL CHECK(mode IN ('preview', 'applied')),
    executed_at TEXT NOT NULL,
    channel_count INTEGER NOT NULL CHECK(channel_count >= 0),
    candidate_count INTEGER NOT NULL CHECK(candidate_count >= 0),
    deleted_count INTEGER NOT NULL CHECK(deleted_count >= 0),
    status TEXT NOT NULL CHECK(status IN ('succeeded', 'failed')),
    notes TEXT,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS measurement_retention_results (
    run_key TEXT NOT NULL REFERENCES measurement_retention_runs(run_key) ON DELETE CASCADE,
    channel_id INTEGER NOT NULL REFERENCES measurement_channels(id) ON DELETE RESTRICT,
    cutoff_at TEXT NOT NULL,
    candidate_count INTEGER NOT NULL CHECK(candidate_count >= 0),
    deleted_count INTEGER NOT NULL CHECK(deleted_count >= 0),
    PRIMARY KEY(run_key, channel_id)
) STRICT;

CREATE TABLE IF NOT EXISTS audit_output_retention_runs (
    run_key TEXT PRIMARY KEY,
    mode TEXT NOT NULL CHECK(mode IN ('preview', 'applied')),
    executed_at TEXT NOT NULL,
    candidate_count INTEGER NOT NULL CHECK(candidate_count >= 0),
    purged_count INTEGER NOT NULL CHECK(purged_count >= 0),
    status TEXT NOT NULL CHECK(status IN ('succeeded', 'failed')),
    notes TEXT,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS database_backups (
    backup_key TEXT PRIMARY KEY,
    relative_path TEXT NOT NULL UNIQUE,
    manifest_relative_path TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    schema_version INTEGER NOT NULL CHECK(schema_version BETWEEN 1 AND 9999),
    status TEXT NOT NULL CHECK(status IN ('verified', 'restored', 'invalid')),
    created_at TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    notes TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS measurement_retention_results_channel_idx
    ON measurement_retention_results(channel_id, cutoff_at);
CREATE INDEX IF NOT EXISTS database_backups_created_idx
    ON database_backups(created_at DESC);

DROP VIEW active_authorized_devices;
CREATE VIEW active_authorized_devices AS
SELECT
    p.project_key,
    p.name AS project_name,
    d.device_key,
    d.name AS device_name,
    d.device_kind,
    d.device_type_key,
    a.authorization_key,
    a.subject,
    a.access_level,
    COALESCE((
        SELECT json_group_array(operation)
        FROM access_authorization_operations
        WHERE authorization_id = a.id
    ), '[]') AS allowed_operations_json,
    a.purpose,
    a.evidence_reference,
    a.valid_from,
    a.valid_until
FROM projects AS p
JOIN project_devices AS pd ON pd.project_id = p.id
JOIN devices AS d ON d.id = pd.device_id
JOIN access_authorizations AS a
  ON a.project_id = p.id AND a.device_id = d.id
WHERE p.status = 'active'
  AND pd.status = 'in_scope'
  AND d.lifecycle_status = 'active'
  AND a.status = 'active'
  AND datetime(a.valid_from) <= datetime('now')
  AND (a.valid_until IS NULL OR datetime(a.valid_until) > datetime('now'));

INSERT OR REPLACE INTO schema_info(key, value) VALUES
    ('schema_name', 'home_device_inventory'),
    ('schema_version', '7'),
    ('data_classification', 'sensitive_home_device_and_physical_access_inventory'),
    ('authorization_model', 'deny_by_default_per_project_and_device'),
    ('audit_output_retention_days', '90');

PRAGMA user_version = 7;
COMMIT;
