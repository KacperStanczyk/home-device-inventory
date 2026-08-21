PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS device_scripts (
    id INTEGER PRIMARY KEY,
    script_key TEXT NOT NULL UNIQUE,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    required_operation TEXT NOT NULL CHECK(required_operation IN (
        'identify', 'inspect', 'read', 'analyze', 'test', 'write', 'configure', 'administer'
    )),
    risk_level TEXT NOT NULL CHECK(risk_level IN ('read_only', 'state_change', 'destructive')),
    timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds BETWEEN 1 AND 3600),
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    interactive INTEGER NOT NULL CHECK(interactive IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(device_id, relative_path)
) STRICT;

CREATE INDEX IF NOT EXISTS device_scripts_device_idx
    ON device_scripts(device_id, enabled);

INSERT OR REPLACE INTO schema_info(key, value) VALUES
    ('schema_name', 'home_device_inventory'),
    ('schema_version', '6'),
    ('data_classification', 'sensitive_home_device_and_physical_access_inventory'),
    ('authorization_model', 'deny_by_default_per_project_and_device');

PRAGMA user_version = 6;
COMMIT;
