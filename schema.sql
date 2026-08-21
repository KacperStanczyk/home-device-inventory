PRAGMA foreign_keys = ON;
PRAGMA secure_delete = ON;

CREATE TABLE IF NOT EXISTS schema_info (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

INSERT OR REPLACE INTO schema_info(key, value) VALUES
    ('schema_name', 'home_device_inventory'),
    ('schema_version', '7'),
    ('data_classification', 'sensitive_home_device_and_physical_access_inventory'),
    ('authorization_model', 'deny_by_default_per_project_and_device'),
    ('audit_output_retention_days', '90');

CREATE TABLE IF NOT EXISTS schema_migrations (
    migration_key TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK(schema_version BETWEEN 1 AND 9999),
    script_sha256 TEXT NOT NULL CHECK(length(script_sha256) = 64),
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS readers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    device_path TEXT,
    connection TEXT,
    usb_vendor_id TEXT,
    usb_product_id TEXT,
    usb_serial TEXT UNIQUE,
    kernel_driver TEXT,
    client_name TEXT,
    client_version TEXT,
    firmware_bootrom TEXT,
    firmware_os TEXT,
    fpga_hf TEXT,
    hardware_model TEXT,
    mcu TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS elements (
    id INTEGER PRIMARY KEY,
    label TEXT NOT NULL,
    element_kind TEXT NOT NULL,
    ownership TEXT NOT NULL,
    authorized_use TEXT,
    frequency_mhz REAL,
    standard TEXT,
    technology TEXT,
    product_family TEXT,
    chip_vendor TEXT,
    chip_model TEXT,
    uid_hex TEXT NOT NULL,
    uid_bytes BLOB NOT NULL,
    uid_length INTEGER NOT NULL,
    uid_observation TEXT,
    atqa_hex TEXT,
    sak_hex TEXT,
    capacity_bytes INTEGER,
    sector_count INTEGER,
    block_count INTEGER,
    block_size INTEGER,
    prng TEXT,
    magic_uid_writable INTEGER,
    manufacturer_block_hex TEXT,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(technology, uid_hex)
) STRICT;

CREATE TABLE IF NOT EXISTS reads (
    id INTEGER PRIMARY KEY,
    run_key TEXT NOT NULL UNIQUE,
    element_id INTEGER NOT NULL REFERENCES elements(id) ON DELETE RESTRICT,
    reader_id INTEGER REFERENCES readers(id) ON DELETE SET NULL,
    read_at TEXT NOT NULL,
    status TEXT NOT NULL,
    method TEXT NOT NULL,
    tool_command TEXT NOT NULL,
    complete INTEGER NOT NULL,
    verified INTEGER NOT NULL,
    verification_method TEXT,
    dump_size INTEGER NOT NULL,
    dump_sha256 TEXT NOT NULL,
    key_file_sha256 TEXT,
    raw_dump BLOB NOT NULL,
    raw_json TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS reads_element_id_idx ON reads(element_id);
CREATE INDEX IF NOT EXISTS reads_dump_sha256_idx ON reads(dump_sha256);

CREATE TABLE IF NOT EXISTS sectors (
    read_id INTEGER NOT NULL REFERENCES reads(id) ON DELETE CASCADE,
    sector_number INTEGER NOT NULL,
    first_block INTEGER NOT NULL,
    trailer_block INTEGER NOT NULL,
    key_a_hex TEXT NOT NULL,
    key_b_hex TEXT NOT NULL,
    key_a_source TEXT,
    key_b_source TEXT,
    access_conditions_hex TEXT NOT NULL,
    access_conditions_json TEXT NOT NULL,
    user_data_hex TEXT,
    PRIMARY KEY(read_id, sector_number)
) STRICT;

CREATE TABLE IF NOT EXISTS blocks (
    read_id INTEGER NOT NULL REFERENCES reads(id) ON DELETE CASCADE,
    block_number INTEGER NOT NULL,
    sector_number INTEGER NOT NULL,
    block_in_sector INTEGER NOT NULL,
    block_role TEXT NOT NULL,
    data BLOB NOT NULL,
    data_hex TEXT NOT NULL,
    data_sha256 TEXT NOT NULL,
    ascii_view TEXT NOT NULL,
    all_zero INTEGER NOT NULL,
    PRIMARY KEY(read_id, block_number)
) STRICT;

CREATE INDEX IF NOT EXISTS blocks_sector_idx ON blocks(read_id, sector_number);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY,
    read_id INTEGER NOT NULL REFERENCES reads(id) ON DELETE CASCADE,
    artifact_kind TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    media_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    content BLOB NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(read_id, artifact_kind, relative_path)
) STRICT;

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    read_id INTEGER NOT NULL REFERENCES reads(id) ON DELETE CASCADE,
    observation_key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    confidence TEXT NOT NULL,
    UNIQUE(read_id, observation_key)
) STRICT;

CREATE TABLE IF NOT EXISTS element_relations (
    id INTEGER PRIMARY KEY,
    source_element_id INTEGER NOT NULL REFERENCES elements(id) ON DELETE RESTRICT,
    target_element_id INTEGER NOT NULL REFERENCES elements(id) ON DELETE RESTRICT,
    relation_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    notes TEXT,
    UNIQUE(source_element_id, target_element_id, relation_type)
) STRICT;

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    project_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK(purpose IN ('education', 'home', 'education_and_home')),
    owner_subject TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('planned', 'active', 'paused', 'completed', 'archived')),
    authorization_policy TEXT NOT NULL,
    scope_notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS device_types (
    type_key TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN (
        'rfid', 'access', 'computing', 'embedded', 'sensor', 'network', 'test', 'generic'
    )),
    default_device_kind TEXT NOT NULL CHECK(default_device_kind IN (
        'rfid_reader', 'rfid_tag', 'rfid_card', 'rfid_key_fob',
        'access_controller', 'lock', 'computer', 'embedded_device',
        'network_device', 'test_equipment', 'other'
    )),
    description TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'retired')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

INSERT OR IGNORE INTO device_types(
    type_key, display_name, category, default_device_kind, description, status, created_at, updated_at
) VALUES
    ('rfid.reader', 'RFID reader', 'rfid', 'rfid_reader', 'Reader or writer for RFID media.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('rfid.tag', 'RFID tag', 'rfid', 'rfid_tag', 'RFID tag without card or key-fob form.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('rfid.card', 'RFID card', 'rfid', 'rfid_card', 'RFID card credential.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('rfid.key_fob', 'RFID key fob', 'rfid', 'rfid_key_fob', 'RFID key-fob credential.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('access.controller', 'Access controller', 'access', 'access_controller', 'Physical access controller.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('access.lock', 'Lock', 'access', 'lock', 'Physical lock or latch.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('computing.computer', 'Computer', 'computing', 'computer', 'General-purpose computer.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('computing.raspberry_pi_3', 'Raspberry Pi 3', 'computing', 'computer', 'Raspberry Pi 3 single-board computer.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('embedded.device', 'Embedded device', 'embedded', 'embedded_device', 'Embedded device or microcontroller.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('sensor.temperature', 'Temperature sensor', 'sensor', 'embedded_device', 'Sensor that reports temperature.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('network.device', 'Network device', 'network', 'network_device', 'Network infrastructure or endpoint.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('test.equipment', 'Test equipment', 'test', 'test_equipment', 'Test or measurement equipment.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00'),
    ('generic.device', 'Generic device', 'generic', 'other', 'Device without a specific registered type.', 'active', '2026-08-15T00:00:00+02:00', '2026-08-15T00:00:00+02:00');

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    device_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    device_kind TEXT NOT NULL CHECK(device_kind IN (
        'rfid_reader', 'rfid_tag', 'rfid_card', 'rfid_key_fob',
        'access_controller', 'lock', 'computer', 'embedded_device',
        'network_device', 'test_equipment', 'other'
    )),
    role TEXT NOT NULL CHECK(role IN ('tool', 'target', 'credential', 'support')),
    manufacturer TEXT,
    model TEXT,
    serial_number TEXT,
    asset_identifier TEXT,
    interface TEXT,
    location_label TEXT,
    ownership_status TEXT NOT NULL CHECK(ownership_status IN (
        'user_owned', 'household_owned', 'authorized_external', 'user_authorized', 'unspecified'
    )),
    lifecycle_status TEXT NOT NULL CHECK(lifecycle_status IN ('active', 'inactive', 'retired', 'lost')),
    sensitivity TEXT NOT NULL CHECK(sensitivity IN ('normal', 'sensitive', 'critical')),
    device_type_key TEXT REFERENCES device_types(type_key) ON DELETE RESTRICT,
    legacy_reader_id INTEGER UNIQUE REFERENCES readers(id) ON DELETE RESTRICT,
    legacy_element_id INTEGER UNIQUE REFERENCES elements(id) ON DELETE RESTRICT,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata_json)),
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(legacy_reader_id IS NULL OR legacy_element_id IS NULL)
) STRICT;

CREATE INDEX IF NOT EXISTS devices_kind_idx ON devices(device_kind);
CREATE INDEX IF NOT EXISTS devices_lifecycle_idx ON devices(lifecycle_status);
CREATE INDEX IF NOT EXISTS devices_type_idx ON devices(device_type_key);

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

CREATE TABLE IF NOT EXISTS device_identifiers (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    identifier_kind TEXT NOT NULL,
    identifier_value TEXT NOT NULL,
    identifier_scope TEXT NOT NULL DEFAULT '',
    classification TEXT NOT NULL CHECK(classification IN ('normal', 'sensitive', 'critical')),
    source_reference TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'historical', 'revoked')),
    observed_at TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(length(trim(identifier_kind)) > 0),
    CHECK(length(trim(identifier_value)) > 0),
    UNIQUE(device_id, identifier_kind, identifier_value, identifier_scope)
) STRICT;

CREATE INDEX IF NOT EXISTS device_identifiers_device_idx
    ON device_identifiers(device_id, status, identifier_kind);

CREATE TABLE IF NOT EXISTS device_information (
    id INTEGER PRIMARY KEY,
    information_key TEXT NOT NULL UNIQUE,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    information_kind TEXT NOT NULL CHECK(information_kind IN ('configuration', 'fact', 'observation', 'service')),
    property_key TEXT NOT NULL,
    value_json TEXT NOT NULL CHECK(json_valid(value_json)),
    unit TEXT,
    source_reference TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK(confidence IN ('reported', 'observed', 'verified', 'low')),
    classification TEXT NOT NULL CHECK(classification IN ('normal', 'sensitive', 'critical')),
    is_current INTEGER NOT NULL CHECK(is_current IN (0, 1)),
    observed_at TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(length(trim(property_key)) > 0)
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS device_information_one_current_idx
    ON device_information(device_id, property_key) WHERE is_current = 1;
CREATE INDEX IF NOT EXISTS device_information_device_idx
    ON device_information(device_id, property_key, observed_at DESC);

CREATE TABLE IF NOT EXISTS device_interfaces (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface_key TEXT NOT NULL,
    interface_type TEXT NOT NULL,
    endpoint TEXT,
    address TEXT,
    authentication_type TEXT,
    secret_reference TEXT,
    status TEXT NOT NULL CHECK(status IN ('active', 'inactive', 'historical')),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json)),
    source_reference TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(length(trim(interface_key)) > 0),
    UNIQUE(device_id, interface_key)
) STRICT;

CREATE INDEX IF NOT EXISTS device_interfaces_device_idx
    ON device_interfaces(device_id, status);

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

CREATE TABLE IF NOT EXISTS device_relations (
    id INTEGER PRIMARY KEY,
    source_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    target_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    relation_type TEXT NOT NULL REFERENCES device_relation_types(relation_type) ON DELETE RESTRICT,
    source_reference TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'historical', 'removed')),
    observed_at TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(source_device_id <> target_device_id),
    UNIQUE(source_device_id, target_device_id, relation_type)
) STRICT;

CREATE INDEX IF NOT EXISTS device_relations_source_idx
    ON device_relations(source_device_id, status);
CREATE INDEX IF NOT EXISTS device_relations_target_idx
    ON device_relations(target_device_id, status);

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

CREATE TABLE IF NOT EXISTS device_components (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    component_key TEXT NOT NULL,
    component_kind TEXT NOT NULL CHECK(component_kind IN ('hardware', 'firmware', 'software', 'service', 'sensor_module', 'other')),
    name TEXT NOT NULL,
    version TEXT,
    status TEXT NOT NULL CHECK(status IN ('active', 'inactive', 'historical')),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json)),
    source_reference TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(device_id, component_key)
) STRICT;

CREATE INDEX IF NOT EXISTS device_components_device_idx
    ON device_components(device_id, status);

CREATE TABLE IF NOT EXISTS rfid_profiles (
    device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    profile_kind TEXT NOT NULL CHECK(profile_kind IN ('reader', 'tag', 'card', 'key_fob', 'controller', 'other')),
    frequency_mhz REAL,
    standard TEXT,
    technology TEXT,
    product_family TEXT,
    chip_vendor TEXT,
    chip_model TEXT,
    uid_identifier_id INTEGER UNIQUE REFERENCES device_identifiers(id) ON DELETE RESTRICT,
    legacy_reader_id INTEGER UNIQUE REFERENCES readers(id) ON DELETE RESTRICT,
    legacy_element_id INTEGER UNIQUE REFERENCES elements(id) ON DELETE RESTRICT,
    technical_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(technical_json)),
    source_reference TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(legacy_reader_id IS NULL OR legacy_element_id IS NULL)
) STRICT;

CREATE TABLE IF NOT EXISTS measurement_channels (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    channel_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    quantity_kind TEXT NOT NULL,
    unit TEXT NOT NULL,
    minimum_value REAL,
    maximum_value REAL,
    retention_days INTEGER CHECK(retention_days IS NULL OR retention_days BETWEEN 1 AND 36500),
    status TEXT NOT NULL CHECK(status IN ('active', 'inactive', 'retired')),
    source_reference TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(minimum_value IS NULL OR maximum_value IS NULL OR minimum_value <= maximum_value),
    UNIQUE(device_id, channel_key)
) STRICT;

CREATE INDEX IF NOT EXISTS measurement_channels_device_idx
    ON measurement_channels(device_id, status);

CREATE TABLE IF NOT EXISTS measurement_samples (
    id INTEGER PRIMARY KEY,
    channel_id INTEGER NOT NULL REFERENCES measurement_channels(id) ON DELETE CASCADE,
    observed_at TEXT NOT NULL,
    value_real REAL NOT NULL,
    quality TEXT NOT NULL CHECK(quality IN ('valid', 'estimated', 'invalid')),
    source_reference TEXT NOT NULL,
    notes TEXT,
    recorded_at TEXT NOT NULL,
    UNIQUE(channel_id, observed_at)
) STRICT;

CREATE INDEX IF NOT EXISTS measurement_samples_channel_time_idx
    ON measurement_samples(channel_id, observed_at DESC);

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

CREATE INDEX IF NOT EXISTS measurement_retention_results_channel_idx
    ON measurement_retention_results(channel_id, cutoff_at);

CREATE TABLE IF NOT EXISTS project_devices (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    role_in_project TEXT NOT NULL CHECK(role_in_project IN ('tool', 'target', 'credential', 'support')),
    scope TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending_authorization', 'in_scope', 'out_of_scope', 'archived')),
    added_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(project_id, device_id)
) STRICT;

CREATE INDEX IF NOT EXISTS project_devices_status_idx
    ON project_devices(project_id, status);

CREATE TABLE IF NOT EXISTS access_authorizations (
    id INTEGER PRIMARY KEY,
    authorization_key TEXT NOT NULL UNIQUE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    subject TEXT NOT NULL,
    authorization_basis TEXT NOT NULL CHECK(authorization_basis IN (
        'user_declaration', 'self_owned', 'household_owner',
        'explicit_permission', 'contract', 'employer_authorization'
    )),
    access_level TEXT NOT NULL CHECK(access_level IN (
        'observe', 'read', 'test', 'write', 'admin', 'full'
    )),
    allowed_operations_json TEXT NOT NULL CHECK(
        json_valid(allowed_operations_json) AND json_type(allowed_operations_json) = 'array'
    ),
    purpose TEXT NOT NULL CHECK(purpose IN ('education', 'home', 'education_and_home')),
    evidence_reference TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'suspended', 'revoked', 'expired')),
    valid_from TEXT NOT NULL,
    valid_until TEXT,
    authorized_at TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(valid_until IS NULL OR datetime(valid_until) > datetime(valid_from)),
    UNIQUE(project_id, device_id, authorization_key)
) STRICT;

CREATE INDEX IF NOT EXISTS access_authorizations_lookup_idx
    ON access_authorizations(project_id, device_id, status);

CREATE TABLE IF NOT EXISTS access_authorization_operations (
    authorization_id INTEGER NOT NULL REFERENCES access_authorizations(id) ON DELETE CASCADE,
    operation TEXT NOT NULL CHECK(operation IN (
        'identify', 'inspect', 'read', 'analyze', 'test', 'write', 'configure', 'administer'
    )),
    created_at TEXT NOT NULL,
    PRIMARY KEY(authorization_id, operation)
) STRICT;

CREATE TABLE IF NOT EXISTS access_methods (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    method_key TEXT NOT NULL,
    method_type TEXT NOT NULL CHECK(method_type IN (
        'usb_serial', 'local', 'ssh', 'web', 'api', 'rfid', 'bluetooth', 'other'
    )),
    endpoint TEXT,
    account_label TEXT,
    authentication_type TEXT,
    secret_reference TEXT,
    status TEXT NOT NULL CHECK(status IN ('active', 'inactive', 'blocked')),
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(project_id, device_id, method_key)
) STRICT;

CREATE INDEX IF NOT EXISTS access_methods_device_idx
    ON access_methods(project_id, device_id, status);

CREATE TABLE IF NOT EXISTS device_commands (
    id INTEGER PRIMARY KEY,
    command_key TEXT NOT NULL UNIQUE,
    device_kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    command_text TEXT NOT NULL,
    required_operation TEXT NOT NULL CHECK(required_operation IN (
        'identify', 'inspect', 'read', 'analyze', 'test', 'write', 'configure', 'administer'
    )),
    risk_level TEXT NOT NULL CHECK(risk_level IN ('read_only', 'state_change', 'destructive')),
    timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds BETWEEN 1 AND 3600),
    output_retention_days INTEGER NOT NULL DEFAULT 90 CHECK(output_retention_days BETWEEN 1 AND 36500),
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    builtin INTEGER NOT NULL CHECK(builtin IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS device_commands_kind_idx
    ON device_commands(device_kind, enabled);

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
    script_sha256 TEXT NOT NULL CHECK(length(script_sha256) = 64),
    script_revision INTEGER NOT NULL DEFAULT 1 CHECK(script_revision >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(device_id, relative_path)
) STRICT;

CREATE INDEX IF NOT EXISTS device_scripts_device_idx
    ON device_scripts(device_id, enabled);

CREATE TABLE IF NOT EXISTS device_command_runs (
    id INTEGER PRIMARY KEY,
    run_key TEXT NOT NULL UNIQUE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    command_id INTEGER REFERENCES device_commands(id) ON DELETE SET NULL,
    command_text TEXT NOT NULL,
    required_operation TEXT NOT NULL,
    client_path TEXT,
    endpoint TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    duration_ms INTEGER NOT NULL CHECK(duration_ms >= 0),
    status TEXT NOT NULL CHECK(status IN ('succeeded', 'failed', 'blocked', 'timed_out')),
    exit_code INTEGER,
    stdout_sha256 TEXT NOT NULL,
    stderr_sha256 TEXT NOT NULL,
    stdout_content BLOB NOT NULL,
    stderr_content BLOB NOT NULL,
    executed_script_sha256 TEXT CHECK(executed_script_sha256 IS NULL OR length(executed_script_sha256) = 64),
    stdout_original_sha256 TEXT CHECK(stdout_original_sha256 IS NULL OR length(stdout_original_sha256) = 64),
    stderr_original_sha256 TEXT CHECK(stderr_original_sha256 IS NULL OR length(stderr_original_sha256) = 64),
    output_purged_at TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS device_command_runs_device_idx
    ON device_command_runs(project_id, device_id, started_at);

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

CREATE INDEX IF NOT EXISTS database_backups_created_idx
    ON database_backups(created_at DESC);

CREATE TABLE IF NOT EXISTS clone_operations (
    id INTEGER PRIMARY KEY,
    run_key TEXT NOT NULL UNIQUE,
    source_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    target_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    source_read_id INTEGER NOT NULL REFERENCES reads(id) ON DELETE RESTRICT,
    executed_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('started', 'written', 'verified', 'failed')),
    method TEXT NOT NULL,
    tool_command TEXT NOT NULL,
    blocks_written INTEGER NOT NULL,
    uid_before_hex TEXT NOT NULL,
    uid_after_hex TEXT NOT NULL,
    source_dump_sha256 TEXT NOT NULL,
    prewrite_backup_sha256 TEXT NOT NULL,
    magic_read_sha256 TEXT NOT NULL,
    standard_read_sha256 TEXT NOT NULL,
    byte_identical INTEGER NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS clone_operations_target_idx
    ON clone_operations(target_device_id, executed_at);

CREATE TABLE IF NOT EXISTS operation_artifacts (
    id INTEGER PRIMARY KEY,
    clone_operation_id INTEGER NOT NULL REFERENCES clone_operations(id) ON DELETE CASCADE,
    artifact_kind TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    media_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    content BLOB NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(clone_operation_id, artifact_kind, relative_path)
) STRICT;

CREATE VIEW IF NOT EXISTS active_authorized_devices AS
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

PRAGMA user_version = 7;
