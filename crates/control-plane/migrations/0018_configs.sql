-- Config objects with versioning and attachments to deployments/nodes.
CREATE TABLE IF NOT EXISTS configs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    version INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
    CHECK (length(name) > 0 AND length(name) <= 255),
    CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS config_entries (
    config_id TEXT NOT NULL REFERENCES configs (id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT,
    secret_ref TEXT,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (config_id, key),
    CHECK (length(key) > 0 AND length(key) <= 255),
    CHECK (value IS NULL OR length(value) <= 4096),
    CHECK (secret_ref IS NULL OR length(secret_ref) <= 255),
    CHECK (
        (value IS NOT NULL AND secret_ref IS NULL)
        OR (value IS NULL AND secret_ref IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS config_files (
    config_id TEXT NOT NULL REFERENCES configs (id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    file_ref TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (config_id, path),
    CHECK (length(path) > 0 AND length(path) <= 512),
    CHECK (length(file_ref) > 0 AND length(file_ref) <= 255)
);

CREATE TABLE IF NOT EXISTS config_deployments (
    config_id TEXT NOT NULL REFERENCES configs (id) ON DELETE CASCADE,
    deployment_id TEXT NOT NULL REFERENCES deployments (id) ON DELETE CASCADE,
    attached_at DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (config_id, deployment_id)
);

CREATE TABLE IF NOT EXISTS config_nodes (
    config_id TEXT NOT NULL REFERENCES configs (id) ON DELETE CASCADE,
    node_id TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    attached_at DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (config_id, node_id)
);

CREATE INDEX IF NOT EXISTS idx_configs_name ON configs (name);
CREATE INDEX IF NOT EXISTS idx_config_deployments_deployment ON config_deployments (deployment_id, config_id);
CREATE INDEX IF NOT EXISTS idx_config_nodes_node ON config_nodes (node_id, config_id);
