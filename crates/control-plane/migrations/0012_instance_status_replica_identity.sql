-- Add replica identity and generation to instance statuses
PRAGMA foreign_keys=off;

CREATE TABLE IF NOT EXISTS instance_statuses_new (
    node_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    replica_number INTEGER NOT NULL DEFAULT 0,
    generation INTEGER NOT NULL DEFAULT 0,
    container_id TEXT,
    state TEXT NOT NULL,
    message TEXT,
    restart_count INTEGER NOT NULL DEFAULT 0,
    last_updated TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (node_id, deployment_id, replica_number),
    FOREIGN KEY (node_id) REFERENCES nodes (id),
    FOREIGN KEY (deployment_id) REFERENCES deployments (id)
);

INSERT INTO instance_statuses_new (
    node_id,
    deployment_id,
    replica_number,
    generation,
    container_id,
    state,
    message,
    restart_count,
    last_updated,
    last_seen,
    created_at,
    updated_at
)
SELECT
    node_id,
    deployment_id,
    0 AS replica_number,
    0 AS generation,
    container_id,
    state,
    message,
    restart_count,
    last_updated,
    last_seen,
    created_at,
    updated_at
FROM instance_statuses;

DROP TABLE instance_statuses;
ALTER TABLE instance_statuses_new RENAME TO instance_statuses;

CREATE INDEX IF NOT EXISTS idx_instance_statuses_last_seen ON instance_statuses (last_seen);
CREATE INDEX IF NOT EXISTS idx_instance_statuses_deployment ON instance_statuses (deployment_id);
CREATE INDEX IF NOT EXISTS idx_instance_statuses_deployment_replica ON instance_statuses (deployment_id, replica_number);

PRAGMA foreign_keys=on;
