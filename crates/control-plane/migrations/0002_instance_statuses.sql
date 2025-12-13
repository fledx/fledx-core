-- Instance status entries reported via heartbeats
CREATE TABLE IF NOT EXISTS instance_statuses (
    node_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    container_id TEXT,
    state TEXT NOT NULL,
    message TEXT,
    restart_count INTEGER NOT NULL DEFAULT 0,
    last_updated TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (node_id, deployment_id),
    FOREIGN KEY (node_id) REFERENCES nodes (id),
    FOREIGN KEY (deployment_id) REFERENCES deployments (id)
);

CREATE INDEX IF NOT EXISTS idx_instance_statuses_last_seen ON instance_statuses (last_seen);
CREATE INDEX IF NOT EXISTS idx_instance_statuses_deployment ON instance_statuses (deployment_id);
