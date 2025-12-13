-- Track aggregated resource usage per deployment/node in minute buckets.
CREATE TABLE IF NOT EXISTS deployment_usage_rollups (
    deployment_id TEXT NOT NULL REFERENCES deployments (id) ON DELETE CASCADE,
    node_id TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    replica_number INTEGER NOT NULL DEFAULT 0,
    bucket_start TEXT NOT NULL,
    samples INTEGER NOT NULL DEFAULT 0,
    avg_cpu_percent REAL NOT NULL,
    avg_memory_bytes INTEGER NOT NULL,
    avg_network_rx_bytes INTEGER NOT NULL,
    avg_network_tx_bytes INTEGER NOT NULL,
    avg_blk_read_bytes INTEGER,
    avg_blk_write_bytes INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK (strftime('%s', bucket_start) = strftime('%s', bucket_start, 'start of minute')),
    PRIMARY KEY (deployment_id, node_id, replica_number, bucket_start)
);

CREATE INDEX IF NOT EXISTS idx_usage_rollups_bucket ON deployment_usage_rollups (bucket_start);
CREATE INDEX IF NOT EXISTS idx_usage_rollups_deployment_bucket ON deployment_usage_rollups (deployment_id, bucket_start);
CREATE INDEX IF NOT EXISTS idx_usage_rollups_node_bucket ON deployment_usage_rollups (node_id, bucket_start);
