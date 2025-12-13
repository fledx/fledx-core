-- Track per-replica node assignments and resolved ports.
CREATE TABLE IF NOT EXISTS deployment_assignments (
    deployment_id TEXT NOT NULL REFERENCES deployments (id) ON DELETE CASCADE,
    replica_number INTEGER NOT NULL,
    node_id TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    ports_json TEXT,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (deployment_id, replica_number)
);

CREATE INDEX IF NOT EXISTS idx_deployment_assignments_node
    ON deployment_assignments (node_id);

-- Backfill existing single-node assignments.
INSERT INTO deployment_assignments (
    deployment_id,
    replica_number,
    node_id,
    ports_json
)
SELECT id, 0, assigned_node_id, ports_json
FROM deployments
WHERE assigned_node_id IS NOT NULL;
