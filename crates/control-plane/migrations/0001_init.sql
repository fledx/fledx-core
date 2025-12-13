-- Nodes table
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    name TEXT,
    token_hash TEXT NOT NULL,
    arch TEXT,
    os TEXT,
    last_seen TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Deployments table
CREATE TABLE IF NOT EXISTS deployments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    command_json TEXT,
    env_json TEXT,
    ports_json TEXT,
    desired_state TEXT NOT NULL,
    assigned_node_id TEXT,
    status TEXT NOT NULL,
    generation INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (assigned_node_id) REFERENCES nodes (id)
);

CREATE INDEX IF NOT EXISTS idx_deployments_assigned_node ON deployments (assigned_node_id);
