CREATE TABLE IF NOT EXISTS node_tokens (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT,
    disabled_at TEXT,
    last_used_at TEXT,
    FOREIGN KEY (node_id) REFERENCES nodes (id)
);

CREATE INDEX IF NOT EXISTS idx_node_tokens_node_id ON node_tokens (node_id);
CREATE INDEX IF NOT EXISTS idx_node_tokens_active ON node_tokens (node_id, disabled_at, expires_at);

INSERT INTO node_tokens (id, node_id, token_hash, created_at, last_used_at)
SELECT id, id, token_hash, created_at, last_seen
FROM nodes;
