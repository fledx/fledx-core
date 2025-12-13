-- Track host port reservations per node to avoid conflicting mappings.
CREATE TABLE IF NOT EXISTS port_reservations (
    deployment_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    host_ip TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL,
    host_port INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (deployment_id, host_ip, protocol, host_port),
    FOREIGN KEY (deployment_id) REFERENCES deployments (id),
    FOREIGN KEY (node_id) REFERENCES nodes (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_port_reservations_node_ip_proto_port
    ON port_reservations (node_id, host_ip, protocol, host_port);

CREATE INDEX IF NOT EXISTS idx_port_reservations_node ON port_reservations (node_id);

-- Backfill existing running deployments so current reservations are captured after
-- upgrade.
INSERT OR IGNORE INTO port_reservations (
    deployment_id,
    node_id,
    host_ip,
    protocol,
    host_port,
    created_at,
    updated_at
)
SELECT
    d.id AS deployment_id,
    d.assigned_node_id AS node_id,
    CASE
        WHEN TRIM(json_extract(port.value, '$.host_ip')) IN ('', '0.0.0.0', '::') THEN ''
        ELSE COALESCE(TRIM(json_extract(port.value, '$.host_ip')), '')
    END AS host_ip,
    LOWER(COALESCE(json_extract(port.value, '$.protocol'), 'tcp')) AS protocol,
    CAST(
        COALESCE(
            json_extract(port.value, '$.host_port'),
            json_extract(port.value, '$.container_port')
        ) AS INTEGER
    ) AS host_port,
    datetime('now') AS created_at,
    datetime('now') AS updated_at
FROM deployments d
JOIN json_each(d.ports_json) AS port
WHERE d.desired_state = 'running'
  AND d.assigned_node_id IS NOT NULL
  AND d.ports_json IS NOT NULL;

-- Enforce wildcard conflicts at the database level to avoid races between
-- concurrent transactions.
CREATE TRIGGER IF NOT EXISTS trg_port_reservations_conflict
BEFORE INSERT ON port_reservations
BEGIN
    SELECT
        RAISE(ABORT, 'port reservation conflict')
    WHERE EXISTS (
        SELECT 1
        FROM port_reservations pr
        WHERE pr.node_id = NEW.node_id
          AND pr.protocol = NEW.protocol
          AND pr.host_port = NEW.host_port
          AND (
                pr.host_ip IN ('', '0.0.0.0', '::')
             OR NEW.host_ip IN ('', '0.0.0.0', '::')
             OR pr.host_ip = NEW.host_ip
          )
    );
END;
