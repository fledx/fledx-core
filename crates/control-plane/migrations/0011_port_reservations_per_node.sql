-- Allow deployments to reserve the same host port on different nodes by
-- including node_id in the primary key.
PRAGMA foreign_keys=OFF;

CREATE TABLE port_reservations_new (
    deployment_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    host_ip TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL,
    host_port INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (deployment_id, node_id, host_ip, protocol, host_port),
    FOREIGN KEY (deployment_id) REFERENCES deployments (id),
    FOREIGN KEY (node_id) REFERENCES nodes (id)
);

INSERT INTO port_reservations_new (
    deployment_id,
    node_id,
    host_ip,
    protocol,
    host_port,
    created_at,
    updated_at
)
SELECT
    deployment_id,
    node_id,
    host_ip,
    protocol,
    host_port,
    created_at,
    updated_at
FROM port_reservations;

DROP TABLE port_reservations;

ALTER TABLE port_reservations_new RENAME TO port_reservations;

CREATE UNIQUE INDEX IF NOT EXISTS idx_port_reservations_node_ip_proto_port
    ON port_reservations (node_id, host_ip, protocol, host_port);

CREATE INDEX IF NOT EXISTS idx_port_reservations_node ON port_reservations (node_id);

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

PRAGMA foreign_keys=ON;
