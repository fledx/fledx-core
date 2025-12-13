-- Flag for tunnel-only deployments.
ALTER TABLE deployments
ADD COLUMN tunnel_only INTEGER NOT NULL DEFAULT 0;
