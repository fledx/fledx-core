-- Replica count and placement hints for deployments.
ALTER TABLE deployments ADD COLUMN replicas INTEGER NOT NULL DEFAULT 1;
ALTER TABLE deployments ADD COLUMN placement_hints_json TEXT;
