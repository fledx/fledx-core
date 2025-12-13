-- Store health configuration and probe results.
ALTER TABLE deployments ADD COLUMN health_json TEXT;

ALTER TABLE instance_statuses ADD COLUMN health_json TEXT;
