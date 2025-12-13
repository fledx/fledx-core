-- Add volumes to deployments for host/container mounts
ALTER TABLE deployments ADD COLUMN volumes_json TEXT;
