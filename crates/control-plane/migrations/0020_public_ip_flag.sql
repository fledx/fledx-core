-- Public ingress flag for deployments
ALTER TABLE deployments
ADD COLUMN requires_public_ip INTEGER NOT NULL DEFAULT 0;
