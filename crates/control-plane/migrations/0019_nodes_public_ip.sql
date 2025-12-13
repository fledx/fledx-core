-- Store public ingress metadata on nodes.
ALTER TABLE nodes ADD COLUMN public_ip TEXT;
ALTER TABLE nodes ADD COLUMN public_host TEXT;
