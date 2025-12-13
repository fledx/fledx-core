-- Node inventory and deployment placement constraints.
ALTER TABLE nodes ADD COLUMN labels_json TEXT;
ALTER TABLE nodes ADD COLUMN capacity_json TEXT;

ALTER TABLE deployments ADD COLUMN constraints_json TEXT;
