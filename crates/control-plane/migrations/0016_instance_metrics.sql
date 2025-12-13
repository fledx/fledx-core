-- Persist bounded resource metrics samples reported by the node-agent.
ALTER TABLE instance_statuses ADD COLUMN metrics_json TEXT;
