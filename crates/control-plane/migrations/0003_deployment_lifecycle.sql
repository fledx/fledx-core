-- Soft delete support for deployments.
ALTER TABLE deployments
ADD COLUMN deleted_at TEXT;

CREATE INDEX IF NOT EXISTS idx_deployments_deleted ON deployments (deleted_at);
