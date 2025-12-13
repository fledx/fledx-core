-- Secret references for deployments (env + files).
ALTER TABLE deployments ADD COLUMN secret_env_json TEXT;
ALTER TABLE deployments ADD COLUMN secret_files_json TEXT;
