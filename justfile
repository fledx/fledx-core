set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := true

default: pre-commit

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

deny-check:
  cargo deny check

build:
  cargo build --workspace --all-features

docs:
  cargo run --package control-plane --bin openapi > docs/openapi.json

clippy:
  cargo clippy --workspace --all-targets --all-features -- -D warnings

check:
  cargo check --workspace --all-features

test:
  cargo test --workspace --all-features

chaos-test:
  FLEDX_CHAOS_SMOKE=1 FLEDX_RUN_CHAOS=1 cargo test -p node-agent --all-features --test chaos_recovery

pre-commit: fmt-check clippy test
  @echo "✅ pre-commit checks passed"

pre-push: deny-check pre-commit chaos-test
  @echo "✅ pre-push checks passed"
