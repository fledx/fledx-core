use chrono::Duration;

use crate::{config, state};

pub(super) fn remaining(managed: &state::ManagedDeployment) -> Option<Duration> {
    state::backoff_remaining(managed)
}

pub(super) fn apply(
    cfg: &config::AppConfig,
    managed: &mut state::ManagedDeployment,
    container_id: Option<String>,
    message: Option<String>,
) {
    state::apply_failure_backoff(cfg, managed, container_id, message)
}
