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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::InstanceState;
    use crate::test_support::base_config;
    use chrono::{Duration, Utc};

    #[test]
    fn apply_sets_backoff_and_remaining() {
        let mut cfg = base_config();
        cfg.restart_backoff_ms = 10;
        cfg.restart_backoff_max_ms = 10;
        let mut managed = state::ManagedDeployment::new(1);

        apply(
            &cfg,
            &mut managed,
            Some("container-1".into()),
            Some("boom".into()),
        );

        assert_eq!(managed.state, InstanceState::Failed);
        assert_eq!(managed.message.as_deref(), Some("boom"));
        assert!(managed.backoff_until.is_some());
        assert!(remaining(&managed).is_some());

        managed.backoff_until = Some(Utc::now() - Duration::seconds(1));
        assert!(remaining(&managed).is_none());
    }
}
