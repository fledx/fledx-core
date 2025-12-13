use sqlx::SqlitePool;

pub mod configs;
pub mod deployments;
pub mod logs;
pub mod migrations;
pub mod nodes;
pub mod ports;
pub mod tokens;
pub mod usage;

pub type Db = SqlitePool;

pub use common::api::{
    CapacityHints, DeploymentHealth, HealthStatus, PlacementAffinity, PlacementConstraints,
    PlacementHints, PortMapping, ResourceMetricSample, SecretEnv, SecretFile, VolumeMount,
};

pub use configs::{
    ConfigEntry, ConfigEntryRecord, ConfigFileRecord, ConfigFileRef, ConfigListRow, ConfigRecord,
    NewConfig,
};
pub use deployments::{
    DeploymentAssignmentRecord, DeploymentListRow, DeploymentRecord, DeploymentStatus,
    DeploymentWithAssignment, DesiredState, NewDeployment, NewDeploymentAssignment,
    UpdatedDeployment,
};
pub use logs::{InstanceState, InstanceStatusRecord, InstanceStatusUpsert, RecordHeartbeatParams};
pub use migrations::{MigrationLabel, MigrationRunOutcome, MigrationSnapshot};
pub use nodes::{NewNode, NodeInventoryUpdate, NodeRecord, NodeStatus};
pub use ports::{
    PortAllocationConfig, PortAllocationError, PortReservationConflict, PortReservationRecord,
};
pub use tokens::NodeTokenRecord;
pub use usage::{
    UsageRollup, UsageRollupFilters, UsageRollupRecord, UsageSummary, UsageSummaryFilters,
};
