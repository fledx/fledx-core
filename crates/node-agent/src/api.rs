//! API DTOs used by the node-agent.

pub use common::api::{
    CapacityHints, ConfigDesired, ConfigEntry, ConfigFile, ConfigMetadata, DeploymentDesired,
    DeploymentHealth, DesiredState, DesiredStateResponse, HealthProbe, HealthProbeKind,
    HealthStatus, InstanceState, InstanceStatus, NodeConfigResponse, PortMapping,
    ResourceMetricSample, SecretEnv, SecretFile, ServiceIdentityBundle, TunnelEndpoint,
    VolumeMount,
};
