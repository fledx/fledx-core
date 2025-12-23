use node_agent::runtime::{ContainerRuntime, ContainerSpec, ContainerStatus, DockerRuntime};
use tracing::warn;
use tracing_subscriber::fmt;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn docker_runtime_runs_hello_world() -> anyhow::Result<()> {
    let _ = fmt::try_init();

    let runtime = match DockerRuntime::connect() {
        Ok(rt) => rt,
        Err(err) => {
            warn!(error = ?err, "skipping docker runtime test (docker not available)");
            return Ok(());
        }
    };

    let image = "hello-world:latest";

    if let Err(err) = runtime.pull_image(image).await {
        warn!(error = ?err, "skipping docker runtime test (cannot pull image)");
        return Ok(());
    }

    let container_id = runtime
        .start_container(ContainerSpec {
            image: image.to_string(),
            name: Some(format!("fledx-agent-test-{}", Uuid::new_v4())),
            env: vec![],
            ports: vec![],
            command: None,
            labels: vec![],
            mounts: vec![],
        })
        .await?;

    let details = runtime.inspect_container(&container_id).await?;
    assert!(
        matches!(
            details.status,
            ContainerStatus::Running | ContainerStatus::Exited { .. }
        ),
        "unexpected container status: {:?}",
        details.status
    );

    runtime.stop_container(&container_id).await?;
    runtime.remove_container(&container_id).await?;

    Ok(())
}
