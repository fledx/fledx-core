#[tokio::main]
async fn main() -> control_plane::Result<()> {
    control_plane::init_tracing();
    let mode = control_plane::parse_command()?;
    tracing::info!(
        version = control_plane::version::VERSION,
        git_sha = control_plane::version::GIT_SHA,
        dirty = control_plane::version::GIT_DIRTY,
        built_at = control_plane::version::BUILD_TIMESTAMP,
        mode = ?mode,
        "control-plane starting"
    );
    control_plane::run(mode).await
}
