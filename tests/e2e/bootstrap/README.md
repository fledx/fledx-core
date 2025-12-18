# CLI bootstrap e2e (local)

This scenario runs the `fledx` CLI inside a container and bootstraps a
control-plane container plus an agent container over SSH. It uses real GitHub
release assets.

## Requirements

- Docker (the script uses `docker build`/`docker run`, not Compose)
- Access to `/var/run/docker.sock` on the host
- A local build of the CLI (the script builds it for you)

## Run

```bash
./tests/e2e/bootstrap/run.sh
```

Options:

```bash
./tests/e2e/bootstrap/run.sh --rebuild --cleanup --insecure
```

- `--rebuild` forces a fresh CLI build.
- `--cleanup` removes the containers and volumes when the run finishes.
- `--insecure` skips signed release verification.

## Notes

- The containers run `systemd` and require `privileged` mode plus
  `--cgroupns=host` on cgroup v2 hosts.
- SSH host key checking is disabled for this local test.
- SSH uses the `fledx` user inside the target containers.
- The test waits for at least one node to reach `ready` status.
- The runner copies the generated `authorized_keys` into the containers before
  invoking the CLI.
- Release binaries embed the signing keys at build time; end users should not
  need to set any env vars.
- For local builds (secure mode), export `FLEDX_RELEASE_SIGNING_ED25519_PUBKEYS`
  so the keys get embedded into the debug binary used by the test.
- The runner invokes `fledx internal release-signing-keys` in secure mode to
  ensure the binary reports configured signing keys and fails early if none are
  found.
- Agent bootstrap runs with `--service-user fledx-agent`.
- The runner ensures the Docker socket GID has a named group inside the agent
  container so the service user can access `/var/run/docker.sock`.
