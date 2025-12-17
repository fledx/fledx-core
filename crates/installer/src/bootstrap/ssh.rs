use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Context;

use super::{
    looks_like_noninteractive_sudo_failure, run_capture, run_checked, sh_quote_path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxArch {
    X86_64,
    Aarch64,
}

impl LinuxArch {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    pub fn from_uname(value: &str) -> anyhow::Result<Self> {
        let normalized = value.trim();
        match normalized {
            "x86_64" | "amd64" => Ok(Self::X86_64),
            "aarch64" | "arm64" => Ok(Self::Aarch64),
            other => anyhow::bail!("unsupported arch '{}'; supported: x86_64, aarch64", other),
        }
    }

    pub fn detect_local() -> anyhow::Result<Self> {
        Self::from_uname(std::env::consts::ARCH)
    }
}

#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: String,
    pub user: Option<String>,
    pub port: u16,
    pub identity_file: Option<PathBuf>,
}

impl SshTarget {
    pub fn from_user_at_host(
        raw_host: &str,
        user_override: Option<String>,
        port: u16,
        identity_file: Option<PathBuf>,
    ) -> Self {
        let (user_from_host, host) = match raw_host.split_once('@') {
            Some((user, host)) => (Some(user.to_string()), host.to_string()),
            None => (None, raw_host.to_string()),
        };
        let user = user_override.or(user_from_host);
        Self {
            host,
            user,
            port,
            identity_file,
        }
    }

    pub fn destination(&self) -> String {
        match &self.user {
            Some(user) => format!("{user}@{}", self.host),
            None => self.host.clone(),
        }
    }

    fn ssh_base(&self) -> Command {
        let mut cmd = Command::new("ssh");
        cmd.arg("-p").arg(self.port.to_string());
        if let Some(key) = &self.identity_file {
            cmd.arg("-i").arg(key);
        }
        cmd
    }

    pub fn run(&self, sudo: SudoMode, script: &str) -> anyhow::Result<()> {
        let mut cmd = self.ssh_base();
        if sudo.interactive {
            cmd.arg("-tt");
        }

        cmd.arg("--");
        cmd.arg(self.destination());

        if sudo.required {
            cmd.arg("sudo");
            if !sudo.interactive {
                cmd.arg("-n");
            }
        }

        cmd.arg("sh").arg("-c").arg(script);
        let output = run_capture(cmd)?;
        if output.status.success() {
            return Ok(());
        }

        if sudo.required
            && !sudo.interactive
            && looks_like_noninteractive_sudo_failure(&output.stderr)
        {
            anyhow::bail!(
                "sudo failed in non-interactive mode on {}.\n\
Hint: rerun with `--sudo-interactive` or configure passwordless sudo \
(NOPASSWD) for this user.\n\
\nstdout:\n{}\n\
stderr:\n{}",
                self.destination(),
                output.stdout.trim_end(),
                output.stderr.trim_end()
            );
        }

        anyhow::bail!(
            "command failed on {} (status {}):\nstdout:\n{}\nstderr:\n{}",
            self.destination(),
            output.status,
            output.stdout.trim_end(),
            output.stderr.trim_end()
        );
    }

    pub fn run_output(&self, script: &str) -> anyhow::Result<String> {
        let mut cmd = self.ssh_base();
        cmd.arg("--");
        cmd.arg(self.destination());
        cmd.arg("sh").arg("-c").arg(script);
        run_checked(cmd)
    }

    pub fn upload_file(&self, local: &Path, remote: &Path) -> anyhow::Result<()> {
        let local_file = fs::File::open(local)
            .with_context(|| format!("failed to open local upload file {}", local.display()))?;
        let remote_cmd = render_upload_command(remote)?;

        let mut cmd = self.ssh_base();
        cmd.arg("--");
        cmd.arg(self.destination());
        cmd.arg("sh").arg("-c").arg(remote_cmd);
        cmd.stdin(Stdio::from(local_file));

        let output = run_capture(cmd)?;
        if output.status.success() {
            return Ok(());
        }
        anyhow::bail!(
            "failed to upload {} to {}:{} (status {}):\nstdout:\n{}\nstderr:\n{}",
            local.display(),
            self.destination(),
            remote.display(),
            output.status,
            output.stdout.trim_end(),
            output.stderr.trim_end()
        );
    }
}

fn render_upload_command(remote: &Path) -> anyhow::Result<String> {
    let parent = remote.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "invalid upload path (missing parent directory): {}",
            remote.display()
        )
    })?;

    Ok(format!(
        "umask 077; mkdir -p -- {}; cat > {}",
        sh_quote_path(parent),
        sh_quote_path(remote),
    ))
}

#[derive(Debug, Clone, Copy)]
pub struct SudoMode {
    pub required: bool,
    pub interactive: bool,
}

impl SudoMode {
    pub fn root(interactive: bool) -> Self {
        Self {
            required: true,
            interactive,
        }
    }
}

#[derive(Debug, Clone)]
pub enum InstallTarget {
    Local,
    Ssh(SshTarget),
}

impl InstallTarget {
    pub fn detect_arch(&self, sudo_interactive: bool) -> anyhow::Result<LinuxArch> {
        match self {
            InstallTarget::Local => LinuxArch::detect_local(),
            InstallTarget::Ssh(ssh) => {
                let uname = ssh.run_output("uname -m")?;
                let arch = LinuxArch::from_uname(&uname)
                    .with_context(|| format!("failed to parse remote arch from uname: {}", uname))?;
                ssh.run(SudoMode::root(sudo_interactive), "true")
                    .context("remote sudo check failed")?;
                Ok(arch)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_target_parses_user_at_host() {
        let target = SshTarget::from_user_at_host("alice@example.com", None, 22, None);
        assert_eq!(target.host, "example.com");
        assert_eq!(target.user.as_deref(), Some("alice"));
    }

    #[test]
    fn ssh_target_user_override_wins() {
        let target = SshTarget::from_user_at_host("alice@example.com", Some("bob".into()), 22, None);
        assert_eq!(target.host, "example.com");
        assert_eq!(target.user.as_deref(), Some("bob"));
    }

    #[test]
    fn linux_arch_maps_common_uname_values() {
        assert_eq!(LinuxArch::from_uname("x86_64").unwrap().as_str(), "x86_64");
        assert_eq!(LinuxArch::from_uname("amd64").unwrap().as_str(), "x86_64");
        assert_eq!(LinuxArch::from_uname("aarch64").unwrap().as_str(), "aarch64");
        assert_eq!(LinuxArch::from_uname("arm64").unwrap().as_str(), "aarch64");
    }

    #[test]
    fn linux_arch_rejects_unknown_values() {
        let err = LinuxArch::from_uname("i686").expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("unsupported arch"), "{msg}");
        assert!(msg.contains("i686"), "{msg}");
        assert!(msg.contains("x86_64"), "{msg}");
        assert!(msg.contains("aarch64"), "{msg}");
    }

    #[test]
    fn render_upload_command_quotes_parent_and_path() {
        let remote = PathBuf::from("/tmp/fledx dir/it's-here.bin");
        let cmd = render_upload_command(&remote).expect("command");

        let parent = remote.parent().expect("parent");
        let expected = format!(
            "umask 077; mkdir -p -- {}; cat > {}",
            super::super::sh_quote_path(parent),
            super::super::sh_quote_path(&remote)
        );
        assert_eq!(cmd, expected);
    }
}
