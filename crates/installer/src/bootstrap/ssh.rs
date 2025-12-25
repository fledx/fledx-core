use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Context;

use super::{looks_like_noninteractive_sudo_failure, run_capture, sh_quote, sh_quote_path};

#[derive(Debug)]
pub(crate) struct CapturedOutput {
    pub stdout: String,
    pub stderr: String,
    pub status: std::process::ExitStatus,
}

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
            // Raspberry Pi OS 32-bit and other 32-bit ARM distros commonly
            // report these values via `uname -m` / package managers.
            "armv7l" | "armv6l" | "armhf" => anyhow::bail!(
                "unsupported arch '{}' (32-bit ARM); supported: x86_64, aarch64.\n\
Hint: install a 64-bit OS image on the target (so `uname -m` returns aarch64) \
or use a target that matches a supported release asset.",
                normalized
            ),
            other => anyhow::bail!("unsupported arch '{}'; supported: x86_64, aarch64", other),
        }
    }

    /// Parse a noisy `uname` output.
    ///
    /// Some SSH targets print banners/motd text to stdout even for non-login,
    /// non-interactive sessions. In those cases the output may include multiple
    /// whitespace-separated tokens/lines; we scan for a known arch token.
    pub fn from_uname_output(output: &str) -> anyhow::Result<Self> {
        // Prefer tokens near the end since banners usually come first.
        for token in output.split_whitespace().rev() {
            if let Ok(arch) = Self::from_uname(token) {
                return Ok(arch);
            }
        }

        anyhow::bail!(
            "unsupported arch output; expected one of: x86_64, aarch64.\n\
Raw output: {:?}",
            output.trim_end()
        );
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
    pub options: SshOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshHostKeyChecking {
    /// Accept unknown host keys and add them to known_hosts (TOFU).
    ///
    /// This avoids interactive prompts, but does not protect against a MITM on
    /// the very first connection.
    AcceptNew,
    /// Require the host key to already exist in known_hosts.
    Strict,
    /// Disable host key checking (insecure).
    Off,
}

impl SshHostKeyChecking {
    fn strict_host_key_checking_value(self) -> &'static str {
        match self {
            Self::AcceptNew => "accept-new",
            Self::Strict => "yes",
            Self::Off => "no",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SshOptions {
    pub batch_mode: bool,
    pub connect_timeout_secs: u16,
    pub host_key_checking: SshHostKeyChecking,
}

impl Default for SshOptions {
    fn default() -> Self {
        Self {
            batch_mode: true,
            connect_timeout_secs: 10,
            host_key_checking: SshHostKeyChecking::Strict,
        }
    }
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
            options: SshOptions::default(),
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
        cmd.arg("-o").arg(format!(
            "ConnectTimeout={}",
            self.options.connect_timeout_secs
        ));
        cmd.arg("-o").arg("ConnectionAttempts=1");
        cmd.arg("-o").arg(format!(
            "StrictHostKeyChecking={}",
            self.options
                .host_key_checking
                .strict_host_key_checking_value()
        ));
        if self.options.host_key_checking == SshHostKeyChecking::Off {
            cmd.arg("-o").arg("UserKnownHostsFile=/dev/null");
        }

        cmd.arg("-o").arg(format!(
            "BatchMode={}",
            if self.options.batch_mode { "yes" } else { "no" }
        ));

        if let Some(key) = &self.identity_file {
            cmd.arg("-i").arg(key);
            cmd.arg("-o").arg("IdentitiesOnly=yes");
        }
        cmd
    }

    pub fn mktemp_dir(&self, template_prefix: &str) -> anyhow::Result<String> {
        if template_prefix.is_empty() {
            anyhow::bail!("mktemp template prefix must not be empty");
        }
        if template_prefix.chars().any(|ch| ch.is_whitespace()) {
            anyhow::bail!("mktemp template prefix must not contain whitespace");
        }

        let template = format!("{template_prefix}.XXXXXXXXXX");
        let script = format!(
            "umask 077; TMPDIR=/tmp mktemp -d -t {}",
            sh_quote(&template)
        );

        let raw = self.run_output(&script).with_context(|| {
            format!(
                "failed to create remote temp dir on {} using mktemp template {:?}",
                self.destination(),
                template
            )
        })?;

        extract_remote_mktemp_dir(&raw, template_prefix).with_context(|| {
            format!(
                "failed to parse mktemp output from {} (template prefix {:?}).\n\
Raw output: {:?}",
                self.destination(),
                template_prefix,
                raw.trim_end()
            )
        })
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

        if sudo.interactive || !self.options.batch_mode {
            cmd.stdin(Stdio::inherit());
            cmd.stdout(Stdio::inherit());
            cmd.stderr(Stdio::inherit());

            let status = cmd
                .status()
                .with_context(|| format!("failed to run {:?}", cmd))?;
            if status.success() {
                return Ok(());
            }

            anyhow::bail!(
                "command failed on {} (status {})",
                self.destination(),
                status
            );
        }

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

    pub fn run_command(
        &self,
        sudo: SudoMode,
        program: &str,
        args: &[OsString],
    ) -> anyhow::Result<()> {
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

        cmd.arg(program);
        cmd.args(args);

        if sudo.interactive || !self.options.batch_mode {
            cmd.stdin(Stdio::inherit());
            cmd.stdout(Stdio::inherit());
            cmd.stderr(Stdio::inherit());

            let status = cmd
                .status()
                .with_context(|| format!("failed to run {:?}", cmd))?;
            if status.success() {
                return Ok(());
            }

            anyhow::bail!(
                "command failed on {} (status {})",
                self.destination(),
                status
            );
        }

        let output = run_capture(cmd)?;
        if output.status.success() {
            return Ok(());
        }

        if self.options.batch_mode && looks_like_ssh_host_key_failure(&output.stderr) {
            anyhow::bail!(
                "{}\n\nssh stderr:\n{}",
                render_ssh_host_key_failure_hint(self),
                output.stderr.trim_end()
            );
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

        if self.options.batch_mode {
            let output = run_capture(cmd)?;
            if output.status.success() {
                return Ok(output.stdout.trim().to_string());
            }
            if looks_like_ssh_host_key_failure(&output.stderr) {
                anyhow::bail!(
                    "{}\n\nssh stderr:\n{}",
                    render_ssh_host_key_failure_hint(self),
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

        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::inherit());

        let child = cmd
            .spawn()
            .with_context(|| format!("failed to run {:?}", cmd))?;
        let output = child
            .wait_with_output()
            .with_context(|| format!("failed to run {:?}", cmd))?;
        if !output.status.success() {
            anyhow::bail!(
                "command failed on {} (status {})",
                self.destination(),
                output.status
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    pub(crate) fn run_capture_command(
        &self,
        program: &str,
        args: &[OsString],
    ) -> anyhow::Result<CapturedOutput> {
        let mut cmd = self.ssh_base();
        cmd.arg("--");
        cmd.arg(self.destination());
        cmd.arg(program);
        cmd.args(args);

        let output = run_capture(cmd)?;
        Ok(CapturedOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            status: output.status,
        })
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

        if !self.options.batch_mode {
            cmd.stdout(Stdio::inherit());
            cmd.stderr(Stdio::inherit());

            let status = cmd
                .status()
                .with_context(|| format!("failed to run {:?}", cmd))?;
            if status.success() {
                return Ok(());
            }

            anyhow::bail!(
                "failed to upload {} to {}:{} (status {})",
                local.display(),
                self.destination(),
                remote.display(),
                status
            );
        }

        let output = run_capture(cmd)?;
        if output.status.success() {
            return Ok(());
        }
        if self.options.batch_mode && looks_like_ssh_host_key_failure(&output.stderr) {
            anyhow::bail!(
                "{}\n\nssh stderr:\n{}",
                render_ssh_host_key_failure_hint(self),
                output.stderr.trim_end()
            );
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

fn looks_like_ssh_host_key_failure(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("host key verification failed")
        || lower.contains("remote host identification has changed")
        || lower.contains("offending key")
        || lower.contains("man-in-the-middle")
}

fn render_ssh_host_key_failure_hint(target: &SshTarget) -> String {
    let dest = target.destination();
    let host = target.host.as_str();
    let port = target.port;

    format!(
        "ssh host key verification failed for {dest}.\n\
fledx defaults to strict host key checking.\n\
\n\
Fix: establish trust out-of-band, then add the host key to your known_hosts.\n\
\n\
Option 1 (recommended): connect once interactively and verify the fingerprint:\n\
  ssh -p {port} {dest}\n\
\n\
Option 2 (non-interactive): pre-populate known_hosts (verify the fingerprint):\n\
  ssh-keyscan -H -p {port} {host} >> ~/.ssh/known_hosts\n\
\n\
Override (less secure): pass --ssh-host-key-checking accept-new (TOFU) or off."
    )
}

fn extract_remote_mktemp_dir(output: &str, template_prefix: &str) -> anyhow::Result<String> {
    // We expect `mktemp` to output a path that contains the template prefix.
    // However, some SSH targets prepend banner/motd text to stdout even for
    // non-interactive sessions. In those cases the output may contain multiple
    // lines/tokens; we scan for an absolute path token that includes the prefix.
    //
    // We prefer tokens near the end since banners usually come first.
    for token in output.split_whitespace().rev() {
        // Strip common ANSI noise by finding the first slash (if any).
        let Some(slash) = token.find('/') else {
            continue;
        };
        let mut candidate = &token[slash..];

        // Remove common trailing punctuation (\r, :, etc.) which can happen when
        // banners are printed without newlines.
        candidate = candidate.trim_end_matches(
            |ch: char| !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '.' | '_' | '-'),
        );

        if !candidate.starts_with('/') {
            continue;
        }
        if !candidate.contains(template_prefix) {
            continue;
        }
        if candidate.chars().any(|ch| ch.is_control()) {
            continue;
        }
        return Ok(candidate.to_string());
    }

    anyhow::bail!(
        "mktemp output did not contain an absolute path that includes {:?}",
        template_prefix
    );
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
                // Try a few probes since different distros expose arch info in
                // different ways, and some SSH targets prepend banners.
                //
                // Note: Some SSH configurations print banner/motd text to
                // stdout even for non-login sessions. To make debugging easy,
                // we include the raw probe output in error messages.
                const ARCH_PROBE_SCRIPT: &str = "uname -m; \
                     dpkg --print-architecture 2>/dev/null || true; \
                     apk --print-arch 2>/dev/null || true";

                let probe = ssh.run_output(ARCH_PROBE_SCRIPT)?;

                let arch = LinuxArch::from_uname_output(&probe).with_context(|| {
                    format!(
                        "failed to parse remote arch on {} using probe `{}`.\n\
Raw output: {:?}",
                        ssh.destination(),
                        ARCH_PROBE_SCRIPT,
                        probe.trim_end()
                    )
                })?;
                ssh.run(SudoMode::root(sudo_interactive), "true")
                    .context("remote sudo check failed")?;
                Ok(arch)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ENV_LOCK;
    use super::*;
    use std::env;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("set perms");
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: String) -> Self {
            let prev = env::var(key).ok();
            // SAFETY: Tests hold ENV_LOCK to serialize env mutations.
            unsafe {
                env::set_var(key, value);
            }
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: Tests hold ENV_LOCK to serialize env mutations.
            unsafe {
                match &self.prev {
                    Some(value) => env::set_var(self.key, value),
                    None => env::remove_var(self.key),
                }
            }
        }
    }

    fn with_fake_ssh<F, R>(stdout: &str, stderr: &str, exit_code: i32, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let dir = tempdir().expect("tempdir");
        let script = "\
cat >/dev/null\n\
if [ -n \"$FAKE_SSH_STDOUT\" ]; then printf \"%s\" \"$FAKE_SSH_STDOUT\"; fi\n\
if [ -n \"$FAKE_SSH_STDERR\" ]; then printf \"%s\" \"$FAKE_SSH_STDERR\" 1>&2; fi\n\
exit ${FAKE_SSH_EXIT:-0}\n";
        let ssh_path = dir.path().join("ssh");
        fs::write(&ssh_path, format!("#!/bin/sh\n{script}")).expect("write ssh");
        make_executable(&ssh_path);

        let old_path = env::var("PATH").unwrap_or_default();
        let _path_guard =
            EnvVarGuard::set("PATH", format!("{}:{}", dir.path().display(), old_path));
        let _stdout_guard = EnvVarGuard::set("FAKE_SSH_STDOUT", stdout.to_string());
        let _stderr_guard = EnvVarGuard::set("FAKE_SSH_STDERR", stderr.to_string());
        let _exit_guard = EnvVarGuard::set("FAKE_SSH_EXIT", exit_code.to_string());
        f()
    }

    #[test]
    fn ssh_target_parses_user_at_host() {
        let target = SshTarget::from_user_at_host("alice@example.com", None, 22, None);
        assert_eq!(target.host, "example.com");
        assert_eq!(target.user.as_deref(), Some("alice"));
    }

    #[test]
    fn ssh_target_user_override_wins() {
        let target =
            SshTarget::from_user_at_host("alice@example.com", Some("bob".into()), 22, None);
        assert_eq!(target.host, "example.com");
        assert_eq!(target.user.as_deref(), Some("bob"));
    }

    #[test]
    fn linux_arch_maps_common_uname_values() {
        assert_eq!(LinuxArch::from_uname("x86_64").unwrap().as_str(), "x86_64");
        assert_eq!(LinuxArch::from_uname("amd64").unwrap().as_str(), "x86_64");
        assert_eq!(
            LinuxArch::from_uname("aarch64").unwrap().as_str(),
            "aarch64"
        );
        assert_eq!(LinuxArch::from_uname("arm64").unwrap().as_str(), "aarch64");
    }

    #[test]
    fn linux_arch_can_be_extracted_from_noisy_uname_output() {
        let out = "Welcome\nLinux\narm64\n";
        assert_eq!(
            LinuxArch::from_uname_output(out).unwrap().as_str(),
            "aarch64"
        );
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
    fn linux_arch_rejects_32bit_arm_with_hint() {
        let err = LinuxArch::from_uname("armv7l").expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("32-bit ARM"), "{msg}");
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

    #[test]
    fn mktemp_dir_extractor_handles_banners_and_ansi_noise() {
        let out = "\u{1b}[0mWelcome!\r\n/tmp/fledx-bootstrap-agent.ABCDEF\r\n";
        let dir = extract_remote_mktemp_dir(out, "fledx-bootstrap-agent").expect("dir");
        assert_eq!(dir, "/tmp/fledx-bootstrap-agent.ABCDEF");
    }

    #[test]
    fn mktemp_dir_extractor_finds_path_in_mixed_output() {
        let out = "Last login: ...\nSome banner text\n/tmp/fledx-bootstrap-cp.123456\n";
        let dir = extract_remote_mktemp_dir(out, "fledx-bootstrap-cp").expect("dir");
        assert_eq!(dir, "/tmp/fledx-bootstrap-cp.123456");
    }

    #[test]
    fn mktemp_dir_extractor_trims_trailing_punctuation() {
        let out = "Output: /tmp/fledx-bootstrap-cp.123456:\r\n";
        let dir = extract_remote_mktemp_dir(out, "fledx-bootstrap-cp").expect("dir");
        assert_eq!(dir, "/tmp/fledx-bootstrap-cp.123456");
    }

    #[test]
    fn mktemp_dir_extractor_errors_when_prefix_missing() {
        let err = extract_remote_mktemp_dir("Welcome!\n/tmp/other.123\n", "fledx-bootstrap-cp")
            .expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("did not contain an absolute path"), "{msg}");
        assert!(msg.contains("fledx-bootstrap-cp"), "{msg}");
    }

    #[test]
    fn ssh_target_uses_override_user_when_provided() {
        let target =
            SshTarget::from_user_at_host("alice@example.com", Some("bob".to_string()), 22, None);
        assert_eq!(target.user.as_deref(), Some("bob"));
        assert_eq!(target.host, "example.com");
        assert_eq!(target.destination(), "bob@example.com");
    }

    #[test]
    fn ssh_target_destination_without_user_uses_host() {
        let target = SshTarget::from_user_at_host("example.com", None, 22, None);
        assert_eq!(target.user, None);
        assert_eq!(target.destination(), "example.com");
    }

    #[test]
    fn host_key_checking_values_match_expectations() {
        assert_eq!(
            SshHostKeyChecking::AcceptNew.strict_host_key_checking_value(),
            "accept-new"
        );
        assert_eq!(
            SshHostKeyChecking::Strict.strict_host_key_checking_value(),
            "yes"
        );
        assert_eq!(
            SshHostKeyChecking::Off.strict_host_key_checking_value(),
            "no"
        );
    }

    #[test]
    fn host_key_failure_detection_matches_expected_messages() {
        assert!(looks_like_ssh_host_key_failure(
            "Host key verification failed."
        ));
        assert!(looks_like_ssh_host_key_failure(
            "REMOTE HOST IDENTIFICATION HAS CHANGED!"
        ));
        assert!(looks_like_ssh_host_key_failure(
            "Offending key in /home/alice/.ssh/known_hosts:12"
        ));
        assert!(looks_like_ssh_host_key_failure(
            "possible man-in-the-middle attack detected"
        ));
    }

    #[test]
    fn host_key_failure_detection_ignores_unrelated_errors() {
        assert!(!looks_like_ssh_host_key_failure(
            "Permission denied (publickey)."
        ));
    }

    #[test]
    fn host_key_failure_hint_includes_destination_and_port() {
        let target = SshTarget::from_user_at_host("alice@example.com", None, 2222, None);
        let hint = render_ssh_host_key_failure_hint(&target);
        assert!(hint.contains("alice@example.com"), "{hint}");
        assert!(hint.contains("2222"), "{hint}");
        assert!(hint.contains("ssh-keyscan"), "{hint}");
    }

    #[test]
    fn render_upload_command_errors_without_parent() {
        let err = render_upload_command(&PathBuf::from("/")).expect_err("should fail");
        let msg = err.to_string();
        assert!(msg.contains("missing parent directory"), "{msg}");
    }

    #[test]
    fn run_output_returns_trimmed_stdout_in_batch_mode() {
        let target = SshTarget::from_user_at_host("example.com", None, 22, None);
        let out = with_fake_ssh("hello\n", "", 0, || target.run_output("echo hi"));
        assert_eq!(out.expect("stdout"), "hello");
    }

    #[test]
    fn run_output_reports_host_key_failure() {
        let target = SshTarget::from_user_at_host("example.com", None, 22, None);
        let err = with_fake_ssh("", "Host key verification failed.", 255, || {
            target.run_output("echo hi")
        })
        .expect_err("should fail");
        assert!(err.to_string().contains("ssh host key verification failed"));
    }

    #[test]
    fn run_command_reports_noninteractive_sudo_failure() {
        let target = SshTarget::from_user_at_host("example.com", None, 22, None);
        let err = with_fake_ssh("", "sudo: a password is required", 1, || {
            target.run_command(SudoMode::root(false), "true", &[])
        })
        .expect_err("should fail");
        assert!(
            err.to_string()
                .contains("sudo failed in non-interactive mode")
        );
    }

    #[test]
    fn upload_file_succeeds_with_fake_ssh() {
        let target = SshTarget::from_user_at_host("example.com", None, 22, None);
        let dir = tempdir().expect("tempdir");
        let local = dir.path().join("payload.bin");
        fs::write(&local, "payload").expect("write");
        with_fake_ssh("", "", 0, || {
            target
                .upload_file(&local, Path::new("/tmp/remote.bin"))
                .expect("upload");
        });
    }

    #[test]
    fn run_capture_command_returns_stdout_and_status() {
        let target = SshTarget::from_user_at_host("example.com", None, 22, None);
        let output = with_fake_ssh("ok", "warn", 7, || {
            target.run_capture_command("echo", &[OsString::from("hi")])
        })
        .expect("capture");
        assert_eq!(output.stdout, "ok");
        assert_eq!(output.stderr, "warn");
        assert!(!output.status.success());
    }

    #[test]
    fn mktemp_dir_rejects_invalid_prefixes() {
        let target = SshTarget::from_user_at_host("example.com", None, 22, None);
        let err = target.mktemp_dir("").expect_err("empty prefix");
        assert!(err.to_string().contains("must not be empty"));

        let err = target
            .mktemp_dir("bad prefix")
            .expect_err("whitespace prefix");
        assert!(err.to_string().contains("must not contain whitespace"));
    }

    #[test]
    fn mktemp_dir_returns_remote_path() {
        let target = SshTarget::from_user_at_host("example.com", None, 22, None);
        let dir = with_fake_ssh("/tmp/fledx-bootstrap-agent.ABCDEF\n", "", 0, || {
            target.mktemp_dir("fledx-bootstrap-agent")
        })
        .expect("mktemp");
        assert_eq!(dir, "/tmp/fledx-bootstrap-agent.ABCDEF");
    }

    #[test]
    fn run_reports_noninteractive_sudo_failure() {
        let target = SshTarget::from_user_at_host("example.com", None, 22, None);
        let err = with_fake_ssh("", "sudo: a password is required", 1, || {
            target.run(SudoMode::root(false), "true")
        })
        .expect_err("should fail");
        assert!(
            err.to_string()
                .contains("sudo failed in non-interactive mode")
        );
    }

    #[test]
    fn run_command_reports_host_key_failure() {
        let target = SshTarget::from_user_at_host("example.com", None, 22, None);
        let err = with_fake_ssh("", "Host key verification failed.", 255, || {
            target.run_command(SudoMode::root(false), "true", &[])
        })
        .expect_err("should fail");
        assert!(err.to_string().contains("ssh host key verification failed"));
    }

    #[test]
    fn upload_file_reports_host_key_failure() {
        let target = SshTarget::from_user_at_host("example.com", None, 22, None);
        let dir = tempdir().expect("tempdir");
        let local = dir.path().join("payload.bin");
        fs::write(&local, "payload").expect("write");
        let err = with_fake_ssh("", "Host key verification failed.", 255, || {
            target.upload_file(&local, Path::new("/tmp/remote.bin"))
        })
        .expect_err("should fail");
        assert!(err.to_string().contains("ssh host key verification failed"));
    }
}
