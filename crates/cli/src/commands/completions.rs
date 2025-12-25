use std::io::{self, Write};

use clap::CommandFactory;
use clap_complete::generate;
use clap_complete::shells::{Bash, Fish, Zsh};

use crate::args::{Cli, CompletionShell};

pub fn generate_completions(shell: CompletionShell) -> anyhow::Result<()> {
    let mut stdout = io::stdout();
    generate_completions_to(shell, &mut stdout)?;
    Ok(())
}

fn generate_completions_to<W: Write>(shell: CompletionShell, writer: &mut W) -> io::Result<()> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    let mut buffer = Vec::new();
    match shell {
        CompletionShell::Bash => {
            generate(Bash, &mut cmd, name.clone(), &mut buffer);
        }
        CompletionShell::Zsh => {
            generate(Zsh, &mut cmd, name.clone(), &mut buffer);
        }
        CompletionShell::Fish => {
            generate(Fish, &mut cmd, name, &mut buffer);
        }
    }

    writer.write_all(&buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn generate_completions_for_supported_shells() -> io::Result<()> {
        let mut buffer = Vec::new();

        generate_completions_to(CompletionShell::Bash, &mut buffer)?;
        assert!(!buffer.is_empty());
        buffer.clear();

        generate_completions_to(CompletionShell::Zsh, &mut buffer)?;
        assert!(!buffer.is_empty());
        buffer.clear();

        generate_completions_to(CompletionShell::Fish, &mut buffer)?;
        assert!(!buffer.is_empty());

        Ok(())
    }

    #[test]
    fn generate_completions_fails_on_write_error() {
        let mut writer = FailingWriter;

        let result = generate_completions_to(CompletionShell::Bash, &mut writer);

        assert!(result.is_err());
    }
}
