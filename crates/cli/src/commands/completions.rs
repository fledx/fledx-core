use std::io;

use clap::CommandFactory;
use clap_complete::generate;
use clap_complete::shells::{Bash, Fish, Zsh};

use crate::args::{Cli, CompletionShell};

pub fn generate_completions(shell: CompletionShell) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    match shell {
        CompletionShell::Bash => {
            generate(Bash, &mut cmd, name.clone(), &mut io::stdout());
        }
        CompletionShell::Zsh => {
            generate(Zsh, &mut cmd, name.clone(), &mut io::stdout());
        }
        CompletionShell::Fish => {
            generate(Fish, &mut cmd, name, &mut io::stdout());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_completions_for_supported_shells() {
        generate_completions(CompletionShell::Bash);
        generate_completions(CompletionShell::Zsh);
        generate_completions(CompletionShell::Fish);
    }
}
