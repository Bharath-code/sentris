use clap::ValueEnum;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellType {
    Bash,
    Zsh,
    Fish,
}

pub struct CompletionGenerator;

impl CompletionGenerator {
    pub fn generate(shell: ShellType) -> &'static str {
        match shell {
            ShellType::Bash => BASH_COMPLETION,
            ShellType::Zsh => ZSH_COMPLETION,
            ShellType::Fish => FISH_COMPLETION,
        }
    }
}

const BASH_COMPLETION: &str = r#"# bash completion for sentris
_sentris() {
    local cur prev words cword
    _init_completion || return

    local commands="scan install uninstall remediate rollback quarantine completions help"
    local formats="text json sarif"

    case "${prev}" in
        sentris)
            COMPREPLY=( $(compgen -W "${commands} -h --help -V --version -q --quiet --no-color" -- "${cur}") )
            return 0
            ;;
        --format|-f)
            COMPREPLY=( $(compgen -W "${formats}" -- "${cur}") )
            return 0
            ;;
        completions)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") )
            return 0
            ;;
        scan)
            COMPREPLY=( $(compgen -W "--staged --git-history --fail-on-secret --format -q --quiet --no-color -h --help" -- "${cur}") )
            return 0
            ;;
        remediate)
            COMPREPLY=( $(compgen -W "--dry-run --yes -y -h --help" -- "${cur}") )
            return 0
            ;;
        rollback)
            COMPREPLY=( $(compgen -W "--session -s -h --help" -- "${cur}") )
            return 0
            ;;
        quarantine)
            COMPREPLY=( $(compgen -W "--branch -b -h --help" -- "${cur}") )
            return 0
            ;;
    esac

    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "--help --version --quiet --no-color" -- "${cur}") )
    fi
}
complete -F _sentris sentris
"#;

const ZSH_COMPLETION: &str = r#"#compdef sentris

_sentris() {
    local -a commands
    commands=(
        'scan:Recursively scan files and directories for hardcoded credentials'
        'install:Install the Sentris pre-commit hook into .git/hooks/pre-commit'
        'uninstall:Uninstall the Sentris pre-commit hook'
        'remediate:Safely auto-remediate a detected secret finding'
        'rollback:Revert a previous remediation session and restore original files'
        'quarantine:Isolate a leaked credential into a Zone 3 quarantine branch'
        'completions:Generate shell autocompletion script'
        'help:Print help information'
    )

    _arguments -C \
        '(-q --quiet)'{-q,--quiet}'[Suppress non-essential output]' \
        '--no-color[Disable colored terminal output]' \
        '(-h --help)'{-h,--help}'[Print help information]' \
        '(-V --version)'{-V,--version}'[Print version information]' \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe -t commands 'sentris command' commands
            ;;
        args)
            case $line[1] in
                scan)
                    _arguments \
                        '--staged[Scan git staged files/diffs]' \
                        '--git-history[Scan deep git commit history and reflog]' \
                        '--fail-on-secret[Exit with non-zero code if secret detected]' \
                        '(-f --format)'{-f,--format}'[Output format]:format:(text json sarif)' \
                        '*:path:_files'
                    ;;
                remediate)
                    _arguments \
                        '--dry-run[Run in preview mode without API changes]' \
                        '(-y --yes)'{-y,--yes}'[Auto-approve confirmation prompts]' \
                        '1:finding_id:'
                    ;;
                rollback)
                    _arguments \
                        '(-s --session)'{-s,--session}'[Session ID to revert]:session_id:'
                    ;;
                quarantine)
                    _arguments \
                        '(-b --branch)'{-b,--branch}'[Custom branch name]:branch_name:' \
                        '1:finding_id:'
                    ;;
                completions)
                    _arguments \
                        '1:shell:(bash zsh fish)'
                    ;;
            esac
            ;;
    esac
}

_sentris "$@"
"#;

const FISH_COMPLETION: &str = r#"# fish completion for sentris

complete -c sentris -f -n "__fish_use_subcommand" -a scan -d "Recursively scan files for credentials"
complete -c sentris -f -n "__fish_use_subcommand" -a install -d "Install pre-commit hook"
complete -c sentris -f -n "__fish_use_subcommand" -a uninstall -d "Uninstall pre-commit hook"
complete -c sentris -f -n "__fish_use_subcommand" -a remediate -d "Safely auto-remediate a secret finding"
complete -c sentris -f -n "__fish_use_subcommand" -a rollback -d "Revert a remediation session"
complete -c sentris -f -n "__fish_use_subcommand" -a quarantine -d "Isolate leaked credential into Zone 3 branch"
complete -c sentris -f -n "__fish_use_subcommand" -a completions -d "Generate shell completion script"

# Global flags
complete -c sentris -s q -l quiet -d "Suppress non-essential output"
complete -c sentris -l no-color -d "Disable colored terminal output"
complete -c sentris -s h -l help -d "Print help"
complete -c sentris -s V -l version -d "Print version"

# Subcommand flags
complete -c sentris -n "__fish_seen_subcommand_from scan" -l staged -d "Scan staged git index diffs"
complete -c sentris -n "__fish_seen_subcommand_from scan" -l git-history -d "Scan commit graph history"
complete -c sentris -n "__fish_seen_subcommand_from scan" -l fail-on-secret -d "Exit with code 1 if secrets found"
complete -c sentris -n "__fish_seen_subcommand_from scan" -s f -l format -a "text json sarif" -d "Output format"

complete -c sentris -n "__fish_seen_subcommand_from remediate" -l dry-run -d "Preview without mutating APIs"
complete -c sentris -n "__fish_seen_subcommand_from remediate" -s y -l yes -d "Auto-approve confirmation"

complete -c sentris -n "__fish_seen_subcommand_from completions" -a "bash zsh fish" -d "Target shell"
"#;
