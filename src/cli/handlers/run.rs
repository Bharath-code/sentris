use std::process::{self, Command, Stdio};

use super::{die, fail};
use crate::error::SentrisError;
use crate::remediator::backend::{SecretBackendFactory, SecretStoreBackend};
use crate::remediator::Remediator;

/// Validates that no command-line argument contains a `{{secret:...}}` placeholder,
/// preventing secrets from ever being expanded into process `argv` (visible via `ps`).
pub fn validate_argv_no_secret_placeholders(args: &[String]) -> Result<(), SentrisError> {
    for arg in args {
        if arg.contains("{{secret:") {
            return Err(SentrisError::Refused(format!(
                "Argument '{arg}' contains a '{{{{secret:...}}}}' placeholder. Expanding secrets into argv exposes them to local users via `ps`. Reference the secret via its environment variable inside the child process instead."
            )));
        }
    }
    Ok(())
}

/// Fetches all requested `keys` from `backend` and spawns `command_args` with those keys injected
/// into the child process's environment only. Returns the child's exit code.
pub fn run_with_injected_env(
    backend: &dyn SecretStoreBackend,
    keys: &[String],
    command_args: &[String],
) -> Result<i32, SentrisError> {
    let Some((program, args)) = command_args.split_first() else {
        return Err(SentrisError::Config(
            "No command specified to run (usage: sentris run --key NAME -- <cmd> [args...])".into(),
        ));
    };
    validate_argv_no_secret_placeholders(command_args)?;

    let mut resolved: Vec<(String, String)> = Vec::with_capacity(keys.len());
    for key in keys {
        let val = backend.fetch_secret(key)?;
        resolved.push((key.clone(), val));
    }

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (k, v) in &resolved {
        cmd.env(k, v);
    }

    let status_res = cmd.status();
    for (_, mut v) in resolved {
        Remediator::zeroize_secret_string(&mut v);
    }

    let status = status_res
        .map_err(|e| SentrisError::Scan(format!("Failed to execute command '{program}': {e}")))?;
    Ok(status.code().unwrap_or(130))
}

/// Auto-discovers required secret variable names from `.env.example` and `.env` in `dir`
/// when the caller omits explicit `--key` flags on `sentris run`.
pub fn discover_keys_in_dir(dir: &std::path::Path) -> Vec<String> {
    let mut keys = Vec::new();
    for file_name in [".env.example", ".env"] {
        let path = dir.join(file_name);
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for raw_line in content.lines() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let without_export = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
            let Some((name, _)) = without_export.split_once('=') else {
                continue;
            };
            let key = name.trim();
            if !key.is_empty()
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && !keys.iter().any(|existing| existing == key)
            {
                keys.push(key.to_string());
            }
        }
    }
    keys
}

pub fn handle_run(backend_name: String, keys: Vec<String>, command_args: Vec<String>) {
    let backend = SecretBackendFactory::from_name(&backend_name)
        .unwrap_or_else(|e| die("Invalid secret backend", e));
    let effective_keys = if keys.is_empty() {
        discover_keys_in_dir(std::path::Path::new("."))
    } else {
        keys
    };
    if effective_keys.is_empty() {
        fail("No `--key <ENV_VAR_NAME>` specified and no keys found in `.env.example` or `.env` (e.g. `sentris run --backend 1password -- npm start` or `sentris run --key STRIPE_SECRET_KEY -- npm start`).");
    }
    match run_with_injected_env(backend.as_ref(), &effective_keys, &command_args) {
        Ok(code) => process::exit(code),
        Err(SentrisError::Refused(msg)) => {
            eprintln!("REFUSED: {msg}");
            process::exit(2);
        }
        Err(err) => die("sentris run failed", err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediator::backend::VaultBackend;

    #[test]
    fn refuses_secret_placeholder_in_argv() {
        let args = vec![
            "curl".to_string(),
            "-H".to_string(),
            "Authorization: Bearer {{secret:API_KEY}}".to_string(),
        ];
        let err = validate_argv_no_secret_placeholders(&args).unwrap_err();
        assert!(matches!(err, SentrisError::Refused(_)));
        assert!(err.to_string().contains("ps"));
    }

    #[cfg(unix)]
    #[test]
    fn injects_secret_into_child_env_and_preserves_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let vault = VaultBackend::new()
            .with_mock(true)
            .with_mock_ledger_path(dir.path().join("vault.json"));
        vault
            .inject_secret("TEST_INJECTED_SECRET", "super_secret_runtime_val", false)
            .unwrap();

        let out_file = dir.path().join("child_env.txt");
        let cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "printf '%s' \"$TEST_INJECTED_SECRET\" > {} && exit 42",
                out_file.display()
            ),
        ];
        let code =
            run_with_injected_env(&vault, &["TEST_INJECTED_SECRET".to_string()], &cmd).unwrap();
        assert_eq!(code, 42);
        let written = std::fs::read_to_string(&out_file).unwrap();
        assert_eq!(written, "super_secret_runtime_val");
    }

    #[test]
    fn auto_discovers_keys_from_dotenv_example_and_dotenv() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env.example"),
            "# Required secrets\nSTRIPE_SECRET_KEY=\nexport DATABASE_URL=\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "STRIPE_SECRET_KEY=sk_test\nOPENAI_API_KEY=sk_proj\n",
        )
        .unwrap();

        let keys = discover_keys_in_dir(dir.path());
        assert_eq!(
            keys,
            vec![
                "STRIPE_SECRET_KEY".to_string(),
                "DATABASE_URL".to_string(),
                "OPENAI_API_KEY".to_string(),
            ]
        );
    }
}
