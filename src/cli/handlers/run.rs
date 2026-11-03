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

    let status = status_res.map_err(|e| {
        SentrisError::Scan(format!("Failed to execute command '{program}': {e}"))
    })?;
    Ok(status.code().unwrap_or(130))
}

pub fn handle_run(backend_name: String, keys: Vec<String>, command_args: Vec<String>) {
    let backend = SecretBackendFactory::from_name(&backend_name)
        .unwrap_or_else(|e| die("Invalid secret backend", e));
    if keys.is_empty() {
        fail("Pass at least one `--key <ENV_VAR_NAME>` to inject into the child environment (e.g. `sentris run --backend vault --key STRIPE_SECRET_KEY -- npm start`).");
    }
    match run_with_injected_env(backend.as_ref(), &keys, &command_args) {
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
}
