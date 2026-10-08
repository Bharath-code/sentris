use crate::error::SentrisError;
use std::fs;
use std::path::Path;

pub struct CodeReplacer;

impl CodeReplacer {
    /// Generates the idiomatic environment variable accessor for the given file extension.
    pub fn get_env_accessor(file_path: &str, var_name: &str) -> String {
        let path = Path::new(file_path);
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Handle dotfiles like .env, .env.local, .env.production
        if file_name == ".env" || file_name.starts_with(".env.") || file_name.ends_with(".env") {
            return var_name.to_string();
        }

        match ext.as_str() {
            "ts" | "js" | "tsx" | "jsx" | "mjs" | "cjs" => {
                format!("process.env.{var_name}")
            }
            "py" => {
                format!("os.environ.get(\"{var_name}\")")
            }
            "rs" => {
                format!("std::env::var(\"{var_name}\").expect(\"{var_name} must be set\")")
            }
            "go" => {
                format!("os.Getenv(\"{var_name}\")")
            }
            "java" => {
                format!("System.getenv(\"{var_name}\")")
            }
            "cs" => {
                format!("Environment.GetEnvironmentVariable(\"{var_name}\")")
            }
            "rb" => {
                format!("ENV[\"{var_name}\"]")
            }
            "php" => {
                format!("getenv(\"{var_name}\")")
            }
            "sh" | "bash" | "zsh" => {
                format!("\"${{{var_name}}}\"")
            }
            "env" | "yml" | "yaml" | "toml" | "ini" => var_name.to_string(),
            _ => format!("process.env.{var_name}"),
        }
    }

    /// Replaces the hardcoded secret in a line of code with the appropriate env var expression.
    /// Handles string quoting and language-specific interpolation/substitution without leftover quotes.
    pub fn replace_secret_in_line(
        file_path: &str,
        target_line: &str,
        secret: &str,
        var_name: &str,
    ) -> String {
        let accessor = Self::get_env_accessor(file_path, var_name);
        let path = Path::new(file_path);
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let is_shell = matches!(ext.as_str(), "sh" | "bash" | "zsh");

        // Quoted patterns in descending order of specificity
        let r_hash_double = format!("r#\"{secret}\"#");
        let r_hash_single = format!("r#'{secret}'#");
        let r_double = format!("r\"{secret}\"");
        let r_single = format!("r'{secret}'");
        let b_double = format!("b\"{secret}\"");
        let b_single = format!("b'{secret}'");
        let f_double = format!("f\"{secret}\"");
        let f_single = format!("f'{secret}'");
        let triple_double = format!("\"\"\"{secret}\"\"\"");
        let triple_single = format!("'''{secret}'''");
        let double_quoted = format!("\"{secret}\"");
        let single_quoted = format!("'{secret}'");
        let backtick_quoted = format!("`{secret}`");

        if target_line.contains(&r_hash_double) {
            target_line.replace(&r_hash_double, &accessor)
        } else if target_line.contains(&r_hash_single) {
            target_line.replace(&r_hash_single, &accessor)
        } else if target_line.contains(&r_double) {
            target_line.replace(&r_double, &accessor)
        } else if target_line.contains(&r_single) {
            target_line.replace(&r_single, &accessor)
        } else if target_line.contains(&b_double) {
            target_line.replace(&b_double, &accessor)
        } else if target_line.contains(&b_single) {
            target_line.replace(&b_single, &accessor)
        } else if target_line.contains(&f_double) {
            target_line.replace(&f_double, &accessor)
        } else if target_line.contains(&f_single) {
            target_line.replace(&f_single, &accessor)
        } else if target_line.contains(&triple_double) {
            target_line.replace(&triple_double, &accessor)
        } else if target_line.contains(&triple_single) {
            target_line.replace(&triple_single, &accessor)
        } else if target_line.contains(&double_quoted) {
            target_line.replace(&double_quoted, &accessor)
        } else if target_line.contains(&single_quoted) {
            target_line.replace(&single_quoted, &accessor)
        } else if target_line.contains(&backtick_quoted) {
            target_line.replace(&backtick_quoted, &accessor)
        } else if is_shell && is_inside_quotes(target_line, secret, '"') {
            // In shell scripts, if secret is already embedded inside an existing double-quoted string,
            // interpolate with ${VAR_NAME} without introducing redundant outer quotes.
            let shell_interpolated = format!("${{{var_name}}}");
            target_line.replace(secret, &shell_interpolated)
        } else {
            target_line.replace(secret, &accessor)
        }
    }

    /// Replaces the hardcoded secret in the target file at line_number with the env var expression
    pub fn replace_secret(
        file_path: &str,
        line_number: usize,
        secret: &str,
        var_name: &str,
    ) -> Result<(String, String), SentrisError> {
        let path = Path::new(file_path);
        if !path.exists() {
            return Err(SentrisError::Scan(format!(
                "Target file does not exist: {file_path}"
            )));
        }

        let content = fs::read_to_string(path)?;
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

        if line_number == 0 || line_number > lines.len() {
            return Err(SentrisError::Scan(format!(
                "Invalid line number {line_number} for file {file_path}"
            )));
        }

        let target_line = &lines[line_number - 1];
        let original_line = target_line.clone();

        let replacement_line =
            Self::replace_secret_in_line(file_path, target_line, secret, var_name);

        lines[line_number - 1] = replacement_line.clone();
        let trailing_newline = if content.ends_with("\r\n") {
            "\r\n"
        } else if content.ends_with('\n') {
            "\n"
        } else {
            ""
        };
        fs::write(path, format!("{}{}", lines.join("\n"), trailing_newline))?;

        Ok((original_line, replacement_line))
    }
}

/// Helper to determine if a substring is inside an unescaped pair of quotes in a line.
fn is_inside_quotes(line: &str, substring: &str, quote: char) -> bool {
    if let Some(idx) = line.find(substring) {
        let before = &line[..idx];
        let after = &line[idx + substring.len()..];

        let count_unescaped = |s: &str| -> usize {
            let mut count = 0;
            let mut prev_backslash = false;
            for c in s.chars() {
                if c == '\\' {
                    prev_backslash = !prev_backslash;
                } else {
                    if c == quote && !prev_backslash {
                        count += 1;
                    }
                    prev_backslash = false;
                }
            }
            count
        };

        let count_before = count_unescaped(before);
        let count_after = count_unescaped(after);
        count_before % 2 == 1 && count_after % 2 == 1
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_accessor_generation_typescript_and_javascript() {
        for ext in ["ts", "js", "tsx", "jsx", "mjs", "cjs"] {
            let file_name = format!("service.{ext}");
            assert_eq!(
                CodeReplacer::get_env_accessor(&file_name, "STRIPE_KEY"),
                "process.env.STRIPE_KEY",
                "Failed for extension: {ext}"
            );
        }
    }

    #[test]
    fn test_accessor_generation_python() {
        assert_eq!(
            CodeReplacer::get_env_accessor("server.py", "STRIPE_KEY"),
            "os.environ.get(\"STRIPE_KEY\")"
        );
    }

    #[test]
    fn test_accessor_generation_rust() {
        assert_eq!(
            CodeReplacer::get_env_accessor("main.rs", "STRIPE_KEY"),
            "std::env::var(\"STRIPE_KEY\").expect(\"STRIPE_KEY must be set\")"
        );
    }

    #[test]
    fn test_accessor_generation_go() {
        assert_eq!(
            CodeReplacer::get_env_accessor("client.go", "STRIPE_KEY"),
            "os.Getenv(\"STRIPE_KEY\")"
        );
    }

    #[test]
    fn test_accessor_generation_java() {
        assert_eq!(
            CodeReplacer::get_env_accessor("App.java", "STRIPE_KEY"),
            "System.getenv(\"STRIPE_KEY\")"
        );
    }

    #[test]
    fn test_accessor_generation_csharp() {
        assert_eq!(
            CodeReplacer::get_env_accessor("Program.cs", "STRIPE_KEY"),
            "Environment.GetEnvironmentVariable(\"STRIPE_KEY\")"
        );
    }

    #[test]
    fn test_accessor_generation_ruby() {
        assert_eq!(
            CodeReplacer::get_env_accessor("config.rb", "STRIPE_KEY"),
            "ENV[\"STRIPE_KEY\"]"
        );
    }

    #[test]
    fn test_accessor_generation_php() {
        assert_eq!(
            CodeReplacer::get_env_accessor("index.php", "STRIPE_KEY"),
            "getenv(\"STRIPE_KEY\")"
        );
    }

    #[test]
    fn test_accessor_generation_shell() {
        for ext in ["sh", "bash", "zsh"] {
            let file_name = format!("deploy.{ext}");
            assert_eq!(
                CodeReplacer::get_env_accessor(&file_name, "STRIPE_KEY"),
                "\"${STRIPE_KEY}\"",
                "Failed for shell extension: {ext}"
            );
        }
    }

    #[test]
    fn test_accessor_generation_configs_and_env() {
        for ext in ["env", "yml", "yaml", "toml", "ini"] {
            let file_name = format!("settings.{ext}");
            assert_eq!(
                CodeReplacer::get_env_accessor(&file_name, "STRIPE_KEY"),
                "STRIPE_KEY",
                "Failed for config extension: {ext}"
            );
        }

        // Test dotfiles
        assert_eq!(
            CodeReplacer::get_env_accessor(".env", "STRIPE_KEY"),
            "STRIPE_KEY"
        );
        assert_eq!(
            CodeReplacer::get_env_accessor(".env.local", "STRIPE_KEY"),
            "STRIPE_KEY"
        );
        assert_eq!(
            CodeReplacer::get_env_accessor("/path/to/.env.production", "STRIPE_KEY"),
            "STRIPE_KEY"
        );
    }

    #[test]
    fn test_accessor_generation_case_insensitivity_and_fallback() {
        assert_eq!(
            CodeReplacer::get_env_accessor("Component.TSX", "API_KEY"),
            "process.env.API_KEY"
        );
        assert_eq!(
            CodeReplacer::get_env_accessor("script.PY", "API_KEY"),
            "os.environ.get(\"API_KEY\")"
        );
        assert_eq!(
            CodeReplacer::get_env_accessor("MAIN.GO", "API_KEY"),
            "os.Getenv(\"API_KEY\")"
        );
        assert_eq!(
            CodeReplacer::get_env_accessor("Unknown.txt", "API_KEY"),
            "process.env.API_KEY"
        );
    }

    #[test]
    fn test_string_replacement_typescript() {
        let secret = "sk_live_123";
        let var = "STRIPE_SECRET_KEY";

        // Double quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "app.ts",
                "const key = \"sk_live_123\";",
                secret,
                var
            ),
            "const key = process.env.STRIPE_SECRET_KEY;"
        );

        // Single quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "app.tsx",
                "const key = 'sk_live_123';",
                secret,
                var
            ),
            "const key = process.env.STRIPE_SECRET_KEY;"
        );

        // Template literals (backticks)
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "app.js",
                "const key = `sk_live_123`;",
                secret,
                var
            ),
            "const key = process.env.STRIPE_SECRET_KEY;"
        );

        // Object property
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "app.ts",
                "  apiKey: \"sk_live_123\",",
                secret,
                var
            ),
            "  apiKey: process.env.STRIPE_SECRET_KEY,"
        );
    }

    #[test]
    fn test_string_replacement_python() {
        let secret = "sk_live_123";
        let var = "STRIPE_SECRET_KEY";

        // Double quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line("server.py", "key = \"sk_live_123\"", secret, var),
            "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
        );

        // Single quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line("server.py", "key = 'sk_live_123'", secret, var),
            "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
        );

        // Triple double quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "server.py",
                "key = \"\"\"sk_live_123\"\"\"",
                secret,
                var
            ),
            "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
        );

        // Triple single quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "server.py",
                "key = '''sk_live_123'''",
                secret,
                var
            ),
            "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
        );

        // Raw / Byte strings
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "server.py",
                "key = r\"sk_live_123\"",
                secret,
                var
            ),
            "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
        );
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "server.py",
                "key = b\"sk_live_123\"",
                secret,
                var
            ),
            "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
        );
    }

    #[test]
    fn test_string_replacement_go() {
        let secret = "sk_live_123";
        let var = "STRIPE_SECRET_KEY";

        // Standard string literal
        assert_eq!(
            CodeReplacer::replace_secret_in_line("main.go", "key := \"sk_live_123\"", secret, var),
            "key := os.Getenv(\"STRIPE_SECRET_KEY\")"
        );

        // Raw string literal (backticks)
        assert_eq!(
            CodeReplacer::replace_secret_in_line("main.go", "key := `sk_live_123`", secret, var),
            "key := os.Getenv(\"STRIPE_SECRET_KEY\")"
        );

        // Struct assignment
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "main.go",
                "\tApiKey: \"sk_live_123\",",
                secret,
                var
            ),
            "\tApiKey: os.Getenv(\"STRIPE_SECRET_KEY\"),"
        );
    }

    #[test]
    fn test_string_replacement_rust() {
        let secret = "sk_live_123";
        let var = "STRIPE_SECRET_KEY";

        // Standard string
        assert_eq!(
            CodeReplacer::replace_secret_in_line("main.rs", "let key = \"sk_live_123\";", secret, var),
            "let key = std::env::var(\"STRIPE_SECRET_KEY\").expect(\"STRIPE_SECRET_KEY must be set\");"
        );

        // Raw string literal
        assert_eq!(
            CodeReplacer::replace_secret_in_line("main.rs", "let key = r#\"sk_live_123\"#;", secret, var),
            "let key = std::env::var(\"STRIPE_SECRET_KEY\").expect(\"STRIPE_SECRET_KEY must be set\");"
        );

        // Raw string literal without hashes
        assert_eq!(
            CodeReplacer::replace_secret_in_line("main.rs", "let key = r\"sk_live_123\";", secret, var),
            "let key = std::env::var(\"STRIPE_SECRET_KEY\").expect(\"STRIPE_SECRET_KEY must be set\");"
        );
    }

    #[test]
    fn test_string_replacement_java() {
        let secret = "sk_live_123";
        let var = "STRIPE_SECRET_KEY";

        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "App.java",
                "String apiKey = \"sk_live_123\";",
                secret,
                var
            ),
            "String apiKey = System.getenv(\"STRIPE_SECRET_KEY\");"
        );

        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "App.java",
                "client.setApiKey(\"sk_live_123\");",
                secret,
                var
            ),
            "client.setApiKey(System.getenv(\"STRIPE_SECRET_KEY\"));"
        );
    }

    #[test]
    fn test_string_replacement_csharp() {
        let secret = "sk_live_123";
        let var = "STRIPE_SECRET_KEY";

        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "Program.cs",
                "string apiKey = \"sk_live_123\";",
                secret,
                var
            ),
            "string apiKey = Environment.GetEnvironmentVariable(\"STRIPE_SECRET_KEY\");"
        );

        assert_eq!(
            CodeReplacer::replace_secret_in_line("Program.cs", "var opt = new Options { Key = \"sk_live_123\" };", secret, var),
            "var opt = new Options { Key = Environment.GetEnvironmentVariable(\"STRIPE_SECRET_KEY\") };"
        );
    }

    #[test]
    fn test_string_replacement_ruby() {
        let secret = "sk_live_123";
        let var = "STRIPE_SECRET_KEY";

        // Double quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "app.rb",
                "stripe_key = \"sk_live_123\"",
                secret,
                var
            ),
            "stripe_key = ENV[\"STRIPE_SECRET_KEY\"]"
        );

        // Single quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "app.rb",
                "stripe_key = 'sk_live_123'",
                secret,
                var
            ),
            "stripe_key = ENV[\"STRIPE_SECRET_KEY\"]"
        );

        // Hash dictionary
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "app.rb",
                "config = { key: \"sk_live_123\" }",
                secret,
                var
            ),
            "config = { key: ENV[\"STRIPE_SECRET_KEY\"] }"
        );
    }

    #[test]
    fn test_string_replacement_php() {
        let secret = "sk_live_123";
        let var = "STRIPE_SECRET_KEY";

        // Double quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "index.php",
                "$apiKey = \"sk_live_123\";",
                secret,
                var
            ),
            "$apiKey = getenv(\"STRIPE_SECRET_KEY\");"
        );

        // Single quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "index.php",
                "$apiKey = 'sk_live_123';",
                secret,
                var
            ),
            "$apiKey = getenv(\"STRIPE_SECRET_KEY\");"
        );

        // Array assignment
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "index.php",
                "$config = ['key' => \"sk_live_123\"];",
                secret,
                var
            ),
            "$config = ['key' => getenv(\"STRIPE_SECRET_KEY\")];"
        );
    }

    #[test]
    fn test_string_replacement_shell() {
        let secret = "sk_live_123";
        let var = "STRIPE_SECRET_KEY";

        // Quoted assignment
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "deploy.sh",
                "export STRIPE_KEY=\"sk_live_123\"",
                secret,
                var
            ),
            "export STRIPE_KEY=\"${STRIPE_SECRET_KEY}\""
        );

        // Single-quoted assignment (must change to double quotes so variable can expand)
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "deploy.bash",
                "STRIPE_KEY='sk_live_123'",
                secret,
                var
            ),
            "STRIPE_KEY=\"${STRIPE_SECRET_KEY}\""
        );

        // Unquoted assignment
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "deploy.zsh",
                "STRIPE_KEY=sk_live_123",
                secret,
                var
            ),
            "STRIPE_KEY=\"${STRIPE_SECRET_KEY}\""
        );

        // Interpolation inside existing double quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "deploy.sh",
                "curl -H \"Authorization: Bearer sk_live_123\" https://api.stripe.com",
                secret,
                var
            ),
            "curl -H \"Authorization: Bearer ${STRIPE_SECRET_KEY}\" https://api.stripe.com"
        );
    }

    #[test]
    fn test_string_replacement_yaml_and_configs() {
        let secret = "sk_live_123";
        let var = "STRIPE_SECRET_KEY";

        // YAML double quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "config.yml",
                "stripe_key: \"sk_live_123\"",
                secret,
                var
            ),
            "stripe_key: STRIPE_SECRET_KEY"
        );

        // YAML single quotes
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "config.yaml",
                "stripe_key: 'sk_live_123'",
                secret,
                var
            ),
            "stripe_key: STRIPE_SECRET_KEY"
        );

        // YAML unquoted
        assert_eq!(
            CodeReplacer::replace_secret_in_line(
                "config.yaml",
                "stripe_key: sk_live_123",
                secret,
                var
            ),
            "stripe_key: STRIPE_SECRET_KEY"
        );

        // .env assignment
        assert_eq!(
            CodeReplacer::replace_secret_in_line(".env", "STRIPE_KEY=\"sk_live_123\"", secret, var),
            "STRIPE_KEY=STRIPE_SECRET_KEY"
        );

        // TOML configuration
        assert_eq!(
            CodeReplacer::replace_secret_in_line("app.toml", "key = \"sk_live_123\"", secret, var),
            "key = STRIPE_SECRET_KEY"
        );

        // INI configuration
        assert_eq!(
            CodeReplacer::replace_secret_in_line("app.ini", "key = \"sk_live_123\"", secret, var),
            "key = STRIPE_SECRET_KEY"
        );
    }

    #[test]
    fn test_replace_secret_file_mutations() {
        let mut tmp = NamedTempFile::new().unwrap();
        let original_content = "import os\n\nkey = \"sk_live_123\"\nprint(key)\n";
        tmp.write_all(original_content.as_bytes()).unwrap();

        let path = tmp.path().to_str().unwrap().to_string();
        // Rename or simulate .py extension
        let py_path = format!("{path}.py");
        std::fs::copy(&path, &py_path).unwrap();

        let (orig, replaced) =
            CodeReplacer::replace_secret(&py_path, 3, "sk_live_123", "STRIPE_SECRET_KEY").unwrap();

        assert_eq!(orig, "key = \"sk_live_123\"");
        assert_eq!(replaced, "key = os.environ.get(\"STRIPE_SECRET_KEY\")");

        let updated = std::fs::read_to_string(&py_path).unwrap();
        assert!(updated.contains("key = os.environ.get(\"STRIPE_SECRET_KEY\")"));
        assert!(!updated.contains("sk_live_123"));

        // Clean up
        let _ = std::fs::remove_file(&py_path);
    }

    #[test]
    fn test_replace_secret_errors() {
        let res = CodeReplacer::replace_secret("nonexistent_file.py", 1, "sec", "VAR");
        assert!(res.is_err());

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"const x = 1;\n").unwrap();
        let path = tmp.path().to_str().unwrap();

        let res_zero = CodeReplacer::replace_secret(path, 0, "sec", "VAR");
        assert!(res_zero.is_err());

        let res_oob = CodeReplacer::replace_secret(path, 999, "sec", "VAR");
        assert!(res_oob.is_err());
    }
}
