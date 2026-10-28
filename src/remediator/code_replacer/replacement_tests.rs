use super::CodeReplacer;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_string_replacement_typescript() {
    let secret = "sk_live_123";
    let var = "STRIPE_SECRET_KEY";

    assert_eq!(
        CodeReplacer::replace_secret_in_line("app.ts", "const key = \"sk_live_123\";", secret, var),
        "const key = process.env.STRIPE_SECRET_KEY;"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("app.tsx", "const key = 'sk_live_123';", secret, var),
        "const key = process.env.STRIPE_SECRET_KEY;"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("app.js", "const key = `sk_live_123`;", secret, var),
        "const key = process.env.STRIPE_SECRET_KEY;"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("app.ts", "  apiKey: \"sk_live_123\",", secret, var),
        "  apiKey: process.env.STRIPE_SECRET_KEY,"
    );
}

#[test]
fn test_string_replacement_python() {
    let secret = "sk_live_123";
    let var = "STRIPE_SECRET_KEY";

    assert_eq!(
        CodeReplacer::replace_secret_in_line("server.py", "key = \"sk_live_123\"", secret, var),
        "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("server.py", "key = 'sk_live_123'", secret, var),
        "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line(
            "server.py",
            "key = \"\"\"sk_live_123\"\"\"",
            secret,
            var
        ),
        "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("server.py", "key = '''sk_live_123'''", secret, var),
        "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("server.py", "key = r\"sk_live_123\"", secret, var),
        "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
    );
    assert_eq!(
        CodeReplacer::replace_secret_in_line("server.py", "key = b\"sk_live_123\"", secret, var),
        "key = os.environ.get(\"STRIPE_SECRET_KEY\")"
    );
}

#[test]
fn test_string_replacement_go() {
    let secret = "sk_live_123";
    let var = "STRIPE_SECRET_KEY";

    assert_eq!(
        CodeReplacer::replace_secret_in_line("main.go", "key := \"sk_live_123\"", secret, var),
        "key := os.Getenv(\"STRIPE_SECRET_KEY\")"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("main.go", "key := `sk_live_123`", secret, var),
        "key := os.Getenv(\"STRIPE_SECRET_KEY\")"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("main.go", "\tApiKey: \"sk_live_123\",", secret, var),
        "\tApiKey: os.Getenv(\"STRIPE_SECRET_KEY\"),"
    );
}

#[test]
fn test_string_replacement_rust() {
    let secret = "sk_live_123";
    let var = "STRIPE_SECRET_KEY";

    assert_eq!(
        CodeReplacer::replace_secret_in_line("main.rs", "let key = \"sk_live_123\";", secret, var),
        "let key = std::env::var(\"STRIPE_SECRET_KEY\").expect(\"STRIPE_SECRET_KEY must be set\");"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line(
            "main.rs",
            "let key = r#\"sk_live_123\"#;",
            secret,
            var
        ),
        "let key = std::env::var(\"STRIPE_SECRET_KEY\").expect(\"STRIPE_SECRET_KEY must be set\");"
    );

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
        CodeReplacer::replace_secret_in_line(
            "Program.cs",
            "var opt = new Options { Key = \"sk_live_123\" };",
            secret,
            var
        ),
        "var opt = new Options { Key = Environment.GetEnvironmentVariable(\"STRIPE_SECRET_KEY\") };"
    );
}

#[test]
fn test_string_replacement_ruby() {
    let secret = "sk_live_123";
    let var = "STRIPE_SECRET_KEY";

    assert_eq!(
        CodeReplacer::replace_secret_in_line("app.rb", "stripe_key = \"sk_live_123\"", secret, var),
        "stripe_key = ENV[\"STRIPE_SECRET_KEY\"]"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("app.rb", "stripe_key = 'sk_live_123'", secret, var),
        "stripe_key = ENV[\"STRIPE_SECRET_KEY\"]"
    );

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

    assert_eq!(
        CodeReplacer::replace_secret_in_line(
            "index.php",
            "$apiKey = \"sk_live_123\";",
            secret,
            var
        ),
        "$apiKey = getenv(\"STRIPE_SECRET_KEY\");"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("index.php", "$apiKey = 'sk_live_123';", secret, var),
        "$apiKey = getenv(\"STRIPE_SECRET_KEY\");"
    );

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

    assert_eq!(
        CodeReplacer::replace_secret_in_line(
            "deploy.sh",
            "export STRIPE_KEY=\"sk_live_123\"",
            secret,
            var
        ),
        "export STRIPE_KEY=\"${STRIPE_SECRET_KEY}\""
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line(
            "deploy.bash",
            "STRIPE_KEY='sk_live_123'",
            secret,
            var
        ),
        "STRIPE_KEY=\"${STRIPE_SECRET_KEY}\""
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("deploy.zsh", "STRIPE_KEY=sk_live_123", secret, var),
        "STRIPE_KEY=\"${STRIPE_SECRET_KEY}\""
    );

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

    assert_eq!(
        CodeReplacer::replace_secret_in_line(
            "config.yml",
            "stripe_key: \"sk_live_123\"",
            secret,
            var
        ),
        "stripe_key: STRIPE_SECRET_KEY"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line(
            "config.yaml",
            "stripe_key: 'sk_live_123'",
            secret,
            var
        ),
        "stripe_key: STRIPE_SECRET_KEY"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("config.yaml", "stripe_key: sk_live_123", secret, var),
        "stripe_key: STRIPE_SECRET_KEY"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line(".env", "STRIPE_KEY=\"sk_live_123\"", secret, var),
        "STRIPE_KEY=STRIPE_SECRET_KEY"
    );

    assert_eq!(
        CodeReplacer::replace_secret_in_line("app.toml", "key = \"sk_live_123\"", secret, var),
        "key = STRIPE_SECRET_KEY"
    );

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
    let py_path = format!("{path}.py");
    std::fs::copy(&path, &py_path).unwrap();

    let (orig, replaced) =
        CodeReplacer::replace_secret(&py_path, 3, "sk_live_123", "STRIPE_SECRET_KEY").unwrap();

    assert_eq!(orig, "key = \"sk_live_123\"");
    assert_eq!(replaced, "key = os.environ.get(\"STRIPE_SECRET_KEY\")");

    let updated = std::fs::read_to_string(&py_path).unwrap();
    assert!(updated.contains("key = os.environ.get(\"STRIPE_SECRET_KEY\")"));
    assert!(!updated.contains("sk_live_123"));

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

#[test]
fn test_multiline_pem_block_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let ts_path = dir.path().join("jwt_signer.ts");
    let pem_code = concat!(
        "const header = 1;\n",
        "const privateKey = `-----BEGIN ",
        "RSA PRIVATE KEY-----\n",
        "MIIEpAIBAAKCAQEA1234567890abcdef\n",
        "9876543210fedcbaMIIEpAIBAAKCAQEA\n",
        "-----END RSA PRIVATE KEY-----`;\n",
        "export default privateKey;\n"
    );
    std::fs::write(&ts_path, pem_code).unwrap();

    let extracted =
        crate::detector::DetectorEngine::extract_multiline_pem_block(pem_code, 2).unwrap();
    assert_eq!(extracted.0, 2);
    assert_eq!(extracted.1, 5);
    assert!(extracted
        .2
        .contains(concat!("-----BEGIN ", "RSA PRIVATE KEY-----\\nMIIEp")));
    assert!(extracted.2.ends_with("-----END RSA PRIVATE KEY-----"));

    let (_, replaced) = CodeReplacer::replace_secret(
        ts_path.to_str().unwrap(),
        2,
        &extracted.2,
        "PRIVATE_KEY_PEM",
    )
    .unwrap();
    assert_eq!(replaced, "const privateKey = process.env.PRIVATE_KEY_PEM;");

    let updated = std::fs::read_to_string(&ts_path).unwrap();
    assert!(updated.contains("const privateKey = process.env.PRIVATE_KEY_PEM;"));
    assert!(!updated.contains("BEGIN RSA PRIVATE KEY"));
    assert!(updated.contains("export default privateKey;"));
}

#[test]
fn test_crlf_file_stays_crlf_and_only_target_line_changes() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("app.py");
    std::fs::write(&p, "import os\r\nkey = \"sk_live_123\"\r\nprint(key)\r\n").unwrap();
    CodeReplacer::replace_secret(p.to_str().unwrap(), 2, "sk_live_123", "STRIPE_SECRET_KEY")
        .unwrap();
    let out = std::fs::read(&p).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(
        text,
        "import os\r\nkey = os.environ.get(\"STRIPE_SECRET_KEY\")\r\nprint(key)\r\n"
    );
}

#[test]
fn test_no_trailing_newline_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.py");
    std::fs::write(&p, "k = \"sk_live_123\"").unwrap();
    CodeReplacer::replace_secret(p.to_str().unwrap(), 1, "sk_live_123", "K").unwrap();
    assert_eq!(
        std::fs::read_to_string(&p).unwrap(),
        "k = os.environ.get(\"K\")"
    );
}

#[test]
fn test_stale_line_errors_and_leaves_file_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.py");
    let src = "x = 1\n";
    std::fs::write(&p, src).unwrap();
    let err = CodeReplacer::replace_secret(p.to_str().unwrap(), 1, "sk_live_123", "K");
    assert!(err.is_err());
    assert_eq!(std::fs::read_to_string(&p).unwrap(), src);
}

#[cfg(unix)]
#[test]
fn test_symlink_target_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.py");
    let link = dir.path().join("link.py");
    std::fs::write(&real, "k = \"sk_live_123\"\n").unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(CodeReplacer::replace_secret(link.to_str().unwrap(), 1, "sk_live_123", "K").is_err());
    assert!(std::fs::read_to_string(&real)
        .unwrap()
        .contains("sk_live_123"));
}

#[test]
fn test_pem_original_block_is_returned_in_full() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("k.ts");
    let src = concat!(
        "const k = `-----BEGIN ",
        "RSA PRIVATE KEY-----\nAAAA\nBBBB\n-----END RSA PRIVATE KEY-----`;\nnext();\n"
    );
    std::fs::write(&p, src).unwrap();
    let (orig, _) =
        CodeReplacer::replace_secret(p.to_str().unwrap(), 1, "ignored", "PRIVATE_KEY_PEM").unwrap();
    assert_eq!(
        orig,
        src.trim_end().strip_suffix("next();").unwrap().trim_end()
    );
}
