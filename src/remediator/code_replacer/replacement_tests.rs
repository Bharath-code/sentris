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
