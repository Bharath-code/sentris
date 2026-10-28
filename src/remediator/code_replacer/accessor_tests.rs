use super::CodeReplacer;

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
