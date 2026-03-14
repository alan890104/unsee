//! Credential path configuration for kernel sandbox.
//!
//! Defines default credential file/directory paths that should be denied
//! to sandboxed agent processes, and provides configuration loading.

use std::path::{Path, PathBuf};

/// Default credential paths relative to $HOME.
///
/// These paths contain authentication material (SSH keys, cloud provider
/// credentials, API tokens) that an LLM agent should never be able to read.
/// Each entry is a directory or file under the user's home directory.
const DEFAULT_CREDENTIAL_DIRS: &[&str] = &[
    // SSH keys and config
    ".ssh",
    // GPG keys
    ".gnupg",
    // Cloud provider credentials
    ".aws",
    ".azure",
    ".config/gcloud",
    ".boto",
    ".s3cfg",
    // Container and orchestration
    ".kube",
    ".docker",
    ".helm",
    // Git credentials
    ".git-credentials",
    // Network credentials
    ".netrc",
    // Package manager tokens
    ".npmrc",
    // Secrets managers
    ".vault-token",
    ".config/op",
    // Generic credential stores
    ".credentials",
    ".secrets",
    ".keys",
    ".pki",
    // Infrastructure
    ".terraform.d",
    // Platform CLI credentials
    ".config/gh",
    ".config/hub",
    ".config/stripe",
    ".config/heroku",
    ".config/doctl",
    ".config/netlify",
    ".config/firebase",
    ".config/configstore",
    ".config/rclone",
    ".fly",
    ".vercel",
    // Password managers
    ".password-store",
    // Linux keyring
    ".local/share/keyrings",

    // Shell command histories — may contain credentials in commands
    // e.g. curl -H "Authorization: Bearer TOKEN", export SECRET=xxx
    ".bash_history",
    ".zsh_history",
    ".zsh_sessions",           // macOS Terminal.app zsh session persistence
    ".sh_history",
    ".ksh_history",
    ".tcshhistory",
    ".csh_history",
    ".local/share/fish",       // fish shell data dir (contains fish_history)

    // Language REPL histories — may contain API keys, connection strings
    ".python_history",         // Python 3.13+ / readline default
    ".node_repl_history",      // Node.js REPL
    ".irb_history",            // Ruby IRB
    ".scala_history",          // Scala REPL
    ".php_history",            // PHP interactive shell
    ".Rhistory",               // R console
    ".julia/logs",             // Julia REPL history (repl_history.jl)
    ".bpython_history",        // bpython

    // IPython/Jupyter — history.sqlite contains executed code
    ".ipython",
    ".jupyter",

    // Database CLI histories — may contain passwords, queries with secrets
    ".psql_history",           // PostgreSQL
    ".mysql_history",          // MySQL
    ".sqlite_history",         // SQLite3
    ".mongosh",                // MongoDB Shell (modern)
    ".dbshell",                // Django dbshell history
    ".redis_history",          // Redis CLI (rediscli)

    // Debugger histories — may contain evaluated expressions with secrets
    ".gdb_history",
    ".lldb",                   // LLDB debugger state

    // HTTP client sessions — contain auth headers, tokens
    ".httpie/sessions",        // HTTPie stored sessions with auth headers
    ".config/httpie/sessions", // HTTPie XDG path
    ".curlrc",                 // curl config (may have -H Authorization)

    // AI IDE / coding tool credential stores (plaintext)
    // These tools may store API keys, OAuth tokens, or auth state
    // in plaintext config files rather than the system keychain.
    ".codeium",                        // Windsurf/Codeium — mcp_config.json has plaintext creds
    ".continue",                       // Continue IDE plugin config
    ".tabnine",                        // Tabnine AI assistant
    ".tabby-client",                   // Tabby (open-source Copilot alternative)
    ".claude",                         // Claude Code — auth state, session tokens, project secrets
    ".gemini",                         // Gemini CLI — browser profile with cookies/sessions, mcp_config
    ".codex",                          // OpenAI Codex CLI
    ".config/github-copilot",         // GitHub Copilot hosts.json with auth tokens
    ".copilot-cli-access-token",      // GitHub Copilot CLI plaintext token (fallback)
    ".copilot-cli-copilot-token",     // GitHub Copilot CLI plaintext token (fallback)

    // IDE global storage — extension state DBs may contain auth tokens
    // These are the data directories where VS Code forks store
    // extension secrets when the OS keychain is unavailable.
    "Library/Application Support/Code/User/globalStorage",      // VS Code macOS
    ".config/Code/User/globalStorage",                           // VS Code Linux
    "Library/Application Support/Cursor/User/globalStorage",     // Cursor macOS
    ".config/Cursor/User/globalStorage",                         // Cursor Linux
    "Library/Application Support/Windsurf/User/globalStorage",   // Windsurf macOS
    ".config/Windsurf/User/globalStorage",                       // Windsurf Linux
    ".vscode-oss/User/globalStorage",                            // VSCodium Linux
    "Library/Application Support/VSCodium/User/globalStorage",   // VSCodium macOS
    ".config/Positron/User/globalStorage",                       // Positron Linux
    "Library/Application Support/Positron/User/globalStorage",   // Positron macOS

    // Emacs auth — plaintext credential files
    ".authinfo",               // Emacs unencrypted auth-source
    ".authinfo.gpg",           // Emacs encrypted auth-source (GPG-protected)

    // Package manager credentials (not yet covered)
    ".pypirc",                 // PyPI upload credentials
    ".gem/credentials",        // RubyGems API key
    ".config/pip",             // pip index credentials
    ".cargo/credentials.toml", // Cargo (crates.io) registry token
    ".m2/settings.xml",        // Maven (may contain repo credentials)
    ".gradle/gradle.properties", // Gradle (may contain signing keys, repo tokens)
    ".sbt/repositories",       // SBT repository credentials
    ".composer/auth.json",     // PHP Composer auth tokens
];

/// Resolve default credential paths under the given home directory.
///
/// Returns absolute paths by joining each default credential directory
/// with the home path. Only includes paths that actually exist on disk.
/// Use this for Linux Landlock where PathFd requires existing paths.
pub fn resolve_credential_paths(home: &Path) -> Vec<PathBuf> {
    DEFAULT_CREDENTIAL_DIRS
        .iter()
        .map(|rel| home.join(rel))
        .filter(|p| p.exists())
        .collect()
}

/// Resolve ALL default credential paths regardless of existence.
///
/// SECURITY: On macOS, Seatbelt deny rules for nonexistent paths are harmless
/// (they simply don't match anything). Including them prevents a TOCTOU attack
/// where an attacker creates a credential directory after sandbox setup but
/// before the agent uses it.
///
/// On Linux Landlock, use `resolve_credential_paths()` instead because Landlock
/// requires opening a PathFd which fails for nonexistent paths.
pub fn resolve_all_credential_paths(home: &Path) -> Vec<PathBuf> {
    DEFAULT_CREDENTIAL_DIRS
        .iter()
        .map(|rel| home.join(rel))
        .collect()
}

/// Load credential path configuration from a config file.
///
/// Format: one path per line. Lines starting with `#` are comments.
/// Lines starting with `+` add a path (relative to home or absolute).
/// Lines starting with `-` remove a default path.
/// Blank lines are ignored.
///
/// Example:
/// ```text
/// # Add custom credential store
/// +~/.my-tokens
/// # SSH is handled by agent forwarding, no need to block
/// -~/.ssh
/// ```
pub fn load_credential_config(config_path: &Path, home: &Path) -> Vec<PathBuf> {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => return resolve_credential_paths(home),
    };

    let mut paths = resolve_credential_paths(home);
    let mut removals: Vec<PathBuf> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(add) = trimmed.strip_prefix('+') {
            let add = add.trim();
            let resolved = resolve_tilde(add, home);
            if resolved.exists() && !paths.contains(&resolved) {
                paths.push(resolved);
            }
        } else if let Some(remove) = trimmed.strip_prefix('-') {
            let remove = remove.trim();
            let resolved = resolve_tilde(remove, home);
            removals.push(resolved);
        }
    }

    paths.retain(|p| !removals.contains(p));
    paths
}

/// Returns the mapping of credential directories to trusted process names.
///
/// SECURITY: This list is intentionally hardcoded and conservative.
/// Only system binaries with well-known names that genuinely need
/// credential access are included. Adding a process name here allows
/// that binary to bypass credential file protection.
///
/// Generic interpreters (python, node, bash, sh, cat) are NEVER included
/// because LLM agents typically run as these processes.
pub fn trusted_process_map() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (".ssh", vec![
            "ssh", "ssh-agent", "ssh-add", "ssh-keygen", "ssh-keyscan",
            "scp", "sftp", "git", "git-remote-ssh",
        ]),
        (".gnupg", vec!["gpg", "gpg-agent", "gpg2", "gpgsm", "git"]),
        (".aws", vec!["aws"]),
        (".azure", vec!["az"]),
        (".config/gcloud", vec!["gcloud", "gsutil", "bq"]),
        (".kube", vec!["kubectl", "helm", "k9s"]),
        (".docker", vec![
            "docker", "docker-credential-osxkeychain", "docker-credential-desktop",
        ]),
        (".git-credentials", vec!["git", "git-credential-store"]),
        (".netrc", vec!["curl", "wget", "ftp"]),
        (".npmrc", vec!["npm", "npx", "yarn", "pnpm"]),
        (".config/gh", vec!["gh"]),
        (".config/hub", vec!["hub"]),
        // AI CLI tools — each tool may only access its own credential store.
        // Prevents cross-agent credential theft (e.g. codex reading claude's tokens).
        (".claude", vec!["claude"]),
        (".gemini", vec!["gemini"]),
        (".codex", vec!["codex"]),
    ]
}

/// Check if a given path falls under any of the protected credential paths.
///
/// Returns true if `path` is equal to or a subdirectory/file within any
/// of the `protected` paths.
pub fn is_credential_path(path: &Path, protected: &[PathBuf]) -> bool {
    protected.iter().any(|p| path.starts_with(p))
}

/// Resolve `~` prefix to the home directory.
fn resolve_tilde(path: &str, home: &Path) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else if path == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_are_under_home() {
        let home = Path::new("/home/testuser");
        // Use raw defaults (don't filter by existence for this test)
        for rel in DEFAULT_CREDENTIAL_DIRS {
            let full = home.join(rel);
            assert!(
                full.starts_with(home),
                "{} should be under home",
                full.display()
            );
        }
    }

    #[test]
    fn is_credential_path_matches_subfiles() {
        let protected = vec![PathBuf::from("/home/user/.ssh")];
        assert!(is_credential_path(
            Path::new("/home/user/.ssh/id_rsa"),
            &protected
        ));
        assert!(is_credential_path(
            Path::new("/home/user/.ssh/config"),
            &protected
        ));
        assert!(is_credential_path(
            Path::new("/home/user/.ssh"),
            &protected
        ));
    }

    #[test]
    fn is_credential_path_rejects_unrelated() {
        let protected = vec![
            PathBuf::from("/home/user/.ssh"),
            PathBuf::from("/home/user/.aws"),
        ];
        assert!(!is_credential_path(
            Path::new("/home/user/code/main.rs"),
            &protected
        ));
        assert!(!is_credential_path(
            Path::new("/home/user/.config/nvim"),
            &protected
        ));
        // Must not match prefix-substring (Path::starts_with is component-based)
        assert!(!is_credential_path(
            Path::new("/home/user/.sshx/something"),
            &protected
        ));
    }

    #[test]
    fn config_add_removes_work() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();

        // Create some default dirs so they pass the exists() filter
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::create_dir_all(home.join(".aws")).unwrap();
        std::fs::create_dir_all(home.join(".my-tokens")).unwrap();

        let config_path = home.join("credentials.conf");
        std::fs::write(
            &config_path,
            "# Custom config\n+~/.my-tokens\n-~/.ssh\n",
        )
        .unwrap();

        let paths = load_credential_config(&config_path, home);

        // .ssh should be removed
        assert!(
            !paths.contains(&home.join(".ssh")),
            ".ssh should be removed"
        );
        // .aws should still be present
        assert!(paths.contains(&home.join(".aws")), ".aws should remain");
        // .my-tokens should be added
        assert!(
            paths.contains(&home.join(".my-tokens")),
            ".my-tokens should be added"
        );
    }

    #[test]
    fn config_ignores_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();

        let config_path = home.join("credentials.conf");
        std::fs::write(
            &config_path,
            "# This is a comment\n\n   \n# Another comment\n",
        )
        .unwrap();

        // Should return defaults (filtered by existence)
        let paths = load_credential_config(&config_path, home);
        let defaults = resolve_credential_paths(home);
        assert_eq!(paths, defaults);
    }

    // ---- Per-process trusted process map tests ----
    // These tests verify the new trusted_process_map() function that maps
    // credential directories to their trusted binary names.
    // These tests will FAIL until the feature is implemented.

    #[test]
    fn test_trusted_process_map_covers_common_tools() {
        // The trusted process map must have entries for all major credential
        // directories so that their legitimate tools can still function.
        let map = trusted_process_map();
        let dir_names: Vec<&str> = map.iter().map(|(dir, _)| *dir).collect();

        let required = [".ssh", ".aws", ".kube", ".config/gh", ".gnupg", ".docker"];
        for name in &required {
            assert!(
                dir_names.contains(name),
                "trusted_process_map must include entry for {}, got: {:?}",
                name,
                dir_names
            );
        }
    }

    #[test]
    fn test_trusted_process_map_no_generic_names() {
        // Generic interpreters and file-reading utilities must NEVER appear
        // in any trusted list. Allowing them would let an LLM agent read
        // credentials by invoking these commonly-available tools.
        let map = trusted_process_map();
        let forbidden = [
            "python", "python3", "node", "cat", "bash", "sh", "zsh",
            "less", "more", "head", "tail",
        ];

        for (dir, procs) in &map {
            for name in &forbidden {
                assert!(
                    !procs.contains(name),
                    "trusted list for {} must NOT contain generic tool '{}', got: {:?}",
                    dir,
                    name,
                    procs
                );
            }
        }
    }

    #[test]
    fn test_history_files_in_defaults() {
        // Shell and REPL history files contain commands with embedded secrets
        // (e.g. curl -H "Authorization: Bearer sk-xxx", export TOKEN=xxx).
        let required = [
            ".bash_history",
            ".zsh_history",
            ".psql_history",
            ".node_repl_history",
            ".mysql_history",
            ".python_history",
            ".irb_history",
        ];
        for name in &required {
            assert!(
                DEFAULT_CREDENTIAL_DIRS.contains(name),
                "DEFAULT_CREDENTIAL_DIRS must include history file {}, got: {:?}",
                name,
                DEFAULT_CREDENTIAL_DIRS
            );
        }
    }

    #[test]
    fn test_ai_cli_creds_in_defaults() {
        // AI coding CLI tools store auth tokens and session state.
        // Each must be protected to prevent cross-agent credential theft.
        let required = [".claude", ".gemini", ".codex"];
        for name in &required {
            assert!(
                DEFAULT_CREDENTIAL_DIRS.contains(name),
                "DEFAULT_CREDENTIAL_DIRS must include AI CLI cred {}, got: {:?}",
                name,
                DEFAULT_CREDENTIAL_DIRS
            );
        }
    }

    #[test]
    fn test_ai_cli_trusted_process_isolation() {
        // Each AI CLI tool must ONLY be trusted for its OWN credential dir.
        // This prevents cross-agent credential theft.
        let map = trusted_process_map();

        // claude can access .claude but NOT .gemini or .codex
        let claude_dirs: Vec<&str> = map.iter()
            .filter(|(_, procs)| procs.contains(&"claude"))
            .map(|(dir, _)| *dir)
            .collect();
        assert!(claude_dirs.contains(&".claude"), "claude must be trusted for .claude");
        assert!(!claude_dirs.contains(&".gemini"), "claude must NOT be trusted for .gemini");
        assert!(!claude_dirs.contains(&".codex"), "claude must NOT be trusted for .codex");

        // gemini can access .gemini but NOT .claude or .codex
        let gemini_dirs: Vec<&str> = map.iter()
            .filter(|(_, procs)| procs.contains(&"gemini"))
            .map(|(dir, _)| *dir)
            .collect();
        assert!(gemini_dirs.contains(&".gemini"), "gemini must be trusted for .gemini");
        assert!(!gemini_dirs.contains(&".claude"), "gemini must NOT be trusted for .claude");

        // codex can access .codex but NOT .claude or .gemini
        let codex_dirs: Vec<&str> = map.iter()
            .filter(|(_, procs)| procs.contains(&"codex"))
            .map(|(dir, _)| *dir)
            .collect();
        assert!(codex_dirs.contains(&".codex"), "codex must be trusted for .codex");
        assert!(!codex_dirs.contains(&".claude"), "codex must NOT be trusted for .claude");
    }

    #[test]
    fn test_ide_state_in_defaults() {
        // AI IDE extensions store OAuth tokens and API keys in plaintext.
        let required = [
            ".codeium",
            ".continue",
            ".config/github-copilot",
            "Library/Application Support/Code/User/globalStorage",
            ".config/Code/User/globalStorage",
            "Library/Application Support/Cursor/User/globalStorage",
        ];
        for name in &required {
            assert!(
                DEFAULT_CREDENTIAL_DIRS.contains(name),
                "DEFAULT_CREDENTIAL_DIRS must include IDE state path {}, got: {:?}",
                name,
                DEFAULT_CREDENTIAL_DIRS
            );
        }
    }

    #[test]
    fn test_package_manager_creds_in_defaults() {
        // Package manager credential files contain registry tokens.
        let required = [
            ".pypirc",
            ".cargo/credentials.toml",
            ".composer/auth.json",
            ".gem/credentials",
        ];
        for name in &required {
            assert!(
                DEFAULT_CREDENTIAL_DIRS.contains(name),
                "DEFAULT_CREDENTIAL_DIRS must include package manager cred {}, got: {:?}",
                name,
                DEFAULT_CREDENTIAL_DIRS
            );
        }
    }

    #[test]
    fn test_trusted_process_map_no_empty_lists() {
        // Every credential directory entry must have at least one trusted
        // binary. An empty list would mean the directory is blocked for
        // all processes, which could be done with plain deny() instead.
        let map = trusted_process_map();
        assert!(!map.is_empty(), "trusted_process_map must not be empty");

        for (dir, procs) in &map {
            assert!(
                !procs.is_empty(),
                "trusted process list for {} must not be empty",
                dir
            );
        }
    }
}
