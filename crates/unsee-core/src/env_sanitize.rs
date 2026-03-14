//! Environment variable sanitization for sandboxed execution.
//!
//! Prevents untrusted parent/shell environments from injecting execution
//! behavior via linker, shell, or interpreter environment variables into
//! the sandboxed agent process.
//!
//! Reference: nono-cli/src/exec_strategy/env_sanitization.rs

use std::collections::HashMap;

/// Returns true if an environment variable is unsafe to inherit into a sandboxed child.
///
/// Covers:
/// - Linker injection (LD_PRELOAD, DYLD_INSERT_LIBRARIES)
/// - Shell startup injection (BASH_ENV, PROMPT_COMMAND, IFS)
/// - Interpreter code/module injection (NODE_OPTIONS, PYTHONPATH, PERL5OPT, etc.)
/// - Credential manager tokens (1Password OP_* vars)
pub fn is_dangerous_env_var(key: &str) -> bool {
    // Linker injection: attacker can load arbitrary shared libraries
    // Without this: agent injects a .so/.dylib that intercepts env var reads,
    // bypassing all unsee protections
    key.starts_with("LD_")
        || key.starts_with("DYLD_")
        // Shell injection: attacker can run arbitrary code on shell startup
        // Without this: BASH_ENV runs a script before every bash invocation
        || key == "BASH_ENV"
        || key == "ENV"
        || key == "CDPATH"
        || key == "GLOBIGNORE"
        || key.starts_with("BASH_FUNC_")
        || key == "PROMPT_COMMAND"
        || key == "IFS"
        // Python injection: attacker can run code or load modules on Python start
        // Without this: PYTHONSTARTUP runs arbitrary Python before the real script
        || key == "PYTHONSTARTUP"
        || key == "PYTHONPATH"
        // Node.js injection: NODE_OPTIONS can pass --require to load arbitrary code
        // Without this: agent loads a shim that intercepts all I/O
        || key == "NODE_OPTIONS"
        || key == "NODE_PATH"
        // Perl injection
        || key == "PERL5OPT"
        || key == "PERL5LIB"
        // Ruby injection
        || key == "RUBYOPT"
        || key == "RUBYLIB"
        || key == "GEM_PATH"
        || key == "GEM_HOME"
        // JVM injection
        || key == "JAVA_TOOL_OPTIONS"
        || key == "_JAVA_OPTIONS"
        // .NET injection
        || key == "DOTNET_STARTUP_HOOKS"
        // Go injection
        || key == "GOFLAGS"
        // Zsh config injection: ZDOTDIR controls where zsh reads .zshrc
        // Without this: agent sets ZDOTDIR=/tmp/evil and writes a .zshrc
        // that exfiltrates env vars on every shell spawn
        || key == "ZDOTDIR"
        // Readline injection: INPUTRC can bind keys to execute commands
        || key == "INPUTRC"
        // Git config injection: can override hooks to run arbitrary commands
        || key.starts_with("GIT_CONFIG_")
        // Curl config injection: can set attacker-controlled CA certs
        || key == "CURL_HOME"
        // 1Password secrets and session tokens: meta-secrets used by the parent
        // to authenticate `op` CLI, must never leak to sandboxed child
        || key == "OP_SERVICE_ACCOUNT_TOKEN"
        || key == "OP_CONNECT_TOKEN"
        || key == "OP_CONNECT_HOST"
        || key.starts_with("OP_SESSION_")
}

/// Build a sanitized environment for the sandboxed child process.
///
/// Strips all dangerous environment variables from the current process's
/// environment, preserving only safe ones. The `preserve` list specifies
/// variable names that should be kept even if they match dangerous patterns
/// (e.g., unsee's own DYLD_INSERT_LIBRARIES for the interpose library).
pub fn sanitize_env(preserve: &[&str]) -> HashMap<String, String> {
    std::env::vars()
        .filter(|(key, _)| preserve.contains(&key.as_str()) || !is_dangerous_env_var(key))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_ld_preload() {
        assert!(is_dangerous_env_var("LD_PRELOAD"));
        assert!(is_dangerous_env_var("LD_LIBRARY_PATH"));
    }

    #[test]
    fn blocks_bash_env() {
        assert!(is_dangerous_env_var("BASH_ENV"));
        assert!(is_dangerous_env_var("BASH_FUNC_evil%%"));
    }

    #[test]
    fn blocks_pythonstartup() {
        assert!(is_dangerous_env_var("PYTHONSTARTUP"));
        assert!(is_dangerous_env_var("PYTHONPATH"));
    }

    #[test]
    fn blocks_node_options() {
        assert!(is_dangerous_env_var("NODE_OPTIONS"));
        assert!(is_dangerous_env_var("NODE_PATH"));
    }

    #[test]
    fn allows_normal_vars() {
        assert!(!is_dangerous_env_var("HOME"));
        assert!(!is_dangerous_env_var("PATH"));
        assert!(!is_dangerous_env_var("USER"));
        assert!(!is_dangerous_env_var("TERM"));
        assert!(!is_dangerous_env_var("OPENAI_API_KEY"));
    }

    #[test]
    fn preserve_list_works() {
        // Temporarily set a dangerous var, check sanitize_env preserves it
        let key = "DYLD_INSERT_LIBRARIES";
        let original = std::env::var(key).ok();

        std::env::set_var(key, "/path/to/unsee_interpose.dylib");
        let env = sanitize_env(&[key]);
        assert!(
            env.contains_key(key),
            "preserved var should not be stripped"
        );

        // Clean up
        match original {
            Some(val) => std::env::set_var(key, val),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn blocks_1password_tokens() {
        assert!(is_dangerous_env_var("OP_SERVICE_ACCOUNT_TOKEN"));
        assert!(is_dangerous_env_var("OP_CONNECT_TOKEN"));
        assert!(is_dangerous_env_var("OP_CONNECT_HOST"));
        assert!(is_dangerous_env_var("OP_SESSION_my_team"));
        assert!(is_dangerous_env_var("OP_SESSION_personal"));
    }

    #[test]
    fn blocks_shell_config_injection() {
        assert!(is_dangerous_env_var("ZDOTDIR"));
        assert!(is_dangerous_env_var("INPUTRC"));
    }

    #[test]
    fn blocks_git_config_injection() {
        assert!(is_dangerous_env_var("GIT_CONFIG_GLOBAL"));
        assert!(is_dangerous_env_var("GIT_CONFIG_SYSTEM"));
    }

    #[test]
    fn blocks_curl_config_injection() {
        assert!(is_dangerous_env_var("CURL_HOME"));
    }

    #[test]
    fn does_not_block_op_prefix_unrelated() {
        assert!(!is_dangerous_env_var("OPENAI_API_KEY"));
        assert!(!is_dangerous_env_var("OPERATOR_TOKEN"));
        assert!(!is_dangerous_env_var("OPTIONS"));
    }
}
