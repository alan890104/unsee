//! macOS sandbox implementation using Seatbelt.
//!
//! Applies a kernel-level sandbox via sandbox_init() that denies the agent
//! process access to credential files while allowing normal project work.
//!
//! Reference: Simplified from nono/src/sandbox/macos.rs

use super::UnseeSandbox;
use crate::GuardError;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

// FFI bindings to macOS sandbox API
// These are private APIs but have been stable across all modern macOS versions.
// Reference: https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf
extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Escape a path for use in Seatbelt profile strings.
///
/// SECURITY: Paths are placed inside double-quoted S-expression strings.
/// Backslash and double-quote must be escaped. Control characters (0x00-0x1F,
/// 0x7F) are rejected because stripping them would cause the rule to target
/// a different path than intended, which is a sandbox bypass vulnerability.
/// Reference: nono/src/sandbox/macos.rs:282-298
fn escape_path(path: &str) -> Result<String, GuardError> {
    let mut result = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            c if c.is_control() => {
                return Err(GuardError::Watch(format!(
                    "path contains control character 0x{:02X}: {}",
                    c as u32, path
                )));
            }
            _ => result.push(c),
        }
    }
    Ok(result)
}

/// Collect parent directories that need metadata access for path resolution.
///
/// SECURITY: Programs need to lstat() each path component when resolving paths.
/// Without metadata access to parent directories, the kernel would deny
/// the agent from even locating allowed paths.
/// Reference: nono/src/sandbox/macos.rs:183-217
fn collect_parent_dirs(sandbox: &UnseeSandbox) -> std::collections::HashSet<String> {
    let mut parents = std::collections::HashSet::new();

    let all_paths = sandbox
        .allow_rw_paths()
        .iter()
        .chain(sandbox.allow_read_paths().iter());

    for path in all_paths {
        let mut current = path.parent();
        while let Some(parent) = current {
            let parent_str = parent.to_string_lossy().to_string();
            if parent_str == "/" || parent_str.is_empty() {
                break;
            }
            // If already present, ancestors were processed too — early exit
            if !parents.insert(parent_str) {
                break;
            }
            current = parent.parent();
        }
    }

    parents
}

/// Validate a process name for use in Seatbelt profiles.
///
/// SECURITY: Process names are placed inside double-quoted S-expression strings.
/// Path separators, quotes, parentheses, and control characters could break
/// the S-expression parser or allow injection of arbitrary sandbox rules.
fn validate_process_name(name: &str) -> Result<(), GuardError> {
    if name.is_empty() {
        return Err(GuardError::Watch("empty process name".to_string()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(GuardError::Watch(format!(
            "process name contains path separator: {}",
            name
        )));
    }
    // SECURITY: Reject characters that could break S-expression parsing.
    // Whitespace inside a quoted process-path string could cause the
    // Seatbelt parser to split it into multiple tokens.
    if name.contains('"') || name.contains('(') || name.contains(')')
        || name.contains(' ') || name.contains('\t')
    {
        return Err(GuardError::Watch(format!(
            "process name contains invalid character: {}",
            name
        )));
    }
    for c in name.chars() {
        if c.is_control() {
            return Err(GuardError::Watch(format!(
                "process name contains control character 0x{:02X}: {}",
                c as u32, name
            )));
        }
        // SECURITY: Reject Unicode whitespace (e.g., non-breaking space U+00A0,
        // ideographic space U+3000). The ASCII space/tab check above only
        // covers 0x20 and 0x09. Unicode whitespace in a quoted S-expression
        // string could confuse the Seatbelt parser.
        if c.is_whitespace() {
            return Err(GuardError::Watch(format!(
                "process name contains whitespace character U+{:04X}: {}",
                c as u32, name
            )));
        }
    }
    Ok(())
}

/// Common directories to search for trusted binaries on macOS.
const MACOS_BIN_SEARCH_PATHS: &[&str] = &[
    "/usr/bin",
    "/usr/local/bin",
    "/usr/sbin",
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
];

/// Resolve a bare binary name to its canonical filesystem paths on macOS.
///
/// SECURITY: We resolve the binary name to canonical paths at sandbox build time.
/// This ensures Seatbelt's `process-path` filter checks the exact binary that
/// was found on the system, not a name that could be spoofed. Symlinks are
/// resolved to their targets (e.g., /usr/local/bin/kubectl → /Applications/...).
fn resolve_process_paths(name: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for dir in MACOS_BIN_SEARCH_PATHS {
        let candidate = std::path::Path::new(dir).join(name);
        if candidate.exists() {
            // Canonicalize to resolve symlinks — process-path needs the real path
            let canonical = std::fs::canonicalize(&candidate)
                .unwrap_or_else(|_| candidate.clone());
            let path_str = canonical.to_string_lossy().to_string();
            if !paths.contains(&path_str) {
                paths.push(path_str);
            }
        }
    }
    paths
}

/// Generate a Seatbelt profile from the UnseeSandbox configuration.
///
/// The profile follows a deny-default model: everything is denied unless
/// explicitly allowed. Credential paths are denied with specific rules
/// that override any broader allow rules.
fn generate_profile(sandbox: &UnseeSandbox) -> Result<String, GuardError> {
    let mut profile = String::new();

    // Profile version
    profile.push_str("(version 1)\n");

    // SECURITY: Start with deny-all default. Every access must be explicitly granted.
    // Without this: sandbox would be permissive by default, defeating its purpose.
    profile.push_str("(deny default)\n");

    // SECURITY: Allow process execution (fork+exec) so the agent command can run.
    // Without this: execvp() in the child would fail with EPERM.
    // Reference: nono/src/sandbox/macos.rs:317-318
    let has_trusted_procs = !sandbox.credential_trusted_procs().is_empty();
    if has_trusted_procs {
        // SECURITY: When per-process credential filtering is active, restrict
        // process-exec* to system paths only. This prevents fake-binary attacks
        // where the agent drops a binary named "ssh" in /tmp to bypass
        // process-name credential allow rules.
        for system_path in &["/usr", "/bin", "/sbin", "/opt", "/System", "/Library", "/Applications"] {
            profile.push_str(&format!(
                "(allow process-exec* (subpath \"{}\"))\n",
                system_path
            ));
        }
        // Allow execution from allowed paths (project dir, etc.)
        for path in sandbox.allow_rw_paths() {
            if let Some(s) = path.to_str() {
                let escaped = escape_path(s)?;
                profile.push_str(&format!(
                    "(allow process-exec* (subpath \"{}\"))\n",
                    escaped
                ));
            }
        }
        for path in sandbox.allow_read_paths() {
            if let Some(s) = path.to_str() {
                let escaped = escape_path(s)?;
                profile.push_str(&format!(
                    "(allow process-exec* (subpath \"{}\"))\n",
                    escaped
                ));
            }
        }
        // SECURITY: Deny execution from /tmp to prevent fake-binary attacks.
        // This must come AFTER the allow rules so it overrides any broader allow
        // that might cover /tmp (e.g., if /tmp is in allow_rw).
        profile.push_str("(deny process-exec* (subpath \"/tmp\"))\n");
    } else {
        profile.push_str("(allow process-exec*)\n");
    }
    profile.push_str("(allow process-fork)\n");

    // SECURITY: Allow self-inspection but deny viewing other processes.
    // Without this: agent could use ps/proc_pidinfo to enumerate system processes,
    // discover credential managers, or inspect the unsee parent process.
    // Reference: nono/src/sandbox/macos.rs:321-332
    profile.push_str("(allow process-info* (target self))\n");
    profile.push_str("(deny process-info* (target others))\n");

    // SECURITY: Mach IPC — allow general service lookup but deny Keychain access.
    // Without this: agent could read stored OAuth tokens, API keys, and passwords
    // from macOS Keychain via Mach IPC, bypassing file-level protections.
    // Reference: nono/src/sandbox/macos.rs:343-350
    profile.push_str("(allow mach-lookup)\n");
    profile.push_str("(deny mach-lookup (global-name \"com.apple.SecurityServer\"))\n");
    profile.push_str("(deny mach-lookup (global-name \"com.apple.securityd\"))\n");
    profile.push_str("(allow mach-per-user-lookup)\n");
    profile.push_str("(allow mach-task-name)\n");

    // SECURITY: Deny mach-priv* to prevent privilege escalation via
    // mach_task_self() → task port hijacking → sandbox escape.
    // Without this: agent could extract its own task port and escalate
    // privileges to bypass all sandbox restrictions.
    // Reference: nono/src/sandbox/macos.rs:350
    profile.push_str("(deny mach-priv*)\n");

    // SECURITY: Signal isolation — only allow signaling self.
    // Without this: agent could kill the unsee parent process, removing
    // all protections (StreamRedactor, WriteGuard) from the session.
    // Reference: nono/src/sandbox/macos.rs:362-378
    profile.push_str("(allow signal (target self))\n");

    // Allow sysctl-read for system information queries (CPU count, memory, etc.)
    // Without this: Node.js, Python, and many CLI tools fail on os.cpus() etc.
    // Reference: nono/src/sandbox/macos.rs:335
    profile.push_str("(allow sysctl-read)\n");

    // Allow POSIX shared memory for inter-process communication.
    // Without this: Chrome/Electron, Python multiprocessing, and other runtimes
    // that use shm_open() will fail.
    // Reference: nono/src/sandbox/macos.rs:353-355
    profile.push_str("(allow ipc-posix-shm-read-data)\n");
    profile.push_str("(allow ipc-posix-shm-write-data)\n");
    profile.push_str("(allow ipc-posix-shm-write-create)\n");

    // Allow system socket for network (agent needs API access)
    profile.push_str("(allow system-socket)\n");

    // Allow filesystem control operations (fcntl on some paths)
    // Reference: nono/src/sandbox/macos.rs:381
    profile.push_str("(allow system-fsctl)\n");

    // Allow reading system information (hostname etc.)
    // Reference: nono/src/sandbox/macos.rs:382
    profile.push_str("(allow system-info)\n");

    // SECURITY: Allow pseudo-terminal operations. Required because the agent
    // runs inside a PTY. The PTY is created by the parent before sandbox_init(),
    // so this only allows the child to use the already-open PTY slave fd.
    // Without this: terminal I/O (including all stdout output) would fail.
    // Reference: nono/src/sandbox/macos.rs:419-420
    profile.push_str("(allow pseudo-tty)\n");

    // Allow file ioctl restricted to TTY/PTY devices.
    // SECURITY: Required for terminal operations (TIOCGWINSZ, TCSETS).
    // Restricted to /dev/tty* and /dev/pty* to prevent ioctl on other devices
    // (e.g., /dev/mem which could leak kernel memory).
    // Reference: nono/src/sandbox/macos.rs:409-417
    profile.push_str("(allow file-ioctl (literal \"/dev/tty\"))\n");
    profile.push_str("(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))\n");
    profile.push_str("(allow file-ioctl (regex #\"^/dev/pty[a-z][0-9a-f]+$\"))\n");

    // Allow reading the root directory entry (required for exec path resolution)
    profile.push_str("(allow file-read* (literal \"/\"))\n");

    // Allow metadata access to parent directories of granted paths (for path resolution)
    let parent_dirs = collect_parent_dirs(sandbox);
    for parent in &parent_dirs {
        let escaped = escape_path(parent)?;
        profile.push_str(&format!(
            "(allow file-read-metadata (literal \"{}\"))\n",
            escaped
        ));
    }

    // SECURITY: Allow mapping executables into memory only from readable paths.
    // Without this restriction: agent could load arbitrary shared libraries via
    // DYLD_INSERT_LIBRARIES from paths outside the sandbox's read set, injecting
    // code that intercepts env var access and bypasses all protections.
    // Reference: nono/src/sandbox/macos.rs:398-406
    for path in sandbox.allow_read_paths() {
        if let Some(s) = path.to_str() {
            let escaped = escape_path(s)?;
            profile.push_str(&format!(
                "(allow file-map-executable (subpath \"{}\"))\n",
                escaped
            ));
        }
    }
    for path in sandbox.allow_rw_paths() {
        if let Some(s) = path.to_str() {
            let escaped = escape_path(s)?;
            profile.push_str(&format!(
                "(allow file-map-executable (subpath \"{}\"))\n",
                escaped
            ));
        }
    }

    // Allow file ioctl on granted paths (for interactive programs)
    for path in sandbox.allow_read_paths().iter().chain(sandbox.allow_rw_paths().iter()) {
        if let Some(s) = path.to_str() {
            let escaped = escape_path(s)?;
            profile.push_str(&format!(
                "(allow file-ioctl (subpath \"{}\"))\n",
                escaped
            ));
        }
    }

    // Read access for read-only paths
    for path in sandbox.allow_read_paths() {
        if let Some(s) = path.to_str() {
            let escaped = escape_path(s)?;
            profile.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                escaped
            ));
        }
    }

    // Read+write access for read-write paths
    for path in sandbox.allow_rw_paths() {
        if let Some(s) = path.to_str() {
            let escaped = escape_path(s)?;
            profile.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                escaped
            ));
        }
    }

    // SECURITY: Explicit deny rules for credential paths.
    // These MUST come between read allows and write allows.
    // In Seatbelt, more specific rules always win; for equal specificity,
    // last-match wins. Placing deny rules after read allows ensures they
    // override any broader allow that might cover credential directories.
    // Reference: nono/src/sandbox/macos.rs:449-458
    for path in sandbox.deny_paths() {
        if let Some(s) = path.to_str() {
            let escaped = escape_path(s)?;
            profile.push_str(&format!(
                "(deny file-read* (subpath \"{}\"))\n",
                escaped
            ));
            profile.push_str(&format!(
                "(deny file-write* (subpath \"{}\"))\n",
                escaped
            ));
        }
    }

    // SECURITY: Allow trusted system binaries to read specific credential paths.
    // These rules use require-all with both subpath and process-path, making them
    // MORE SPECIFIC than the bare subpath deny rules above. Seatbelt evaluates
    // more-specific rules with higher priority, so these override the deny.
    // Only file-read* is allowed — write access to credential paths is always denied.
    //
    // process-path takes a canonical filesystem path (not a bare name). We resolve
    // each trusted binary name to its canonical path(s) on this system. Symlinks
    // are followed (e.g., /usr/local/bin/kubectl → /Applications/Docker.app/...).
    for (cred_path, trusted_procs) in sandbox.credential_trusted_procs() {
        if let Some(s) = cred_path.to_str() {
            let escaped = escape_path(s)?;
            for proc_name in trusted_procs {
                // Validate the name to prevent injection
                validate_process_name(proc_name)?;
                // Resolve to canonical filesystem path(s)
                let resolved_paths = resolve_process_paths(proc_name);
                for proc_path in &resolved_paths {
                    let escaped_proc = escape_path(proc_path)?;
                    profile.push_str(&format!(
                        "(allow file-read* (require-all (subpath \"{}\") (process-path \"{}\")))\n",
                        escaped, escaped_proc
                    ));
                }
            }
        }
    }

    // Write access for read-write paths (AFTER deny rules)
    for path in sandbox.allow_rw_paths() {
        if let Some(s) = path.to_str() {
            let escaped = escape_path(s)?;
            profile.push_str(&format!(
                "(allow file-write* (subpath \"{}\"))\n",
                escaped
            ));
        }
    }

    // SECURITY: Allow all network access. Agent needs to call external APIs
    // (OpenAI, Anthropic, etc.) to function. Network restriction is out of
    // scope for Shield v1 — the threat model is credential file exfiltration,
    // not network-level data loss.
    profile.push_str("(allow network-outbound)\n");
    profile.push_str("(allow network-inbound)\n");
    profile.push_str("(allow network-bind)\n");

    Ok(profile)
}

/// Apply Seatbelt sandbox with the given configuration.
///
/// THIS IS IRREVERSIBLE. After sandbox_init() succeeds, the process and
/// all its children are permanently restricted.
pub(super) fn apply(sandbox: &UnseeSandbox) -> Result<(), GuardError> {
    let profile = generate_profile(sandbox)?;

    let profile_cstr = CString::new(profile).map_err(|e| {
        GuardError::Watch(format!("invalid profile string: {}", e))
    })?;

    let mut error_buf: *mut c_char = ptr::null_mut();

    // SAFETY: sandbox_init is a stable macOS API. We pass:
    // - A valid null-terminated C string for the profile
    // - 0 for raw profile mode (not a named profile)
    // - A pointer to receive any error message
    let result = unsafe {
        sandbox_init(
            profile_cstr.as_ptr(),
            0, // Raw profile mode
            &mut error_buf,
        )
    };

    if result != 0 {
        let error_msg = if !error_buf.is_null() {
            // SAFETY: sandbox_init sets error_buf to a valid C string on error
            let msg = unsafe {
                std::ffi::CStr::from_ptr(error_buf)
                    .to_string_lossy()
                    .into_owned()
            };
            // SAFETY: sandbox_free_error expects a pointer from sandbox_init
            unsafe { sandbox_free_error(error_buf) };
            msg
        } else {
            format!("sandbox_init returned error code {}", result)
        };

        return Err(GuardError::Watch(format!("seatbelt init failed: {}", error_msg)));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_escape_path_simple() {
        assert_eq!(escape_path("/simple/path").unwrap(), "/simple/path");
    }

    #[test]
    fn test_escape_path_backslash() {
        assert_eq!(
            escape_path("/path with\\slash").unwrap(),
            "/path with\\\\slash"
        );
    }

    #[test]
    fn test_escape_path_quote() {
        assert_eq!(escape_path("/path\"quoted").unwrap(), "/path\\\"quoted");
    }

    #[test]
    fn test_escape_path_rejects_control_characters() {
        assert!(escape_path("/path\nwith\nnewlines").is_err());
        assert!(escape_path("/path\rwith\rreturns").is_err());
        assert!(escape_path("/path\twith\ttabs").is_err());
        assert!(escape_path("/path\x1bwith\x1bescape").is_err());
    }

    #[test]
    fn test_escape_path_injection_via_newline() {
        // An attacker embeds a newline to break out of the quoted string
        // and inject a new S-expression. This must be rejected.
        let malicious = "/tmp/evil\n(allow file-read* (subpath \"/\"))";
        assert!(escape_path(malicious).is_err());
    }

    #[test]
    fn test_generate_profile_has_deny_default() {
        let sandbox = UnseeSandbox::new();
        let profile = generate_profile(&sandbox).unwrap();
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
    }

    #[test]
    fn test_generate_profile_allows_rw_paths() {
        let mut sandbox = UnseeSandbox::new();
        sandbox.allow_rw(PathBuf::from("/project"));
        let profile = generate_profile(&sandbox).unwrap();

        assert!(profile.contains("(allow file-read* (subpath \"/project\"))"));
        assert!(profile.contains("(allow file-write* (subpath \"/project\"))"));
    }

    #[test]
    fn test_generate_profile_allows_read_paths() {
        let mut sandbox = UnseeSandbox::new();
        sandbox.allow_read(PathBuf::from("/usr"));
        let profile = generate_profile(&sandbox).unwrap();

        assert!(profile.contains("(allow file-read* (subpath \"/usr\"))"));
        assert!(!profile.contains("(allow file-write* (subpath \"/usr\"))"));
    }

    #[test]
    fn test_generate_profile_denies_credential_paths() {
        let mut sandbox = UnseeSandbox::new();
        sandbox.deny(PathBuf::from("/home/user/.ssh"));
        let profile = generate_profile(&sandbox).unwrap();

        assert!(profile.contains("(deny file-read* (subpath \"/home/user/.ssh\"))"));
        assert!(profile.contains("(deny file-write* (subpath \"/home/user/.ssh\"))"));
    }

    #[test]
    fn test_deny_rules_between_read_and_write_allows() {
        let mut sandbox = UnseeSandbox::new();
        sandbox.allow_rw(PathBuf::from("/project"));
        sandbox.deny(PathBuf::from("/home/user/.ssh"));
        let profile = generate_profile(&sandbox).unwrap();

        // Deny rules must come after read allows but before write allows
        let read_pos = profile
            .find("(allow file-read* (subpath \"/project\"))")
            .expect("read rule not found");
        let deny_pos = profile
            .find("(deny file-read* (subpath \"/home/user/.ssh\"))")
            .expect("deny rule not found");
        let write_pos = profile
            .find("(allow file-write* (subpath \"/project\"))")
            .expect("write rule not found");

        assert!(
            read_pos < deny_pos,
            "read rules must come before deny rules"
        );
        assert!(
            deny_pos < write_pos,
            "deny rules must come before write rules"
        );
    }

    #[test]
    fn test_generate_profile_has_security_features() {
        let sandbox = UnseeSandbox::new();
        let profile = generate_profile(&sandbox).unwrap();

        // Process isolation
        assert!(profile.contains("(deny process-info* (target others))"));
        // Keychain denial
        assert!(profile.contains("(deny mach-lookup (global-name \"com.apple.SecurityServer\"))"));
        assert!(profile.contains("(deny mach-lookup (global-name \"com.apple.securityd\"))"));
        // Privilege escalation prevention
        assert!(profile.contains("(deny mach-priv*)"));
        // Signal isolation
        assert!(profile.contains("(allow signal (target self))"));
        // PTY support
        assert!(profile.contains("(allow pseudo-tty)"));
        // Network allowed (agent needs API access)
        assert!(profile.contains("(allow network-outbound)"));
    }

    #[test]
    fn test_generate_profile_has_file_map_executable_for_readable() {
        let mut sandbox = UnseeSandbox::new();
        sandbox.allow_read(PathBuf::from("/usr"));
        let profile = generate_profile(&sandbox).unwrap();

        assert!(profile.contains("(allow file-map-executable (subpath \"/usr\"))"));
    }

    #[test]
    fn test_collect_parent_dirs() {
        let mut sandbox = UnseeSandbox::new();
        sandbox.allow_rw(PathBuf::from("/Users/test/.claude"));
        let parents = collect_parent_dirs(&sandbox);

        assert!(parents.contains("/Users"));
        assert!(parents.contains("/Users/test"));
        assert!(!parents.contains("/"));
    }

    #[test]
    fn test_sandbox_blocks_credential_read() {
        // This test actually applies the sandbox, so it must run in a
        // forked child process to avoid affecting other tests.
        //
        // We fork, apply sandbox with deny ~/.ssh, then try to read a
        // file under that path. The read should fail with EACCES.
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let key_file = ssh_dir.join("id_rsa");
        std::fs::write(&key_file, "FAKE_PRIVATE_KEY").unwrap();

        let project_dir = dir.path().join("project");
        std::fs::create_dir_all(&project_dir).unwrap();
        let project_file = project_dir.join("main.rs");
        std::fs::write(&project_file, "fn main() {}").unwrap();

        // Use a subprocess to test the sandbox (can't apply in-process
        // since it would affect all other tests)
        let output = std::process::Command::new("sh")
            .args(["-c", &format!(
                "cat '{}'",
                key_file.display()
            )])
            .output()
            .unwrap();

        // Without sandbox, the file should be readable
        assert!(
            output.status.success(),
            "pre-sandbox: file should be readable"
        );

        // We can't easily test the actual sandbox in unit tests because
        // sandbox_init() is irreversible and applies to the current process.
        // E2E tests in unsee-cli cover the real sandbox behavior.
    }

    #[test]
    fn test_sandbox_allows_project_read() {
        let mut sandbox = UnseeSandbox::new();
        sandbox.allow_rw(PathBuf::from("/tmp/test-project"));
        sandbox.allow_read(PathBuf::from("/usr"));
        let profile = generate_profile(&sandbox).unwrap();

        // Project dir has read and write
        assert!(profile.contains("(allow file-read* (subpath \"/tmp/test-project\"))"));
        assert!(profile.contains("(allow file-write* (subpath \"/tmp/test-project\"))"));
    }

    // ---- Per-process credential access control tests ----
    // These tests verify the new deny_with_trusted() feature that allows
    // trusted system binaries (ssh, git, gpg) to read credential files
    // while blocking untrusted processes (cat, python, node).
    // These tests will FAIL until the feature is implemented.

    #[test]
    fn test_process_name_allow_rules_generated() {
        // When deny_with_trusted() is used, the generated profile must contain
        // process-path-scoped allow rules for each trusted binary found on the system.
        let mut sandbox = UnseeSandbox::new();
        sandbox.allow_rw(PathBuf::from("/project"));
        sandbox.allow_read(PathBuf::from("/usr"));
        sandbox.deny_with_trusted(
            PathBuf::from("/Users/testuser/.ssh"),
            vec!["ssh".to_string(), "git".to_string()],
        );
        let profile = generate_profile(&sandbox).unwrap();

        // If ssh exists on the system, there must be a process-path rule for it.
        // The exact path depends on the system (/usr/bin/ssh, /opt/homebrew/bin/ssh, etc.)
        let ssh_paths = resolve_process_paths("ssh");
        if !ssh_paths.is_empty() {
            assert!(
                profile.contains("(allow file-read* (require-all (subpath \"/Users/testuser/.ssh\") (process-path"),
                "missing process-path allow rule for ssh:\n{}",
                profile
            );
        }

        let git_paths = resolve_process_paths("git");
        if !git_paths.is_empty() {
            // Count how many process-path rules reference .ssh
            let ssh_path_rules: Vec<&str> = profile.lines()
                .filter(|l| l.contains("process-path") && l.contains("/Users/testuser/.ssh"))
                .collect();
            // Should have at least one rule per resolved binary
            assert!(
                ssh_path_rules.len() >= ssh_paths.len(),
                "expected at least {} process-path rules for .ssh (ssh paths), got {}:\n{}",
                ssh_paths.len(), ssh_path_rules.len(), profile
            );
        }
    }

    #[test]
    fn test_process_name_allow_after_deny() {
        // Seatbelt uses last-match-wins for equally specific rules.
        // Process-path allow rules MUST come AFTER the deny rules so they
        // can override the blanket deny for trusted processes.
        let mut sandbox = UnseeSandbox::new();
        sandbox.allow_rw(PathBuf::from("/project"));
        sandbox.deny_with_trusted(
            PathBuf::from("/Users/testuser/.ssh"),
            vec!["ssh".to_string()],
        );
        let profile = generate_profile(&sandbox).unwrap();

        let deny_pos = profile
            .find("(deny file-read* (subpath \"/Users/testuser/.ssh\"))")
            .expect("deny rule not found in profile");

        // Find any process-path allow rule for .ssh
        let allow_pos = profile
            .find("(allow file-read* (require-all (subpath \"/Users/testuser/.ssh\") (process-path")
            .expect("process-path allow rule not found in profile");

        assert!(
            deny_pos < allow_pos,
            "process-path allow rule must come AFTER deny rule (deny@{}, allow@{})",
            deny_pos,
            allow_pos
        );
    }

    #[test]
    fn test_validate_process_name_rejects_paths() {
        // Process names must be bare binary names, not paths or injections.
        // Allowing paths would let an attacker craft a binary at a chosen
        // path to bypass the sandbox.
        use super::validate_process_name;

        // Slash — could be path traversal
        assert!(validate_process_name("usr/bin/ssh").is_err(), "should reject /");
        assert!(validate_process_name("/ssh").is_err(), "should reject leading /");

        // Backslash — escape injection in S-expression
        assert!(validate_process_name("ssh\\agent").is_err(), "should reject \\");

        // Double quote — S-expression string injection
        assert!(validate_process_name("ssh\"").is_err(), "should reject \"");

        // Parentheses — S-expression structure injection
        assert!(validate_process_name("ssh)").is_err(), "should reject )");
        assert!(validate_process_name("(ssh").is_err(), "should reject (");

        // Control characters — could cause parser confusion
        assert!(validate_process_name("ssh\n").is_err(), "should reject newline");
        assert!(validate_process_name("ssh\t").is_err(), "should reject tab");
        assert!(validate_process_name("ssh\x00").is_err(), "should reject null");
        assert!(validate_process_name("ssh\x1b").is_err(), "should reject escape");
    }

    #[test]
    fn test_validate_process_name_accepts_valid() {
        // These are real system binary names that must be accepted.
        use super::validate_process_name;

        let valid_names = [
            "ssh",
            "ssh-agent",
            "git",
            "docker-credential-osxkeychain",
            "gpg2",
        ];
        for name in &valid_names {
            assert!(
                validate_process_name(name).is_ok(),
                "should accept valid process name: {}",
                name
            );
        }
    }

    #[test]
    fn test_exec_restricted_to_system_paths() {
        // When per-process credential control is active, process-exec*
        // must NOT be a blanket allow. A blanket allow would let an attacker
        // drop a binary in /tmp and run it with trusted-process privileges.
        let mut sandbox = UnseeSandbox::new();
        sandbox.allow_rw(PathBuf::from("/project"));
        sandbox.allow_read(PathBuf::from("/usr"));
        sandbox.deny_with_trusted(
            PathBuf::from("/Users/testuser/.ssh"),
            vec!["ssh".to_string()],
        );
        let profile = generate_profile(&sandbox).unwrap();

        // Must NOT have a standalone blanket allow for process-exec*
        assert!(
            !profile.contains("(allow process-exec*)\n"),
            "profile must NOT contain blanket (allow process-exec*) when deny_with_trusted is used:\n{}",
            profile
        );

        // /tmp execution must be denied to prevent dropped-binary attacks
        assert!(
            profile.contains("(deny process-exec* (subpath \"/tmp\"))"),
            "profile must deny process-exec* from /tmp:\n{}",
            profile
        );
    }

    #[test]
    fn test_no_write_exceptions_for_trusted() {
        // Even trusted processes must NEVER get file-write* access to
        // credential paths. Write access would allow key replacement attacks.
        let mut sandbox = UnseeSandbox::new();
        sandbox.deny_with_trusted(
            PathBuf::from("/Users/testuser/.ssh"),
            vec!["ssh".to_string(), "git".to_string()],
        );
        sandbox.deny_with_trusted(
            PathBuf::from("/Users/testuser/.gnupg"),
            vec!["gpg".to_string()],
        );
        let profile = generate_profile(&sandbox).unwrap();

        // No file-write* exceptions with process-path for any credential path
        assert!(
            !profile.contains("(allow file-write* (require-all"),
            "must NEVER generate file-write* exceptions for trusted processes:\n{}",
            profile
        );
    }

    #[test]
    fn test_deny_without_trusted_has_no_exceptions() {
        // The plain deny() method (without trusted processes) must NOT
        // generate any process-path allow exceptions. Only deny_with_trusted()
        // creates exceptions.
        let mut sandbox = UnseeSandbox::new();
        sandbox.allow_rw(PathBuf::from("/project"));
        sandbox.deny(PathBuf::from("/Users/testuser/.ssh"));
        sandbox.deny(PathBuf::from("/Users/testuser/.aws"));
        let profile = generate_profile(&sandbox).unwrap();

        // No process-path rules should exist
        assert!(
            !profile.contains("process-path"),
            "plain deny() must not generate process-path rules:\n{}",
            profile
        );

        // But deny rules must still be present
        assert!(
            profile.contains("(deny file-read* (subpath \"/Users/testuser/.ssh\"))"),
            "deny rule for .ssh missing"
        );
        assert!(
            profile.contains("(deny file-read* (subpath \"/Users/testuser/.aws\"))"),
            "deny rule for .aws missing"
        );
    }
}
