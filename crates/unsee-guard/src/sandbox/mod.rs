//! Kernel sandbox for credential file protection.
//!
//! Uses platform-specific mechanisms to deny agent access to credential
//! files and directories:
//! - macOS: Seatbelt (sandbox_init)
//! - Linux: Landlock LSM
//!
//! The sandbox is applied in the PTY child process after fork() and before
//! exec(), so the unsee parent process (StreamRedactor, WriteGuard) is
//! unaffected.
//!
//! Reference: Simplified from nono/src/sandbox/

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub mod seccomp;

#[cfg(target_os = "macos")]
mod macos;

use std::path::PathBuf;

/// Information about sandbox support on this platform.
#[derive(Debug, Clone)]
pub struct SupportInfo {
    /// Whether sandboxing is supported
    pub is_supported: bool,
    /// Platform name
    pub platform: &'static str,
    /// Detailed support information
    pub details: String,
}

/// Kernel sandbox configuration for credential file protection.
///
/// Builder pattern: configure allow/deny paths, then call `apply()` in the
/// child process to enforce the sandbox. Once applied, restrictions are
/// irreversible — this is a security feature, not a bug.
///
/// # Example
/// ```no_run
/// use unsee_guard::sandbox::UnseeSandbox;
/// use std::path::PathBuf;
///
/// let mut sandbox = UnseeSandbox::new();
/// sandbox
///     .allow_rw(PathBuf::from("/project"))
///     .allow_read(PathBuf::from("/usr"))
///     .deny(PathBuf::from("/home/user/.ssh"));
///
/// // In child process after fork():
/// sandbox.apply().expect("sandbox failed");
/// ```
pub struct UnseeSandbox {
    /// Paths with read+write access (project directory, tmpdir)
    allow_rw: Vec<PathBuf>,
    /// Paths with read-only access (system paths, interpose library)
    allow_read: Vec<PathBuf>,
    /// Paths explicitly denied (credential directories)
    deny_paths: Vec<PathBuf>,
    /// Per-credential-path trusted process mapping.
    /// Each entry is (credential_path, list_of_trusted_binary_names).
    /// On Linux, the seccomp supervisor uses this to allow specific binaries
    /// to read specific credential files while denying all others.
    credential_trusted_procs: Vec<(PathBuf, Vec<String>)>,
}

impl UnseeSandbox {
    /// Create a new empty sandbox configuration.
    pub fn new() -> Self {
        UnseeSandbox {
            allow_rw: Vec::new(),
            allow_read: Vec::new(),
            deny_paths: Vec::new(),
            credential_trusted_procs: Vec::new(),
        }
    }

    /// Allow read+write access to a path (directory or file).
    ///
    /// Use for: project directory, TMPDIR, other writable locations.
    pub fn allow_rw(&mut self, path: PathBuf) -> &mut Self {
        self.allow_rw.push(path);
        self
    }

    /// Allow read-only access to a path (directory or file).
    ///
    /// Use for: /usr, /bin, /lib, interpose library path.
    pub fn allow_read(&mut self, path: PathBuf) -> &mut Self {
        self.allow_read.push(path);
        self
    }

    /// Deny access to a path (directory or file).
    ///
    /// SECURITY: Deny rules take precedence over allow rules on macOS
    /// (Seatbelt deny overrides allow for equally-specific rules).
    /// On Linux, Landlock is strictly allow-list: denied paths are simply
    /// not added to the ruleset, so they are implicitly denied.
    pub fn deny(&mut self, path: PathBuf) -> &mut Self {
        self.deny_paths.push(path);
        self
    }

    /// Deny access to a credential path, but allow specific trusted processes
    /// to read it via seccomp user notification (Linux only).
    ///
    /// SECURITY: On Linux, this adds the path to the deny list (Landlock blocks
    /// all access) AND registers trusted binaries for the seccomp supervisor to
    /// selectively allow. On macOS, this falls back to a plain deny().
    pub fn deny_with_trusted(&mut self, path: PathBuf, trusted_procs: Vec<String>) -> &mut Self {
        self.deny_paths.push(path.clone());
        self.credential_trusted_procs.push((path, trusted_procs));
        self
    }

    /// Get the per-credential-path trusted process mapping.
    pub fn credential_trusted_procs(&self) -> &[(PathBuf, Vec<String>)] {
        &self.credential_trusted_procs
    }

    /// Apply the sandbox to the current process. THIS IS IRREVERSIBLE.
    ///
    /// Must be called in the child process after fork(), before exec().
    /// After this call, the process can only access paths explicitly allowed.
    ///
    /// Returns `Ok(Some(listener_fd))` on Linux when seccomp user notification
    /// was successfully set up (the fd must be sent to the parent supervisor).
    /// Returns `Ok(None)` on macOS or when seccomp is unavailable.
    ///
    /// # Errors
    ///
    /// Returns an error if the sandbox cannot be applied (unsupported platform,
    /// invalid paths, kernel rejection).
    pub fn apply(&self) -> Result<Option<i32>, crate::GuardError> {
        #[cfg(target_os = "macos")]
        {
            macos::apply(self)?;
            Ok(None)
        }

        #[cfg(target_os = "linux")]
        {
            linux::apply(self)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(crate::GuardError::Watch(format!(
                "Sandbox not supported on {}",
                std::env::consts::OS
            )))
        }
    }

    /// Check if kernel sandboxing is supported on this platform.
    pub fn is_supported() -> bool {
        #[cfg(target_os = "macos")]
        {
            true
        }

        #[cfg(target_os = "linux")]
        {
            linux::is_supported()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    /// Probe whether apply() would succeed by running it in a forked child.
    ///
    /// On Linux, Landlock's restrict_self() is irreversible. If it returns
    /// PartiallyEnforced, the child is stuck with broken restrictions that
    /// can block PTY access. This probe forks a throwaway child to test
    /// the exact apply() code path. The child's restrictions die with it.
    ///
    /// On macOS, always returns true (Seatbelt is reliable).
    pub fn probe_apply(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            true
        }

        #[cfg(target_os = "linux")]
        {
            let pid = unsafe { libc::fork() };
            match pid {
                -1 => false,
                0 => {
                    // Child: run the full apply() and check if it succeeds.
                    // restrict_self() is irreversible but the child _exits
                    // immediately, so its restrictions are harmless.
                    let ok = self.apply().is_ok();
                    unsafe { libc::_exit(if ok { 0 } else { 1 }) };
                }
                child_pid => {
                    let mut status: libc::c_int = 0;
                    unsafe { libc::waitpid(child_pid, &mut status, 0) };
                    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
                }
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    /// Get detailed information about sandbox support on this platform.
    pub fn support_info() -> SupportInfo {
        #[cfg(target_os = "macos")]
        {
            SupportInfo {
                is_supported: true,
                platform: "macos",
                details: "macOS Seatbelt sandbox available".to_string(),
            }
        }

        #[cfg(target_os = "linux")]
        {
            linux::support_info()
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            SupportInfo {
                is_supported: false,
                platform: std::env::consts::OS,
                details: format!("Platform '{}' is not supported", std::env::consts::OS),
            }
        }
    }

    /// Get the list of denied paths (for status display).
    pub fn deny_paths(&self) -> &[PathBuf] {
        &self.deny_paths
    }

    /// Get the list of read-write allowed paths.
    pub fn allow_rw_paths(&self) -> &[PathBuf] {
        &self.allow_rw
    }

    /// Get the list of read-only allowed paths.
    pub fn allow_read_paths(&self) -> &[PathBuf] {
        &self.allow_read
    }
}

impl Default for UnseeSandbox {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// After calling deny_with_trusted(), the credential path must appear in
    /// both deny_paths() (for Landlock blocking) and credential_trusted_procs()
    /// (for seccomp selective allow). If either is missing, the security model
    /// breaks: Landlock without seccomp means trusted binaries are also blocked;
    /// seccomp without Landlock means untrusted binaries can still read files.
    #[test]
    fn test_deny_with_trusted_stores_mapping() {
        let mut sandbox = UnseeSandbox::new();
        let cred_path = PathBuf::from("/home/user/.ssh");
        let trusted = vec!["ssh".to_string(), "git".to_string()];

        sandbox.deny_with_trusted(cred_path.clone(), trusted.clone());

        // The credential path must be in the deny list
        assert!(
            sandbox.deny_paths().contains(&cred_path),
            "deny_paths() must contain the credential path after deny_with_trusted()"
        );

        // The credential path must also appear in the trusted process mapping
        let mapping = sandbox.credential_trusted_procs();
        let found = mapping.iter().find(|(p, _)| p == &cred_path);
        assert!(
            found.is_some(),
            "credential_trusted_procs() must contain an entry for the credential path"
        );

        // The trusted process names must match exactly
        let (_, stored_procs) = found.unwrap();
        assert_eq!(
            stored_procs, &trusted,
            "trusted process names must match what was passed to deny_with_trusted()"
        );
    }
}
