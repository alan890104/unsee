//! Linux sandbox implementation using Landlock LSM.
//!
//! Applies a kernel-level sandbox via Landlock that denies the agent
//! process access to credential files while allowing normal project work.
//!
//! Landlock is strictly allow-list: only paths added to the ruleset are
//! accessible. Denied paths are simply not added, so they are implicitly
//! blocked by the kernel.
//!
//! Reference: Simplified from nono/src/sandbox/linux.rs

use super::{UnseeSandbox, SupportInfo};
use crate::GuardError;
use landlock::{
    Access, AccessFs, BitFlags, CompatLevel, Compatible, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};

/// ABI probe order: highest to lowest.
const ABI_PROBE_ORDER: [ABI; 6] = [ABI::V6, ABI::V5, ABI::V4, ABI::V3, ABI::V2, ABI::V1];

/// Detected Landlock ABI version with feature query methods.
///
/// SECURITY: ABI detection is critical for graceful degradation. On older
/// kernels, some protections (Refer, Truncate, IoctlDev) are unavailable.
/// Shield logs warnings but continues with reduced protection rather than
/// failing open (no sandbox at all).
/// Reference: nono/src/sandbox/linux.rs:13-107
#[derive(Debug, Clone, Copy)]
struct DetectedAbi {
    abi: ABI,
}

impl DetectedAbi {
    fn new(abi: ABI) -> Self {
        Self { abi }
    }

    /// Whether file rename across directories is supported (V2+).
    /// SECURITY: Without Refer, agent could rename credential files to
    /// an allowed directory: `mv ~/.ssh/id_rsa ./` → read succeeds.
    fn has_refer(&self) -> bool {
        AccessFs::from_all(self.abi).contains(AccessFs::Refer)
    }

    /// Whether file truncation control is supported (V3+).
    /// SECURITY: Without Truncate, agent could truncate .env files,
    /// destroying credential records.
    fn has_truncate(&self) -> bool {
        AccessFs::from_all(self.abi).contains(AccessFs::Truncate)
    }

    /// Whether device ioctl filtering is supported (V5+).
    /// SECURITY: Without IoctlDev, ioctl on device files is unfiltered.
    /// We restrict IoctlDev to actual device files (stat check) to avoid
    /// granting ioctl access to regular files.
    fn has_ioctl_dev(&self) -> bool {
        AccessFs::from_all(self.abi).contains(AccessFs::IoctlDev)
    }

    fn version_string(&self) -> &'static str {
        match self.abi {
            ABI::V1 => "V1",
            ABI::V2 => "V2",
            ABI::V3 => "V3",
            ABI::V4 => "V4",
            ABI::V5 => "V5",
            ABI::V6 => "V6",
            _ => "unknown",
        }
    }

    fn feature_names(&self) -> Vec<String> {
        let mut features = vec!["Basic filesystem access control".to_string()];
        if self.has_refer() {
            features.push("File rename across directories (Refer)".to_string());
        }
        if self.has_truncate() {
            features.push("File truncation (Truncate)".to_string());
        }
        if self.has_ioctl_dev() {
            features.push("Device ioctl filtering (IoctlDev)".to_string());
        }
        features
    }
}

/// Detect the highest Landlock ABI supported by the running kernel.
///
/// Probes from V6 down to V1. Returns the highest ABI for which a full
/// ruleset can be created.
fn detect_abi() -> Result<DetectedAbi, GuardError> {
    for &abi in &ABI_PROBE_ORDER {
        if probe_abi_candidate(abi).is_ok() {
            return Ok(DetectedAbi::new(abi));
        }
    }
    Err(GuardError::Watch(
        "No supported Landlock ABI detected. Requires Linux kernel 5.13+".to_string(),
    ))
}

/// Probe whether a specific ABI version is supported.
fn probe_abi_candidate(abi: ABI) -> Result<(), String> {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("filesystem access probe failed: {}", e))?
        .create()
        .map_err(|e| format!("ruleset creation probe failed: {}", e))?;
    Ok(())
}

/// Check if Landlock is supported on this system.
///
/// SECURITY: Uses a fork-based probe that actually calls restrict_self() in a
/// disposable child process. A simple ABI detection is insufficient because
/// some environments (e.g., Docker Desktop) detect Landlock ABI support but
/// return PartiallyEnforced from restrict_self(), which can block PTY access
/// and hang the child process. The fork probe catches this at startup rather
/// than at sandbox apply time (when restrict_self is irreversible).
pub(super) fn is_supported() -> bool {
    // Quick check: can we detect the Landlock ABI?
    // The full enforcement test is done by UnseeSandbox::probe_apply()
    // which runs the actual apply() in a forked child.
    detect_abi().is_ok()
}

/// Get information about Landlock support.
pub(super) fn support_info() -> SupportInfo {
    match detect_abi() {
        Ok(detected) => {
            let features = detected.feature_names();
            SupportInfo {
                is_supported: true,
                platform: "linux",
                details: format!(
                    "Landlock available ({}, features: {})",
                    detected.version_string(),
                    features.join(", ")
                ),
            }
        }
        Err(_) => SupportInfo {
            is_supported: false,
            platform: "linux",
            details: "Landlock not available. Requires Linux kernel 5.13+ with Landlock enabled."
                .to_string(),
        },
    }
}

/// Convert access mode to Landlock AccessFs flags.
///
/// SECURITY: Refer and Truncate are included in write access to support
/// atomic writes (write to .tmp → rename to target), the standard pattern
/// for safe config updates. Without Refer in allowed paths, legitimate
/// file saves would fail.
/// Reference: nono/src/sandbox/linux.rs:222-255
fn read_access(abi: ABI) -> BitFlags<AccessFs> {
    let available = AccessFs::from_all(abi);
    (AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute) & available
}

fn write_access(abi: ABI) -> BitFlags<AccessFs> {
    let available = AccessFs::from_all(abi);
    let desired = AccessFs::WriteFile
        | AccessFs::MakeChar
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::MakeBlock
        | AccessFs::MakeSym
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::Refer
        | AccessFs::Truncate;
    desired & available
}

/// Check if a path is a character or block device file.
///
/// SECURITY: IoctlDev is only granted for actual device files (e.g.,
/// /dev/tty, /dev/null), not for regular files or directories. This
/// prevents agents from using device ioctls on non-device paths.
/// Reference: nono/src/sandbox/linux.rs:261-280
fn is_device_path(path: &std::path::Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path)
        .map(|m| {
            let ft = m.file_type();
            ft.is_char_device() || ft.is_block_device()
        })
        .unwrap_or(false)
}

fn is_device_directory(path: &std::path::Path) -> bool {
    path.starts_with("/dev") && path.is_dir()
}

/// Check if a path is under any of the denied paths.
///
/// SECURITY: On Linux, Landlock is strictly allow-list — there is no
/// "deny" concept. Instead, we simply do NOT add denied paths to the
/// ruleset, so the kernel implicitly blocks access.
fn is_under_denied(path: &std::path::Path, deny_paths: &[std::path::PathBuf]) -> bool {
    deny_paths.iter().any(|d| path.starts_with(d))
}

/// Apply Landlock sandbox with the given configuration.
///
/// THIS IS IRREVERSIBLE. After restrict_self() succeeds, the process and
/// all its children are permanently restricted to only the allowed paths.
///
/// On Linux 5.14+, also installs a seccomp-bpf filter that traps openat()
/// and returns a listener fd for the supervisor. The listener fd is returned
/// so the child can send it to the parent via socketpair before exec.
///
/// Returns Ok(Some(listener_fd)) if seccomp was set up, Ok(None) if seccomp
/// is unavailable (Landlock-only fallback).
///
/// SECURITY: The ruleset is created with HardRequirement for filesystem
/// access rights, ensuring that if the kernel doesn't support the expected
/// ABI, the sandbox fails loudly rather than silently degrading.
/// Reference: nono/src/sandbox/linux.rs:331-559
pub(super) fn apply(sandbox: &UnseeSandbox) -> Result<Option<i32>, GuardError> {
    // Determine if seccomp should be set up (checked later, after Landlock rules
    // are added but before restrict_self).
    let want_seccomp = !sandbox.credential_trusted_procs().is_empty()
        && super::seccomp::is_seccomp_user_notif_supported();

    if !sandbox.credential_trusted_procs().is_empty() && !want_seccomp {
        eprintln!(
            "unsee-guard: seccomp user notification not supported (kernel < 5.14), \
             falling back to Landlock-only (all credential reads blocked)"
        );
    }

    let detected = detect_abi()?;
    let target_abi = detected.abi;

    let handled_fs = AccessFs::from_all(target_abi);

    // Create the ruleset with HardRequirement for filesystem access.
    // SECURITY: HardRequirement ensures that if the caller passes an ABI
    // higher than the kernel supports, handle_access() fails instead of
    // silently dropping flags via BestEffort.
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled_fs)
        .map_err(|e| GuardError::Watch(format!("failed to handle fs access: {}", e)))?
        .set_compatibility(CompatLevel::BestEffort)
        .create()
        .map_err(|e| GuardError::Watch(format!("failed to create ruleset: {}", e)))?;

    let ioctl_dev_available = detected.has_ioctl_dev();

    // Add rules for read-only paths (skip any that are under denied paths)
    for path in sandbox.allow_read_paths() {
        if is_under_denied(path, sandbox.deny_paths()) {
            continue;
        }

        let access = read_access(target_abi);
        let mut effective_access = access;

        // SECURITY: Grant IoctlDev only for actual device files/directories.
        // Terminal ioctls (TCSETS, TIOCGWINSZ) require this flag on V5+ kernels.
        // Reference: nono/src/sandbox/linux.rs:502-516
        if ioctl_dev_available
            && (is_device_path(path) || is_device_directory(path))
        {
            effective_access |= AccessFs::IoctlDev;
        }

        match PathFd::new(path) {
            Ok(path_fd) => {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, effective_access))
                    .map_err(|e| {
                        GuardError::Watch(format!(
                            "cannot add Landlock rule for {}: {}",
                            path.display(),
                            e
                        ))
                    })?;
            }
            Err(e) => {
                // Path may not exist — skip it silently. This is safe because
                // not adding a rule means the path remains denied.
                eprintln!(
                    "unsee-guard: skipping Landlock rule for {}: {}",
                    path.display(),
                    e
                );
            }
        }
    }

    // Add rules for read-write paths (skip any under denied paths)
    for path in sandbox.allow_rw_paths() {
        if is_under_denied(path, sandbox.deny_paths()) {
            continue;
        }

        let access = read_access(target_abi) | write_access(target_abi);
        let mut effective_access = access;

        if ioctl_dev_available
            && (is_device_path(path) || is_device_directory(path))
        {
            effective_access |= AccessFs::IoctlDev;
        }

        match PathFd::new(path) {
            Ok(path_fd) => {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, effective_access))
                    .map_err(|e| {
                        GuardError::Watch(format!(
                            "cannot add Landlock rule for {}: {}",
                            path.display(),
                            e
                        ))
                    })?;
            }
            Err(e) => {
                eprintln!(
                    "unsee-guard: skipping Landlock rule for {}: {}",
                    path.display(),
                    e
                );
            }
        }
    }

    // SECURITY: Install seccomp AFTER adding all Landlock rules (which use
    // openat() internally via PathFd) but BEFORE restrict_self(). If seccomp
    // were installed first, the openat() calls in PathFd::new() would be
    // trapped with no supervisor to handle them, causing the process to hang.
    let listener_fd = if want_seccomp {
        match super::seccomp::setup_seccomp() {
            Ok(fd) => Some(fd),
            Err(e) => {
                eprintln!(
                    "unsee-guard: seccomp setup failed, falling back to Landlock-only: {}",
                    e
                );
                None
            }
        }
    } else {
        None
    };

    // SECURITY: Apply the ruleset — THIS IS IRREVERSIBLE.
    // After restrict_self(), no new rules can be added and no existing
    // rules can be removed. This is a defense-in-depth feature.
    let status = ruleset
        .restrict_self()
        .map_err(|e| GuardError::Watch(format!("failed to restrict self: {}", e)))?;

    // SECURITY: Check the enforcement status of the ruleset.
    // - FullyEnforced: all access rights are enforced — ideal.
    // - PartiallyEnforced: some access flags were dropped by the kernel.
    //   This can break PTY access (e.g., IoctlDev for terminal ioctls),
    //   causing the child process to hang. Treat as an error — the caller's
    //   probe_apply() should have detected this before the real apply.
    // - NotEnforced: no rules were enforced — sandbox is useless, fail.
    match status.ruleset {
        landlock::RulesetStatus::FullyEnforced => {}
        landlock::RulesetStatus::PartiallyEnforced => {
            return Err(GuardError::Watch(
                "Landlock sandbox only partially enforced — some rules were dropped by the kernel. \
                 This may block PTY access.".to_string(),
            ));
        }
        landlock::RulesetStatus::NotEnforced => {
            return Err(GuardError::Watch(
                "Landlock sandbox was not enforced".to_string(),
            ));
        }
    }

    Ok(listener_fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_abi_or_unsupported() {
        // This test just verifies the detection logic doesn't panic.
        // On non-Landlock systems (macOS CI), it returns Err which is fine.
        let _ = detect_abi();
    }

    #[test]
    fn test_is_under_denied() {
        let deny = vec![
            std::path::PathBuf::from("/home/user/.ssh"),
            std::path::PathBuf::from("/home/user/.aws"),
        ];
        assert!(is_under_denied(
            std::path::Path::new("/home/user/.ssh/id_rsa"),
            &deny
        ));
        assert!(is_under_denied(
            std::path::Path::new("/home/user/.aws/credentials"),
            &deny
        ));
        assert!(!is_under_denied(
            std::path::Path::new("/home/user/project/main.rs"),
            &deny
        ));
        // Must not match prefix-substring
        assert!(!is_under_denied(
            std::path::Path::new("/home/user/.sshx/key"),
            &deny
        ));
    }

    /// Seccomp user notification support detection must not panic regardless
    /// of the kernel version. It may return true (kernel >= 5.14) or false
    /// (older kernel / missing CONFIG_SECCOMP_USER_NOTIF), both are valid.
    #[test]
    fn test_seccomp_support_detection() {
        use crate::sandbox::seccomp::is_seccomp_user_notif_supported;
        let result = is_seccomp_user_notif_supported();
        // We only assert it returns a bool without panicking.
        // The actual value depends on the kernel running the test.
        let _ = result;
    }

    #[test]
    fn test_read_write_access_flags() {
        // Verify we get non-empty flags for V1 (minimum supported)
        let read = read_access(ABI::V1);
        assert!(!read.is_empty(), "read access should have flags");

        let write = write_access(ABI::V1);
        assert!(!write.is_empty(), "write access should have flags");

        // Read and write should have different flags
        assert_ne!(read, write, "read and write should differ");
    }
}
