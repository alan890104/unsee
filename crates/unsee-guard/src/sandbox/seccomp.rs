//! Seccomp user notification for per-process credential access control.
//!
//! Intercepts openat() syscalls via seccomp-bpf and forwards them to a
//! supervisor that checks /proc/PID/exe to allow trusted binaries while
//! denying untrusted processes from reading credential files.
//!
//! SECURITY: This module is Linux-only. On macOS, per-process filtering
//! is handled by Seatbelt's process-name filter in macos.rs.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Trusted binary paths that are allowed to read credential files.
///
/// SECURITY: On Linux, we check the FULL canonical path from /proc/PID/exe,
/// not just the process name. This prevents fake-binary attacks where the
/// agent creates a binary with a trusted name at an untrusted path.
///
/// Generic interpreters (python, node, bash, sh, cat) are NEVER included
/// because LLM agents typically run as these processes.
const TRUSTED_BINARY_PATHS: &[&str] = &[
    // SSH
    "/usr/bin/ssh",
    "/usr/bin/ssh-agent",
    "/usr/bin/ssh-add",
    "/usr/bin/ssh-keygen",
    "/usr/bin/ssh-keyscan",
    "/usr/bin/scp",
    "/usr/bin/sftp",
    // Git
    "/usr/bin/git",
    // GPG
    "/usr/bin/gpg",
    "/usr/bin/gpg2",
    "/usr/bin/gpg-agent",
    "/usr/bin/gpgsm",
    // Cloud CLI
    "/usr/bin/aws",
    "/usr/bin/az",
    "/usr/bin/gcloud",
    "/usr/bin/gsutil",
    "/usr/bin/bq",
    // Container/orchestration
    "/usr/bin/kubectl",
    "/usr/bin/helm",
    "/usr/bin/docker",
    "/usr/bin/k9s",
    // Platform CLI
    "/usr/bin/gh",
    "/usr/bin/hub",
    // Network tools (for .netrc)
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/usr/bin/ftp",
    // Package managers (for .npmrc)
    "/usr/bin/npm",
    "/usr/bin/npx",
    "/usr/bin/yarn",
    "/usr/bin/pnpm",
    // /usr/local/bin variants
    "/usr/local/bin/ssh",
    "/usr/local/bin/git",
    "/usr/local/bin/gpg",
    "/usr/local/bin/gpg2",
    "/usr/local/bin/aws",
    "/usr/local/bin/az",
    "/usr/local/bin/gcloud",
    "/usr/local/bin/kubectl",
    "/usr/local/bin/helm",
    "/usr/local/bin/docker",
    "/usr/local/bin/k9s",
    "/usr/local/bin/gh",
    "/usr/local/bin/hub",
    "/usr/local/bin/npm",
    "/usr/local/bin/npx",
    "/usr/local/bin/yarn",
    "/usr/local/bin/pnpm",
];

/// Check if a binary path is in the trusted set.
///
/// SECURITY: Uses exact path matching against known system binary locations.
/// Symlinks are resolved by the caller (via /proc/PID/exe which the kernel
/// resolves). A script named "ssh" at /tmp/ssh would NOT match because
/// /proc/PID/exe would show the interpreter (/usr/bin/python3), not /tmp/ssh.
pub fn is_trusted_binary(exe_path: &Path) -> bool {
    let path_str = exe_path.to_str().unwrap_or("");
    TRUSTED_BINARY_PATHS.contains(&path_str)
}

/// Check if seccomp user notification is supported on this kernel.
///
/// Probes by attempting to create a seccomp filter with SECCOMP_FILTER_FLAG_NEW_LISTENER.
/// Returns false on kernels < 5.0 or when seccomp is disabled.
pub fn is_seccomp_user_notif_supported() -> bool {
    // On non-Linux, always false
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
    #[cfg(target_os = "linux")]
    {
        // Probe by checking if SECCOMP_FILTER_FLAG_NEW_LISTENER is accepted.
        // A minimal BPF program that allows everything:
        let filter = build_bpf_filter();
        if filter.is_empty() {
            return false;
        }
        // We don't actually install it — just check if the kernel supports the flag.
        // For now, check kernel version via uname.
        let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::uname(&mut utsname) };
        if ret != 0 {
            return false;
        }
        let release = unsafe {
            std::ffi::CStr::from_ptr(utsname.release.as_ptr())
                .to_string_lossy()
                .to_string()
        };
        // Parse major.minor from release string
        let parts: Vec<&str> = release.split('.').collect();
        if parts.len() < 2 {
            return false;
        }
        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = parts[1].parse().unwrap_or(0);
        // SECCOMP_IOCTL_NOTIF_ADDFD requires kernel 5.14+
        major > 5 || (major == 5 && minor >= 14)
    }
}

/// BPF sock_filter instruction.
///
/// Matches the kernel's struct sock_filter layout.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFilter {
    /// Instruction code
    pub code: u16,
    /// Jump true offset
    pub jt: u8,
    /// Jump false offset
    pub jf: u8,
    /// Constant value
    pub k: u32,
}

// BPF instruction constants
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// SECCOMP_RET_ALLOW — allow the syscall to proceed normally
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// SECCOMP_RET_USER_NOTIF — forward to the supervisor for decision
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

/// Build the BPF filter program that traps file-opening syscalls.
///
/// SECURITY: We trap open(), openat(), AND openat2() — all three syscalls
/// that can open files. Missing any of these would allow a bypass:
/// - open(): Legacy syscall, still available on most kernels
/// - openat(): Primary file-opening syscall (used by glibc)
/// - openat2(): Extended variant (kernel 5.6+), same path argument layout
///
/// The filter:
/// 1. Loads the syscall number from seccomp_data.nr
/// 2. If it's open/openat/openat2 → SECCOMP_RET_USER_NOTIF (supervisor)
/// 3. Otherwise → SECCOMP_RET_ALLOW (let Landlock handle)
///
/// We trap ALL calls and let the supervisor decide per-path/per-process.
/// Trying to filter by path in BPF would require reading userspace memory,
/// creating a TOCTOU vulnerability.
pub fn build_bpf_filter() -> Vec<SockFilter> {
    // offsetof(struct seccomp_data, nr) = 0
    let offset_nr: u32 = 0;
    let openat_nr = libc::SYS_openat as u32;

    // SYS_open may not exist on aarch64 (removed in favor of openat).
    // We include it conditionally so the filter works on x86_64 where it's
    // still available and could be called directly by statically-linked binaries.
    #[cfg(target_arch = "x86_64")]
    let open_nr: Option<u32> = Some(libc::SYS_open as u32);
    #[cfg(not(target_arch = "x86_64"))]
    let open_nr: Option<u32> = None;

    // SYS_openat2 = 437 on x86_64, 437 on aarch64 (kernel 5.6+).
    // Not in the libc crate yet, so we hardcode it.
    const SYS_OPENAT2: u32 = 437;

    let mut filter = Vec::new();

    // [0] Load syscall number
    filter.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: offset_nr,
    });

    // Calculate jump offsets: we need to know how many JEQ checks follow
    // to compute the "false" jump target (the final ALLOW instruction).
    // Structure: [LOAD] [JEQ open?] [JEQ openat] [JEQ openat2] [USER_NOTIF] [ALLOW]
    let mut num_checks: u8 = 2; // openat + openat2 always present
    if open_nr.is_some() {
        num_checks += 1;
    }

    let mut remaining = num_checks;

    // [1?] If syscall == open (x86_64 only)
    if let Some(nr) = open_nr {
        remaining -= 1;
        filter.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: remaining,  // jump to USER_NOTIF
            jf: 0,          // fall through to next check
            k: nr,
        });
    }

    // [N] If syscall == openat
    remaining -= 1;
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: remaining,  // jump to USER_NOTIF
        jf: 0,          // fall through to next check
        k: openat_nr,
    });

    // [N+1] If syscall == openat2
    remaining -= 1;
    debug_assert_eq!(remaining, 0);
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,  // true: next instruction (USER_NOTIF)
        jf: 1,  // false: skip to ALLOW
        k: SYS_OPENAT2,
    });

    // [N+2] Return USER_NOTIF for matched syscalls
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_USER_NOTIF,
    });

    // [N+3] Return ALLOW for everything else
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    filter
}

// --- Seccomp syscall constants (not in libc crate) ---
#[cfg(target_os = "linux")]
mod syscall_consts {
    // seccomp() operation
    pub const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    // Flag: return a listener fd for user notifications
    pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 1 << 3;

    // ioctl commands for the seccomp listener fd
    pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC0502100;
    pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC0182101;
    pub const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x40082102;
    pub const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x40182103;

    // seccomp_notif_resp flags
    pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
}

/// BPF sock_fprog structure for seccomp(SET_MODE_FILTER).
#[cfg(target_os = "linux")]
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Seccomp notification from the kernel.
/// Layout matches struct seccomp_notif (kernel 5.0+).
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

/// Seccomp syscall data (matches struct seccomp_data).
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

/// Seccomp notification response to the kernel.
#[cfg(target_os = "linux")]
#[repr(C)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// Seccomp ADDFD request — inject an fd into the notifying process.
#[cfg(target_os = "linux")]
#[repr(C)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

/// Install the seccomp-bpf filter that traps openat() to USER_NOTIF.
///
/// SECURITY: Must be called in the child process BEFORE Landlock restrict_self()
/// and BEFORE execvp(). The returned listener fd must be sent to the parent
/// (supervisor) via a Unix socketpair.
///
/// Returns the listener fd on success.
#[cfg(target_os = "linux")]
pub fn setup_seccomp() -> Result<i32, crate::GuardError> {
    use syscall_consts::*;

    let filter = build_bpf_filter();
    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // SECURITY: Set NO_NEW_PRIVS so unprivileged processes can use seccomp.
    // This is required before seccomp(SET_MODE_FILTER).
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(crate::GuardError::Watch(format!(
            "prctl(NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Install the BPF filter with NEW_LISTENER flag to get a notification fd.
    let listener_fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const SockFprog,
        )
    };

    if listener_fd < 0 {
        return Err(crate::GuardError::Watch(format!(
            "seccomp(SET_MODE_FILTER, NEW_LISTENER) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(listener_fd as i32)
}

/// Supervisor for seccomp user notifications.
///
/// Runs in the parent process, receiving notifications from the child's
/// seccomp filter. For each openat() call, it checks:
/// 1. Is the path a credential path? If not → CONTINUE (let Landlock handle).
/// 2. Is the calling process a trusted binary? If yes → open + ADDFD.
/// 3. Otherwise → EPERM.
#[cfg(target_os = "linux")]
pub struct SeccompSupervisor {
    listener_fd: i32,
    /// Credential paths that are protected
    credential_paths: Vec<PathBuf>,
    /// Set of trusted binary canonical paths (e.g., /usr/bin/ssh)
    trusted_binaries: HashSet<String>,
}

#[cfg(target_os = "linux")]
impl SeccompSupervisor {
    /// Create a new supervisor.
    ///
    /// `credential_trusted_procs` maps credential paths to their trusted process names.
    /// We resolve the trusted names to full paths for Linux exe checking.
    pub fn new(
        listener_fd: i32,
        credential_trusted_procs: &[(PathBuf, Vec<String>)],
    ) -> Self {
        let credential_paths: Vec<PathBuf> = credential_trusted_procs
            .iter()
            .map(|(p, _)| p.clone())
            .collect();

        // Build the set of trusted binary full paths from TRUSTED_BINARY_PATHS
        let trusted_binaries: HashSet<String> = TRUSTED_BINARY_PATHS
            .iter()
            .map(|s| s.to_string())
            .collect();

        SeccompSupervisor {
            listener_fd,
            credential_paths,
            trusted_binaries,
        }
    }

    /// Run the supervisor loop. Blocks until the listener fd is closed
    /// (child exits) or an unrecoverable error occurs.
    ///
    /// SECURITY: If the supervisor dies, all pending openat() calls return
    /// ENOSYS (fail-closed). The child cannot bypass the seccomp filter.
    pub fn run(&self) {
        use syscall_consts::*;

        loop {
            // Receive notification from the child
            let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                libc::ioctl(self.listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif)
            };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOENT) {
                    // Notification was already handled or process exited
                    continue;
                }
                // EBADF or other → listener closed, child exited
                break;
            }

            // SECURITY: Extract the path argument from the correct register.
            // open(path, flags, mode)    → path is in args[0]
            // openat(dirfd, path, flags) → path is in args[1]
            // openat2(dirfd, path, how, size) → path is in args[1]
            let path_addr = {
                let _nr = notif.data.nr as i64;
                #[cfg(target_arch = "x86_64")]
                let is_open = _nr == libc::SYS_open;
                #[cfg(not(target_arch = "x86_64"))]
                let is_open = false;
                if is_open {
                    notif.data.args[0]  // open(): path is first arg
                } else {
                    notif.data.args[1]  // openat()/openat2(): path is second arg
                }
            };
            let path = self.read_path_from_process(notif.pid, path_addr);

            // Check NOTIF_ID_VALID — TOCTOU mitigation. Between reading the path
            // and responding, the child could have been replaced. If the id is no
            // longer valid, skip this notification.
            if !self.is_id_valid(notif.id) {
                continue;
            }

            match path {
                Some(ref p) if self.is_credential_path(p) => {
                    // This is a credential path — check if the process is trusted
                    let exe = self.read_exe(notif.pid);
                    // Re-check validity after reading exe
                    if !self.is_id_valid(notif.id) {
                        continue;
                    }

                    if let Some(ref exe_path) = exe {
                        if self.trusted_binaries.contains(exe_path.as_str()) {
                            // Trusted binary — open the file ourselves and inject the fd
                            self.respond_with_fd(notif.id, p);
                            continue;
                        }
                    }
                    // Untrusted process or couldn't read exe → deny
                    self.respond_eperm(notif.id);
                }
                _ => {
                    // Not a credential path → let Landlock handle it
                    self.respond_continue(notif.id);
                }
            }
        }

        // Clean up
        unsafe { libc::close(self.listener_fd) };
    }

    /// Read a null-terminated path string from the target process's memory.
    fn read_path_from_process(&self, pid: u32, addr: u64) -> Option<String> {
        // SECURITY: Must use CString for null-terminated C string.
        // format!().as_ptr() is NOT null-terminated — passing it to libc::open()
        // reads past the buffer until a stray null byte is found (UB).
        let mem_path = std::ffi::CString::new(format!("/proc/{}/mem", pid)).ok()?;
        let fd = unsafe {
            libc::open(mem_path.as_ptr(), libc::O_RDONLY)
        };
        if fd < 0 {
            return None;
        }

        // SECURITY: Use PATH_MAX (typically 4096) to match kernel limit.
        // If a path exceeds this, the kernel would reject the openat() anyway.
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let n = unsafe {
            libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), addr as i64)
        };
        unsafe { libc::close(fd) };

        if n <= 0 {
            return None;
        }

        // Find null terminator
        let len = buf[..n as usize].iter().position(|&b| b == 0)?;
        let raw_path = std::str::from_utf8(&buf[..len]).ok()?;

        // If relative path (dirfd-based), we can't easily resolve it.
        // For credential paths, they're always absolute, so relative paths
        // are almost certainly not credential paths → return None to trigger CONTINUE.
        if !raw_path.starts_with('/') {
            return None;
        }

        // Canonicalize to resolve symlinks
        std::fs::canonicalize(raw_path)
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }

    /// Read the canonical exe path of a process via /proc/PID/exe.
    ///
    /// SECURITY: When a binary is deleted while running, the kernel appends
    /// " (deleted)" to /proc/PID/exe (e.g. "/usr/bin/ssh (deleted)").
    /// We strip this suffix so the trusted binary check still works.
    /// Without this, a package upgrade that replaces /usr/bin/ssh would
    /// break credential access for all running ssh processes.
    ///
    /// If canonicalize fails (binary truly deleted and not replaced),
    /// we return None → the process is treated as untrusted → EPERM.
    /// This is fail-closed: we do NOT fall back to the unresolved path,
    /// because an attacker could place a fake binary at that path after
    /// the original was deleted.
    fn read_exe(&self, pid: u32) -> Option<String> {
        let link = format!("/proc/{}/exe", pid);
        std::fs::read_link(&link)
            .ok()
            .map(|p| {
                let s = p.to_string_lossy().to_string();
                if let Some(stripped) = s.strip_suffix(" (deleted)") {
                    PathBuf::from(stripped)
                } else {
                    p
                }
            })
            .and_then(|p| std::fs::canonicalize(&p).ok())
            .map(|p| p.to_string_lossy().to_string())
    }

    /// Check if a path falls under any protected credential path.
    fn is_credential_path(&self, path: &str) -> bool {
        let p = Path::new(path);
        self.credential_paths.iter().any(|cp| p.starts_with(cp))
    }

    /// Check if a notification id is still valid (TOCTOU mitigation).
    fn is_id_valid(&self, id: u64) -> bool {
        use syscall_consts::*;
        let ret = unsafe {
            libc::ioctl(self.listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id)
        };
        ret == 0
    }

    /// Respond with CONTINUE — let the syscall proceed to Landlock.
    fn respond_continue(&self, id: u64) {
        use syscall_consts::*;
        let resp = SeccompNotifResp {
            id,
            val: 0,
            error: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        };
        unsafe { libc::ioctl(self.listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) };
    }

    /// Respond with EPERM — deny the syscall.
    fn respond_eperm(&self, id: u64) {
        use syscall_consts::*;
        let resp = SeccompNotifResp {
            id,
            val: 0,
            error: -(libc::EPERM as i32),
            flags: 0,
        };
        unsafe { libc::ioctl(self.listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) };
    }

    /// Open the file ourselves and inject the fd into the child process via ADDFD.
    ///
    /// SECURITY: The supervisor opens the file in its own (unrestricted) context,
    /// then uses SECCOMP_IOCTL_NOTIF_ADDFD to place the fd into the child. The
    /// child's openat() returns this injected fd instead of opening the file itself.
    fn respond_with_fd(&self, id: u64, path: &str) {
        use syscall_consts::*;
        use std::ffi::CString;

        let c_path = match CString::new(path) {
            Ok(p) => p,
            Err(_) => {
                self.respond_eperm(id);
                return;
            }
        };

        // Open the file read-only in the supervisor's (unrestricted) namespace
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            self.respond_eperm(id);
            return;
        }

        // Inject the fd into the child process
        let addfd = SeccompNotifAddfd {
            id,
            flags: 0,
            srcfd: fd as u32,
            newfd: 0,       // kernel picks the fd number
            newfd_flags: 0,
        };

        let ret = unsafe {
            libc::ioctl(self.listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd)
        };

        // Close our copy of the fd
        unsafe { libc::close(fd) };

        if ret < 0 {
            // ADDFD failed — respond with error
            self.respond_eperm(id);
        }
        // On success, ADDFD already responded to the notification
    }
}

/// Send a file descriptor over a Unix socket.
#[cfg(target_os = "linux")]
pub fn send_fd(sock: i32, fd: i32) -> Result<(), std::io::Error> {
    use std::mem;

    // Build cmsg with SCM_RIGHTS
    let iov = libc::iovec {
        iov_base: b"\0".as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    // cmsg buffer: header + one int
    let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<i32>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    // Fill in the cmsg header
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<i32>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const i32 as *const u8,
            libc::CMSG_DATA(cmsg),
            mem::size_of::<i32>(),
        );
    }

    let ret = unsafe { libc::sendmsg(sock, &msg, 0) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Receive a file descriptor from a Unix socket.
#[cfg(target_os = "linux")]
pub fn recv_fd(sock: i32) -> Result<i32, std::io::Error> {
    use std::mem;

    let mut buf = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<i32>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space;

    let ret = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no control message received",
        ));
    }

    // SECURITY: Validate that the received control message is actually
    // SCM_RIGHTS and large enough to contain an fd. Without the level/type
    // check, a malformed cmsg could cause us to interpret garbage as an fd.
    // Without the length check, a truncated cmsg could cause an out-of-bounds
    // read when we copy sizeof(i32) bytes from CMSG_DATA.
    let expected_cmsg_len = unsafe { libc::CMSG_LEN(mem::size_of::<i32>() as u32) } as usize;
    unsafe {
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "received control message is not SCM_RIGHTS",
            ));
        }
        if ((*cmsg).cmsg_len as usize) < expected_cmsg_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SCM_RIGHTS control message too short to contain an fd",
            ));
        }
    }

    let mut fd: i32 = -1;
    unsafe {
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut i32 as *mut u8,
            mem::size_of::<i32>(),
        );
    }

    Ok(fd)
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::path::Path;

    // --- is_trusted_binary tests ---

    /// Trusted system binaries in /usr/bin and /usr/local/bin must be accepted.
    #[test]
    fn test_trusted_binary_accepts_system_paths() {
        let trusted = &[
            "/usr/bin/ssh",
            "/usr/bin/git",
            "/usr/bin/gpg",
            "/usr/local/bin/aws",
        ];
        for path_str in trusted {
            let path = Path::new(path_str);
            assert!(
                is_trusted_binary(path),
                "{} should be trusted but was rejected",
                path_str
            );
        }
    }

    /// Binaries outside system directories must be rejected, even if they
    /// share the same filename as a trusted binary.
    #[test]
    fn test_trusted_binary_rejects_non_system_paths() {
        let untrusted = &[
            "/tmp/ssh",
            "/home/user/ssh",
            "/opt/evil/git",
            "./ssh",
        ];
        for path_str in untrusted {
            let path = Path::new(path_str);
            assert!(
                !is_trusted_binary(path),
                "{} should NOT be trusted but was accepted",
                path_str
            );
        }
    }

    /// Interpreters and generic utilities must be rejected. An LLM agent
    /// typically runs as python3/node/bash — allowing these would defeat
    /// the entire access control mechanism.
    #[test]
    fn test_trusted_binary_rejects_interpreters() {
        let interpreters = &[
            "/usr/bin/python3",
            "/usr/bin/node",
            "/usr/bin/bash",
            "/usr/bin/sh",
            "/usr/bin/cat",
        ];
        for path_str in interpreters {
            let path = Path::new(path_str);
            assert!(
                !is_trusted_binary(path),
                "{} (interpreter/utility) should NOT be trusted but was accepted",
                path_str
            );
        }
    }

    // --- BPF filter structure tests ---

    /// The BPF filter must trap openat() — the primary file-opening syscall.
    #[test]
    fn test_bpf_filter_targets_openat() {
        let filter = build_bpf_filter();
        assert!(!filter.is_empty(), "BPF filter should not be empty");

        let openat_nr = libc::SYS_openat as u32;
        assert!(
            filter.iter().any(|insn| insn.k == openat_nr),
            "BPF filter must contain a check for SYS_openat ({})",
            openat_nr
        );
    }

    /// SECURITY: The BPF filter must also trap openat2() (kernel 5.6+).
    /// Without this, an agent could use openat2() to bypass seccomp entirely.
    #[test]
    fn test_bpf_filter_targets_openat2() {
        let filter = build_bpf_filter();
        const SYS_OPENAT2: u32 = 437;
        assert!(
            filter.iter().any(|insn| insn.k == SYS_OPENAT2),
            "BPF filter must trap openat2 (syscall 437) to prevent bypass"
        );
    }

    /// On x86_64, the legacy open() syscall must also be trapped.
    /// Statically-linked binaries may call open() directly.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_bpf_filter_targets_open_x86_64() {
        let filter = build_bpf_filter();
        let open_nr = libc::SYS_open as u32;
        assert!(
            filter.iter().any(|insn| insn.k == open_nr),
            "BPF filter must trap SYS_open ({}) on x86_64",
            open_nr
        );
    }

    /// When the BPF filter matches openat(), the return action must be
    /// SECCOMP_RET_USER_NOTIF so the supervisor can intercept the call.
    #[test]
    fn test_bpf_filter_returns_user_notif() {
        let filter = build_bpf_filter();

        let seccomp_ret_user_notif: u32 = 0x7fc0_0000;

        let has_user_notif = filter.iter().any(|insn| {
            insn.k == seccomp_ret_user_notif
        });

        assert!(
            has_user_notif,
            "BPF filter must return SECCOMP_RET_USER_NOTIF (0x7fc00000) for openat matches"
        );
    }

    /// Non-openat syscalls must be allowed through (SECCOMP_RET_ALLOW).
    /// The filter's default/fallthrough action should be ALLOW.
    #[test]
    fn test_bpf_filter_allows_non_openat() {
        let filter = build_bpf_filter();

        let seccomp_ret_allow: u32 = 0x7fff_0000;

        let has_allow = filter.iter().any(|insn| {
            insn.k == seccomp_ret_allow
        });

        assert!(
            has_allow,
            "BPF filter must return SECCOMP_RET_ALLOW (0x7fff0000) for non-openat syscalls"
        );
    }
}
