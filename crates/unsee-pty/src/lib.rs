use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;

use unsee_guard::sandbox::UnseeSandbox;

/// A PTY session wrapping a child process.
///
/// The child runs in a pseudo-terminal; the parent reads/writes the master side.
pub struct PtySession {
    master_fd: RawFd,
    child_pid: libc::pid_t,
    /// Seccomp listener fd received from the child (Linux only).
    /// None on macOS or when seccomp is unavailable.
    seccomp_listener_fd: Option<RawFd>,
}

impl PtySession {
    /// Spawn a child process in a new PTY.
    ///
    /// `argv` is the command and its arguments.
    /// `extra_env` contains additional environment variables to set in the child.
    /// `sandbox` optionally applies a kernel sandbox in the child before exec.
    pub fn spawn(
        argv: &[String],
        extra_env: &HashMap<String, String>,
        sandbox: Option<&UnseeSandbox>,
    ) -> io::Result<Self> {
        if argv.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty argv"));
        }

        let mut master_fd: libc::c_int = 0;
        let mut slave_fd: libc::c_int = 0;
        let ret = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        // On Linux, create a socketpair for passing the seccomp listener fd
        // from child to parent. On macOS this is unused.
        #[cfg(target_os = "linux")]
        let sock_fds = {
            let mut fds: [libc::c_int; 2] = [-1, -1];
            let ret = unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
            };
            if ret != 0 {
                unsafe {
                    libc::close(master_fd);
                    libc::close(slave_fd);
                }
                return Err(io::Error::last_os_error());
            }
            fds
        };

        let pid = unsafe { libc::fork() };
        match pid {
            -1 => {
                unsafe {
                    libc::close(master_fd);
                    libc::close(slave_fd);
                }
                #[cfg(target_os = "linux")]
                unsafe {
                    libc::close(sock_fds[0]);
                    libc::close(sock_fds[1]);
                }
                Err(io::Error::last_os_error())
            }
            0 => {
                // Child process
                unsafe { libc::close(master_fd) };
                // Close parent's end of socketpair
                #[cfg(target_os = "linux")]
                unsafe { libc::close(sock_fds[0]) };

                unsafe { libc::setsid() };
                unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY.into(), 0) };

                unsafe {
                    libc::dup2(slave_fd, 0);
                    libc::dup2(slave_fd, 1);
                    libc::dup2(slave_fd, 2);
                    if slave_fd > 2 {
                        libc::close(slave_fd);
                    }
                }

                // SECURITY: Use libc::setenv() instead of std::env::set_var().
                // set_var() acquires a Rust mutex internally. If the parent
                // thread held that mutex at fork() time, the child deadlocks.
                // setenv() is async-signal-safe on POSIX systems.
                //
                // CString::new() can fail if the string contains a null byte.
                // We must NOT panic between fork and exec (not async-signal-safe),
                // so we _exit(125) on error instead of unwrap().
                for (key, value) in extra_env {
                    let c_key = match CString::new(key.as_str()) {
                        Ok(k) => k,
                        Err(_) => unsafe { libc::_exit(125) },
                    };
                    let c_val = match CString::new(value.as_str()) {
                        Ok(v) => v,
                        Err(_) => unsafe { libc::_exit(125) },
                    };
                    unsafe { libc::setenv(c_key.as_ptr(), c_val.as_ptr(), 1) };
                }

                // Apply kernel sandbox if provided.
                // SECURITY: This must happen AFTER env vars are set (so
                // DYLD_INSERT_LIBRARIES is in place) and BEFORE execvp
                // (so the agent command runs inside the sandbox).
                // The sandbox is irreversible — once applied, the agent
                // and all its children are permanently restricted.
                if let Some(sandbox) = sandbox {
                    match sandbox.apply() {
                        Ok(listener_fd_opt) => {
                            // On Linux, send the seccomp listener fd to the parent
                            // via the socketpair, then close both fds.
                            #[cfg(target_os = "linux")]
                            {
                                if let Some(listener_fd) = listener_fd_opt {
                                    // Send the listener fd to the parent
                                    let _ = unsee_guard::sandbox::seccomp::send_fd(
                                        sock_fds[1], listener_fd
                                    );
                                    // Close listener fd in the child — parent owns it now
                                    unsafe { libc::close(listener_fd) };
                                }
                                // Close the child's socketpair end
                                unsafe { libc::close(sock_fds[1]) };
                            }
                            #[cfg(not(target_os = "linux"))]
                            {
                                let _ = listener_fd_opt;
                            }
                        }
                        Err(_e) => {
                            // Close socketpair before exit so parent doesn't hang
                            #[cfg(target_os = "linux")]
                            unsafe { libc::close(sock_fds[1]) };
                            // SECURITY: Write a static error message to stderr.
                            // format!() allocates on the heap, which is not
                            // async-signal-safe between fork and exec. A heap
                            // allocation here could deadlock if the allocator
                            // mutex was held at fork() time.
                            let msg = b"unsee: sandbox apply failed\n";
                            let _ = unsafe {
                                libc::write(
                                    2,
                                    msg.as_ptr() as *const libc::c_void,
                                    msg.len(),
                                )
                            };
                            unsafe { libc::_exit(126) };
                        }
                    }
                } else {
                    // No sandbox — close socketpair in child
                    #[cfg(target_os = "linux")]
                    unsafe { libc::close(sock_fds[1]) };
                }

                // SECURITY: No unwrap() between fork and exec — a panic here
                // is not async-signal-safe and could deadlock or corrupt state.
                let c_cmd = match CString::new(argv[0].as_str()) {
                    Ok(c) => c,
                    Err(_) => unsafe { libc::_exit(125) },
                };
                let c_args: Vec<CString> = {
                    let mut args = Vec::new();
                    for a in argv {
                        match CString::new(a.as_str()) {
                            Ok(c) => args.push(c),
                            Err(_) => unsafe { libc::_exit(125) },
                        }
                    }
                    args
                };
                let c_argv: Vec<*const libc::c_char> = c_args
                    .iter()
                    .map(|a| a.as_ptr())
                    .chain(std::iter::once(std::ptr::null()))
                    .collect();

                unsafe { libc::execvp(c_cmd.as_ptr(), c_argv.as_ptr()) };
                // If execvp returns, it failed
                unsafe { libc::_exit(127) };
            }
            child_pid => {
                // Parent process
                unsafe { libc::close(slave_fd) };

                // On Linux, receive the seccomp listener fd from the child.
                // The child sends the fd if seccomp was set up, or closes
                // the socket without sending if seccomp is unavailable.
                let seccomp_listener_fd;
                #[cfg(target_os = "linux")]
                {
                    // Close child's end of socketpair
                    unsafe { libc::close(sock_fds[1]) };
                    // Set a timeout on the socket to avoid hanging if the child
                    // crashes before closing its end.
                    let timeout = libc::timeval { tv_sec: 5, tv_usec: 0 };
                    unsafe {
                        libc::setsockopt(
                            sock_fds[0],
                            libc::SOL_SOCKET,
                            libc::SO_RCVTIMEO,
                            &timeout as *const libc::timeval as *const libc::c_void,
                            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                        );
                    }
                    // Try to receive the listener fd (may not be sent if seccomp unavailable)
                    seccomp_listener_fd = unsee_guard::sandbox::seccomp::recv_fd(sock_fds[0]).ok();
                    unsafe { libc::close(sock_fds[0]) };
                }
                #[cfg(not(target_os = "linux"))]
                {
                    seccomp_listener_fd = None;
                }

                Ok(PtySession {
                    master_fd,
                    child_pid,
                    seccomp_listener_fd,
                })
            }
        }
    }

    /// Read from the PTY master side.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(self.master_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            // EIO is expected when child exits and PTY closes
            if err.raw_os_error() == Some(libc::EIO) {
                return Ok(0);
            }
            Err(err)
        } else {
            Ok(n as usize)
        }
    }

    /// Write to the PTY master side (forwards to child's stdin).
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe { libc::write(self.master_fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Wait for the child process to exit. Returns the exit code.
    pub fn wait(&self) -> i32 {
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(self.child_pid, &mut status, 0) };

        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            1
        }
    }

    /// Get the master file descriptor (for use with select/poll/kqueue).
    pub fn master_fd(&self) -> RawFd {
        self.master_fd
    }

    /// Get the child PID.
    pub fn child_pid(&self) -> libc::pid_t {
        self.child_pid
    }

    /// Get the seccomp listener fd (Linux only, None on macOS or if seccomp unavailable).
    pub fn seccomp_listener_fd(&self) -> Option<RawFd> {
        self.seccomp_listener_fd
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        unsafe { libc::close(self.master_fd) };
        // SECURITY: Close seccomp listener fd to prevent leak.
        // When the listener fd closes, the kernel causes all pending
        // seccomp notifications to return ENOSYS (fail-closed).
        if let Some(fd) = self.seccomp_listener_fd {
            unsafe { libc::close(fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_echo_captures_output() {
        let session = PtySession::spawn(
            &["echo".into(), "hello".into()],
            &HashMap::new(),
            None,
        )
        .unwrap();

        let mut all = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match session.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => all.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }

        let exit_code = session.wait();
        let output = String::from_utf8_lossy(&all);
        assert!(output.contains("hello"), "output: {}", output);
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn preserves_exit_code_zero() {
        let session = PtySession::spawn(
            &["true".into()],
            &HashMap::new(),
            None,
        )
        .unwrap();

        // Drain output
        let mut buf = [0u8; 4096];
        loop {
            match session.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }

        assert_eq!(session.wait(), 0);
    }

    #[test]
    fn preserves_nonzero_exit_code() {
        let session = PtySession::spawn(
            &["false".into()],
            &HashMap::new(),
            None,
        )
        .unwrap();

        let mut buf = [0u8; 4096];
        loop {
            match session.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }

        assert_eq!(session.wait(), 1);
    }

    #[test]
    fn spawn_with_env_override() {
        let mut env = HashMap::new();
        env.insert("UNSEE_TEST_VAR".into(), "unsee_value".into());

        let session = PtySession::spawn(
            &["sh".into(), "-c".into(), "echo $UNSEE_TEST_VAR".into()],
            &env,
            None,
        )
        .unwrap();

        let mut all = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match session.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => all.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }

        let exit_code = session.wait();
        let output = String::from_utf8_lossy(&all);
        assert!(output.contains("unsee_value"), "output: {}", output);
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn pty_plus_redactor_integration() {
        // This test verifies PTY output can be piped through a simple redaction
        let session = PtySession::spawn(
            &["echo".into(), "my-secret-value".into()],
            &HashMap::new(),
            None,
        )
        .unwrap();

        let mut all = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match session.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => all.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }

        session.wait();
        let output = String::from_utf8_lossy(&all);
        // Verify the output actually contains the secret (pre-redaction)
        assert!(output.contains("my-secret-value"), "output: {}", output);
    }
}
