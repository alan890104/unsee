use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use unsee_core::{credpaths, env_sanitize, ignorelist, mapping::MultiFileMapping, parser};
use unsee_guard::sandbox::UnseeSandbox;
use unsee_guard::WriteGuard;
use unsee_pty::PtySession;
use unsee_redact::StreamRedactor;

/// Environment variable used as a sentinel to detect re-exec.
/// If set, we are in Phase 2 (post double-exec) and should proceed normally.
const REEXEC_ENV: &str = "__UNSEE_REEXEC";

/// Re-exec the current process with a clean environment to scrub
/// the parent's kernel procargs snapshot (KERN_PROCARGS2 / /proc/PID/environ).
///
/// Phase 1: original invocation → re-exec self with env_clear + safe vars
/// Phase 2: re-exec'd process has clean procargs → continue normally
fn ensure_clean_procargs(cmd: &[String]) -> Result<()> {
    if std::env::var_os(REEXEC_ENV).is_some() {
        // Phase 2: already re-exec'd, remove sentinel and continue
        std::env::remove_var(REEXEC_ENV);
        return Ok(());
    }

    // Phase 1: re-exec with clean env
    let exe = std::env::current_exe().context("resolving own executable path")?;

    let mut safe_env: HashMap<String, String> = HashMap::new();

    // Preserve essential environment variables
    const SAFE_VARS: &[&str] = &[
        "PATH", "HOME", "USER", "LOGNAME", "SHELL",
        "TERM", "COLORTERM", "TERM_PROGRAM", "TERM_PROGRAM_VERSION",
        "LANG", "LANGUAGE",
        "TMPDIR",
        "EDITOR", "VISUAL", "PAGER",
        "SSH_AUTH_SOCK", "SSH_AGENT_PID",
        "DISPLAY", "WAYLAND_DISPLAY",
        "NO_COLOR", "FORCE_COLOR", "CLICOLOR",
        "HOSTNAME",
        "RUST_LOG",
    ];
    const SAFE_PREFIXES: &[&str] = &["LC_", "XDG_"];

    for (key, value) in std::env::vars() {
        let dominated = SAFE_VARS.contains(&key.as_str())
            || SAFE_PREFIXES.iter().any(|p| key.starts_with(p));
        if dominated {
            safe_env.insert(key, value);
        }
    }

    // Set sentinel so Phase 2 knows to skip re-exec
    safe_env.insert(REEXEC_ENV.into(), "1".into());

    let mut child = std::process::Command::new(exe);
    child.env_clear();
    for (k, v) in &safe_env {
        child.env(k, v);
    }
    child.arg("protect").arg("--");
    for arg in cmd {
        child.arg(arg);
    }

    let status = child.status().context("re-exec for clean procargs")?;
    std::process::exit(status.code().unwrap_or(1));
}

pub fn run(cmd: &[String]) -> Result<()> {
    if cmd.is_empty() {
        anyhow::bail!("no command specified after --");
    }

    // Double-exec: scrub parent procargs on first invocation
    ensure_clean_procargs(cmd)?;

    let dir = Path::new(".");

    // 1. Discover and parse .env files
    let env_files = parser::discover_env_files(dir)
        .context("discovering .env files")?;

    // Load ignorelist
    let ignore_path = dir.join(".unsee.ignore");
    let ignorelist = if ignore_path.exists() {
        ignorelist::parse_ignorelist(&ignore_path)
            .context("parsing .unsee.ignore")?
    } else {
        HashSet::new()
    };

    // 2. Build mapping
    let file_set = parser::parse_env_files(&env_files)
        .context("parsing .env files")?;
    let mapping = MultiFileMapping::build(&file_set, &ignorelist, None);

    if mapping.secrets_count() == 0 {
        tracing::info!("no secrets to protect, running command directly");
    }

    // 3. Write TSV map file for interpose library
    let tsv = mapping.to_tsv();
    let map_file = tempfile::NamedTempFile::new()
        .context("creating map file")?;
    std::fs::write(map_file.path(), &tsv)
        .context("writing map file")?;

    // SECURITY: Set FD_CLOEXEC on the map file so it is not inherited by the
    // child process after exec. The map file contains the full mapping of
    // placeholders to real secret values — if leaked to the agent, it could
    // read every secret directly.
    {
        let fd = map_file.as_file().as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        }
    }

    // 4. Defense-in-depth: strip dangerous env vars from the current process
    // environment. The re-exec in Phase 1 already filters to SAFE_VARS, but
    // this provides a second barrier against linker/interpreter injection
    // that might slip through if SAFE_VARS is ever expanded.
    let preload_var = WriteGuard::preload_env_var();
    let _sanitized = env_sanitize::sanitize_env(&[preload_var, "__UNSEE_ACTIVE", "UNSEE_MAP_FILE"]);
    for (key, _) in std::env::vars() {
        if env_sanitize::is_dangerous_env_var(&key) && key != preload_var {
            std::env::remove_var(&key);
        }
    }

    // 5. Prepare extra env vars for child
    let mut extra_env: HashMap<String, String> = HashMap::new();
    extra_env.insert("UNSEE_MAP_FILE".into(), map_file.path().to_string_lossy().to_string());
    extra_env.insert("__UNSEE_ACTIVE".into(), "1".into());

    // Set DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD (Linux)
    let dylib_path = WriteGuard::dylib_path();
    if dylib_path.exists() {
        extra_env.insert(
            WriteGuard::preload_env_var().into(),
            dylib_path.to_string_lossy().to_string(),
        );
    }

    // Secret values are NOT injected as env vars. The app/framework reads
    // .env files directly and decides its own loading priority (e.g. Vite:
    // .env.mode.local > .env.mode > .env.local > .env). Shield only needs
    // all values in the redactor to mask output, regardless of which file
    // the framework ultimately uses.

    // 6. Build kernel sandbox for credential file protection.
    // SECURITY: If the platform doesn't support sandboxing (e.g., old kernel,
    // container without Landlock), proceed without a sandbox and log a warning.
    // Running without a sandbox is strictly better than crashing — the other
    // layers (StreamRedactor, WriteGuard, interpose) still provide protection.
    let sandbox = if UnseeSandbox::is_supported() {
        let s = build_sandbox()?;
        // Probe: fork a throwaway child and run apply() to verify it succeeds.
        // On Linux, restrict_self() is irreversible — if it returns
        // PartiallyEnforced, the child is stuck with broken restrictions.
        // The probe catches this before the real child is forked.
        if s.probe_apply() {
            Some(s)
        } else {
            eprintln!(
                "unsee: WARNING: kernel sandbox probe failed (partial enforcement). \
                 Credential file protection will rely on other defense layers."
            );
            None
        }
    } else {
        eprintln!(
            "unsee: WARNING: kernel sandbox not available on this system. \
             Credential file protection will rely on other defense layers."
        );
        None
    };

    // 7. Start WriteGuard in background thread
    let (guard_tx, guard_handle) = {
        let reverse_map = mapping.reverse_map();
        let watch_paths: Vec<_> = env_files.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let guard = WriteGuard::new(reverse_map, watch_paths);
            guard.watch_blocking(rx);
        });
        (tx, handle)
    };

    // 8. Spawn child in PTY with sandbox
    let session = PtySession::spawn(cmd, &extra_env, sandbox.as_ref())
        .context("spawning child process")?;

    // SECURITY: Delete the map file from the filesystem immediately after spawn.
    // The interpose library in the child loaded the file during exec() (via its
    // constructor/init function). After that, the file is no longer needed on disk.
    // Without this, the LLM agent could `cat $UNSEE_MAP_FILE` and read all
    // secret values directly, bypassing the redactor entirely.
    //
    // The parent still holds the NamedTempFile handle (keeps the inode alive on
    // Unix even after unlink), but no process can open it by path anymore.
    if let Err(e) = std::fs::remove_file(map_file.path()) {
        // Non-fatal: file might already be gone, but log for awareness
        tracing::warn!("failed to unlink map file: {}", e);
    }

    // 8b. On Linux, start the seccomp supervisor thread if we got a listener fd.
    // The supervisor intercepts openat() calls and allows trusted binaries
    // to read credential files while blocking untrusted processes.
    #[cfg(target_os = "linux")]
    let seccomp_handle = {
        if let Some(listener_fd) = session.seccomp_listener_fd() {
            let cred_trusted = sandbox.as_ref()
                .map(|s| s.credential_trusted_procs().to_vec())
                .unwrap_or_default();
            Some(std::thread::spawn(move || {
                // SECURITY: Catch panics so we can log them. If the supervisor
                // panics silently, all openat() calls return ENOSYS (fail-closed),
                // but without logging the operator has no way to diagnose.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let supervisor = unsee_guard::sandbox::seccomp::SeccompSupervisor::new(
                        listener_fd,
                        &cred_trusted,
                    );
                    supervisor.run();
                }));
                if let Err(e) = result {
                    let msg = if let Some(s) = e.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = e.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown panic".to_string()
                    };
                    eprintln!("unsee-guard: seccomp supervisor panicked: {}", msg);
                }
            }))
        } else {
            None
        }
    };

    // 9. Main loop: read PTY → redact → stdout
    let secrets = mapping.redacted_secrets();
    let mut redactor = StreamRedactor::new(&secrets);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    // Forward stdin to PTY in background
    let master_fd = session.master_fd();
    let stdin_handle = std::thread::spawn(move || {
        use std::io::Read;
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let ret = unsafe {
                        libc::write(
                            master_fd,
                            buf.as_ptr() as *const libc::c_void,
                            n,
                        )
                    };
                    if ret < 0 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut buf = [0u8; 4096];
    loop {
        match session.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let redacted = redactor.feed(&buf[..n]);
                let _ = out.write_all(&redacted);
                let _ = out.flush();
            }
            Err(_) => break,
        }
    }

    let rest = redactor.finish();
    if !rest.is_empty() {
        let _ = out.write_all(&rest);
        let _ = out.flush();
    }

    // 10. Wait for child, shutdown guard, exit
    let exit_code = session.wait();

    let _ = guard_tx.send(());
    let _ = guard_handle.join();

    // Join seccomp supervisor (Linux only). The supervisor exits when
    // the listener fd is closed (child process exited).
    #[cfg(target_os = "linux")]
    {
        if let Some(handle) = seccomp_handle {
            let _ = handle.join();
        }
    }

    // Join stdin thread to ensure clean shutdown. drop() would detach
    // the thread, leaving it running during process teardown.
    let _ = stdin_handle.join();

    std::process::exit(exit_code);
}

/// Canonicalize a path, falling back to the original if canonicalization fails.
///
/// SECURITY: On macOS, symlinks like /var → /private/var mean that Seatbelt
/// rules must use canonical paths. Without canonicalization, a rule targeting
/// /var/folders/... wouldn't match the kernel's view of /private/var/folders/...
/// and the sandbox would fail to block or allow the intended path.
fn canonical_or_original(path: PathBuf) -> PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// Build a kernel sandbox configuration for credential file protection.
///
/// Resolves credential paths to deny, system paths to allow, and project
/// directory for read+write access. Respects user configuration from
/// ~/.unsee/credentials.conf if it exists.
///
/// All paths are canonicalized to handle macOS symlinks (e.g., /var →
/// /private/var) so Seatbelt rules match the kernel's view of the filesystem.
///
/// SECURITY: HOME handling is platform-specific:
/// - macOS (Seatbelt): allow_rw(HOME) + explicit deny rules for credential paths.
///   Seatbelt supports deny-overrides-allow for more-specific subpath rules.
/// - Linux (Landlock): enumerate HOME's immediate children and skip credential
///   directories. Landlock is strictly allow-list — once a parent directory is
///   allowed, all children are implicitly allowed with no way to carve exceptions.
fn build_sandbox() -> Result<UnseeSandbox> {
    let mut sandbox = UnseeSandbox::new();

    // Allow project directory (read+write)
    let cwd = std::env::current_dir().context("getting current directory")?;
    sandbox.allow_rw(canonical_or_original(cwd));

    // Allow system paths (read-only) so the agent can run commands
    for p in &["/usr", "/bin", "/sbin", "/lib", "/opt", "/etc"] {
        let path = PathBuf::from(p);
        if path.exists() {
            sandbox.allow_read(canonical_or_original(path));
        }
    }

    // macOS-specific system paths
    #[cfg(target_os = "macos")]
    {
        // SECURITY: Only allow specific subdirectories of /private/var that
        // are needed for normal operation. Avoid allowing /private/var broadly
        // because it contains macOS Keychain DB files under /private/var/db.
        for p in &[
            "/System",
            "/Library",
            "/Applications",
            "/private/etc",
            "/private/tmp",
            "/private/var/folders",  // per-user temp (narrowed from /private/var)
            "/private/var/run",      // sockets
            "/private/var/tmp",      // tmp
            "/var",
        ] {
            let path = PathBuf::from(p);
            if path.exists() {
                sandbox.allow_read(canonical_or_original(path));
            }
        }
    }

    // SECURITY: Only allow specific device nodes needed for terminal operation.
    // Broadly allowing /dev would expose /dev/mem, /dev/kmem, /dev/disk* etc.
    for p in &[
        "/dev/null",
        "/dev/zero",
        "/dev/urandom",
        "/dev/random",
        "/dev/tty",
        "/dev/ptmx",   // PTY multiplexer
        "/dev/pts",     // PTY slave devices (Linux)
        "/dev/fd",      // file descriptor device
        "/dev/stdin",
        "/dev/stdout",
        "/dev/stderr",
    ] {
        let path = PathBuf::from(p);
        if path.exists() {
            sandbox.allow_rw(canonical_or_original(path));
        }
    }

    // Allow interpose library path (read-only, needed for DYLD_INSERT_LIBRARIES)
    let dylib_path = WriteGuard::dylib_path();
    if dylib_path.exists() {
        // Allow the directory containing the dylib, not just the file
        if let Some(parent) = dylib_path.parent() {
            sandbox.allow_read(canonical_or_original(parent.to_path_buf()));
        }
    }

    // Allow TMPDIR (read+write)
    if let Ok(tmp) = std::env::var("TMPDIR") {
        sandbox.allow_rw(canonical_or_original(PathBuf::from(tmp)));
    }
    // Also allow /tmp as fallback (canonicalize handles /tmp → /private/tmp on macOS)
    sandbox.allow_rw(canonical_or_original(PathBuf::from("/tmp")));

    // HOME handling — platform-specific for correctness
    if let Ok(home) = std::env::var("HOME") {
        let home_canonical = canonical_or_original(PathBuf::from(&home));

        // Resolve credential paths (against canonical home)
        let config_path = home_canonical.join(".unsee/credentials.conf");
        let cred_paths = if config_path.exists() {
            credpaths::load_credential_config(&config_path, &home_canonical)
        } else {
            // SECURITY: On macOS, include ALL default credential paths regardless
            // of whether they exist. Seatbelt deny rules for nonexistent paths are
            // harmless, but omitting them creates a TOCTOU window: an attacker could
            // create the directory after sandbox setup.
            credpaths::resolve_all_credential_paths(&home_canonical)
        };

        // Build a lookup from credential relative path to trusted process names.
        // Paths in the trusted map get deny_with_trusted() (allowing specific
        // system binaries to read them); paths NOT in the map get plain deny().
        let trusted_map = credpaths::trusted_process_map();
        let trusted_lookup: HashMap<&str, &Vec<&str>> = trusted_map
            .iter()
            .map(|(dir, procs)| (*dir, procs))
            .collect();

        #[cfg(target_os = "macos")]
        {
            // macOS Seatbelt: allow HOME broadly, then deny credential subdirs.
            // Seatbelt evaluates more-specific (subpath) deny rules over broader
            // (subpath) allow rules, so this is safe.
            sandbox.allow_rw(home_canonical.clone());
            for p in &cred_paths {
                let canonical = canonical_or_original(p.clone());
                // Check if this credential path has trusted processes by matching
                // the relative path suffix against the trusted process map.
                let rel = p.strip_prefix(&home_canonical)
                    .ok()
                    .map(|r| r.to_string_lossy().to_string());
                if let Some(rel_str) = rel {
                    if let Some(procs) = trusted_lookup.get(rel_str.as_str()) {
                        let proc_strings: Vec<String> = procs.iter().map(|s| s.to_string()).collect();
                        sandbox.deny_with_trusted(canonical, proc_strings);
                        continue;
                    }
                }
                sandbox.deny(canonical);
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Linux Landlock: strictly allow-list. Cannot carve exceptions from
            // a parent allow rule. Must enumerate HOME's children and skip
            // credential directories.
            // SECURITY: This is critical — adding HOME as a single allow_rw would
            // grant access to ALL credential files, completely bypassing the sandbox.
            if let Ok(entries) = std::fs::read_dir(&home_canonical) {
                for entry in entries.flatten() {
                    let entry_path = canonical_or_original(entry.path());
                    if !credpaths::is_credential_path(&entry_path, &cred_paths) {
                        sandbox.allow_rw(entry_path);
                    }
                }
            }
            // Add deny paths with trusted process info where available.
            for p in &cred_paths {
                let canonical = canonical_or_original(p.clone());
                let rel = p.strip_prefix(&home_canonical)
                    .ok()
                    .map(|r| r.to_string_lossy().to_string());
                if let Some(rel_str) = rel {
                    if let Some(procs) = trusted_lookup.get(rel_str.as_str()) {
                        let proc_strings: Vec<String> = procs.iter().map(|s| s.to_string()).collect();
                        sandbox.deny_with_trusted(canonical, proc_strings);
                        continue;
                    }
                }
                sandbox.deny(canonical);
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            sandbox.allow_rw(home_canonical);
        }
    }

    Ok(sandbox)
}
