pub mod sandbox;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum GuardError {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("watch error: {0}")]
    Watch(String),
}

/// WriteGuard watches .env* files and replaces placeholders with real values
/// when an LLM agent writes back to them.
pub struct WriteGuard {
    /// placeholder → real value
    reverse_map: HashMap<String, String>,
    /// Files to watch
    watch_paths: Vec<PathBuf>,
}

impl WriteGuard {
    /// Create a new WriteGuard.
    pub fn new(reverse_map: HashMap<String, String>, watch_paths: Vec<PathBuf>) -> Self {
        WriteGuard {
            reverse_map,
            watch_paths,
        }
    }

    /// Check a file for placeholders and replace them with real values.
    /// Returns true if the file was modified.
    ///
    /// SECURITY: Opens with O_NOFOLLOW to prevent symlink TOCTOU attacks.
    /// Without this, an agent could replace a .env file with a symlink to
    /// ~/.ssh/config between the read and write, causing secret values to
    /// be written to an unintended file.
    pub fn fix_file(&self, path: &Path) -> bool {
        use std::os::unix::fs::OpenOptionsExt;

        // SECURITY: O_NOFOLLOW rejects symlinks at open time.
        // If path is a symlink, this returns ELOOP — we skip silently.
        let content = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => {
                use std::io::Read;
                let mut s = String::new();
                match std::io::BufReader::new(file).read_to_string(&mut s) {
                    Ok(_) => s,
                    Err(e) => {
                        eprintln!("unsee-guard: failed to read {}: {}", path.display(), e);
                        return false;
                    }
                }
            }
            Err(e) => {
                // ELOOP = symlink, ENOENT = deleted — both are expected
                if e.raw_os_error() != Some(libc::ELOOP) && e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("unsee-guard: failed to open {}: {}", path.display(), e);
                }
                return false;
            }
        };

        let mut fixed = content.clone();
        let mut changed = false;

        for (placeholder, real_value) in &self.reverse_map {
            if fixed.contains(placeholder.as_str()) {
                fixed = fixed.replace(placeholder.as_str(), real_value.as_str());
                changed = true;
            }
        }

        if changed {
            // SECURITY: Write with O_NOFOLLOW — same check as read.
            // Also log errors instead of silently ignoring them.
            match std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    if let Err(e) = file.write_all(fixed.as_bytes()) {
                        eprintln!("unsee-guard: failed to write {}: {}", path.display(), e);
                    }
                }
                Err(e) => {
                    eprintln!("unsee-guard: failed to open {} for writing: {}", path.display(), e);
                }
            }
        }
        changed
    }

    /// Path to the compiled interpose library (.dylib on macOS, .so on Linux).
    pub fn dylib_path() -> PathBuf {
        PathBuf::from(env!("UNSEE_DYLIB_PATH"))
    }

    /// Environment variable name for library preloading.
    pub fn preload_env_var() -> &'static str {
        if cfg!(target_os = "macos") {
            "DYLD_INSERT_LIBRARIES"
        } else {
            "LD_PRELOAD"
        }
    }
}

// ---- macOS: kqueue file watcher ----
#[cfg(target_os = "macos")]
impl WriteGuard {
    /// Watch files using kqueue, blocking until shutdown signal is received.
    pub fn watch_blocking(&self, shutdown: std::sync::mpsc::Receiver<()>) {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        use std::time::Duration;

        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            eprintln!("unsee-guard: kqueue failed");
            return;
        }

        let mut fds: Vec<(i32, PathBuf)> = Vec::new();
        let mut kevents: Vec<libc::kevent> = Vec::new();

        for path in &self.watch_paths {
            // SECURITY: O_NOFOLLOW prevents symlink TOCTOU attacks.
            // Without this, an agent could replace a watched .env file with
            // a symlink before kqueue registration, causing us to watch
            // (and later fix_file) a different file than intended.
            let file = match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
            {
                Ok(f) => f,
                Err(e) => {
                    if e.raw_os_error() != Some(libc::ELOOP) {
                        eprintln!("unsee-guard: open {}: {}", path.display(), e);
                    }
                    continue;
                }
            };
            let fd = file.as_raw_fd();
            std::mem::forget(file);

            fds.push((fd, path.clone()));
            kevents.push(libc::kevent {
                ident: fd as usize,
                filter: libc::EVFILT_VNODE,
                flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR,
                fflags: libc::NOTE_WRITE,
                data: 0,
                udata: std::ptr::null_mut(),
            });
        }

        if kevents.is_empty() {
            unsafe { libc::close(kq) };
            return;
        }

        let ret = unsafe {
            libc::kevent(
                kq,
                kevents.as_ptr(),
                kevents.len() as i32,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if ret < 0 {
            for (fd, _) in &fds {
                unsafe { libc::close(*fd) };
            }
            unsafe { libc::close(kq) };
            return;
        }

        let mut out_events = vec![unsafe { std::mem::zeroed::<libc::kevent>() }; 8];
        let timeout = libc::timespec { tv_sec: 1, tv_nsec: 0 };

        loop {
            if shutdown.try_recv().is_ok() {
                break;
            }
            let n = unsafe {
                libc::kevent(kq, std::ptr::null(), 0, out_events.as_mut_ptr(), out_events.len() as i32, &timeout)
            };
            if n < 0 { break; }
            for i in 0..n as usize {
                let fd = out_events[i].ident as i32;
                if let Some((_, path)) = fds.iter().find(|(f, _)| *f == fd) {
                    std::thread::sleep(Duration::from_millis(10));
                    if self.fix_file(path) {
                        eprintln!("unsee-guard: fixed placeholders in {}", path.display());
                    }
                }
            }
        }

        for (fd, _) in &fds {
            unsafe { libc::close(*fd) };
        }
        unsafe { libc::close(kq) };
    }
}

// ---- Linux: inotify file watcher ----
#[cfg(target_os = "linux")]
impl WriteGuard {
    /// Watch files using inotify, blocking until shutdown signal is received.
    pub fn watch_blocking(&self, shutdown: std::sync::mpsc::Receiver<()>) {
        use std::ffi::CString;
        use std::time::Duration;

        let ifd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK) };
        if ifd < 0 {
            eprintln!("unsee-guard: inotify_init failed");
            return;
        }

        let mut wd_map: HashMap<i32, PathBuf> = HashMap::new();
        for path in &self.watch_paths {
            if let Ok(c_path) = CString::new(path.to_string_lossy().as_bytes()) {
                let wd = unsafe {
                    libc::inotify_add_watch(ifd, c_path.as_ptr(), libc::IN_CLOSE_WRITE)
                };
                if wd >= 0 {
                    wd_map.insert(wd, path.clone());
                }
            }
        }

        if wd_map.is_empty() {
            unsafe { libc::close(ifd) };
            return;
        }

        let mut buf = [0u8; 4096];
        loop {
            if shutdown.try_recv().is_ok() {
                break;
            }

            // poll with 1s timeout
            let mut pfd = libc::pollfd {
                fd: ifd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pfd, 1, 1000) };
            if ret <= 0 {
                continue;
            }

            let n = unsafe {
                libc::read(ifd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n <= 0 {
                continue;
            }

            let mut offset = 0usize;
            while offset < n as usize {
                let event = unsafe {
                    &*(buf.as_ptr().add(offset) as *const libc::inotify_event)
                };
                if let Some(path) = wd_map.get(&event.wd) {
                    std::thread::sleep(Duration::from_millis(10));
                    if self.fix_file(path) {
                        eprintln!("unsee-guard: fixed placeholders in {}", path.display());
                    }
                }
                offset += std::mem::size_of::<libc::inotify_event>() + event.len as usize;
            }
        }

        unsafe { libc::close(ifd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn make_guard(pairs: &[(&str, &str)]) -> WriteGuard {
        let reverse_map: HashMap<String, String> = pairs
            .iter()
            .map(|(ph, real)| (ph.to_string(), real.to_string()))
            .collect();
        WriteGuard::new(reverse_map, vec![])
    }

    #[test]
    fn fix_file_replaces_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "SECRET=unsee:abc123\nOTHER=ok\n").unwrap();

        let guard = WriteGuard::new(
            HashMap::from([("unsee:abc123".into(), "real-secret".into())]),
            vec![],
        );
        assert!(guard.fix_file(&path));

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("SECRET=real-secret"));
        assert!(content.contains("OTHER=ok"));
        assert!(!content.contains("unsee:abc123"));
    }

    #[test]
    fn fix_file_no_change_when_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "SECRET=real-secret\n").unwrap();

        let guard = make_guard(&[("unsee:abc123", "real-secret")]);
        assert!(!guard.fix_file(&path));
    }

    #[test]
    fn fix_file_preserves_other_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "# comment\nA=unsee:aaa\nB=keep\n\nC=unsee:ccc\n").unwrap();

        let guard = WriteGuard::new(
            HashMap::from([
                ("unsee:aaa".into(), "real-a".into()),
                ("unsee:ccc".into(), "real-c".into()),
            ]),
            vec![],
        );
        assert!(guard.fix_file(&path));

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# comment"));
        assert!(content.contains("A=real-a"));
        assert!(content.contains("B=keep"));
        assert!(content.contains("C=real-c"));
        assert!(content.contains("\n\n"));
    }

    // ---- watch_blocking test: works on both macOS (kqueue) and Linux (inotify) ----
    #[test]
    fn watch_detects_and_fixes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "KEY=clean\n").unwrap();

        let guard = WriteGuard::new(
            HashMap::from([("unsee:test".into(), "real-val".into())]),
            vec![path.clone()],
        );

        let (tx, rx) = mpsc::channel();
        let path_clone = path.clone();
        let handle = std::thread::spawn(move || {
            guard.watch_blocking(rx);
        });

        std::thread::sleep(Duration::from_millis(200));
        std::fs::write(&path_clone, "KEY=unsee:test\n").unwrap();

        std::thread::sleep(Duration::from_millis(500));

        let content = std::fs::read_to_string(&path_clone).unwrap();
        assert!(content.contains("KEY=real-val"), "content: {}", content);

        tx.send(()).unwrap();
        handle.join().unwrap();
    }

    // ---- dylib/so interpose tests: cross-platform ----
    #[test]
    fn dylib_intercepts_python_write() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("map.tsv");
        std::fs::write(&map_path, "unsee:testph00001234\treal-secret-value\n").unwrap();

        let env_path = dir.path().join(".env");
        let script = format!(
            "f = open('{}', 'w')\nf.write('KEY=unsee:testph00001234\\n')\nf.close()",
            env_path.display()
        );

        let output = std::process::Command::new("python3")
            .args(["-c", &script])
            .env(WriteGuard::preload_env_var(), WriteGuard::dylib_path())
            .env("UNSEE_MAP_FILE", map_path.to_str().unwrap())
            .output()
            .expect("python3 is required for this test");

        assert!(
            output.status.success(),
            "python3 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let content = std::fs::read_to_string(&env_path).unwrap();
        assert!(content.contains("real-secret-value"), "interpose didn't replace: {}", content);
        assert!(!content.contains("unsee:testph00001234"), "placeholder leaked: {}", content);
    }

    #[test]
    fn dylib_intercepts_node_write() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("map.tsv");
        std::fs::write(&map_path, "unsee:nodetest12345\tnode-real-secret\n").unwrap();

        let env_path = dir.path().join(".env");
        let script = format!(
            "require('fs').writeFileSync('{}', 'TOKEN=unsee:nodetest12345\\n')",
            env_path.display()
        );

        let output = std::process::Command::new("node")
            .args(["-e", &script])
            .env(WriteGuard::preload_env_var(), WriteGuard::dylib_path())
            .env("UNSEE_MAP_FILE", map_path.to_str().unwrap())
            .output()
            .expect("node is required for this test");

        assert!(
            output.status.success(),
            "node failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let content = std::fs::read_to_string(&env_path).unwrap();
        assert!(content.contains("node-real-secret"), "interpose didn't replace: {}", content);
        assert!(!content.contains("unsee:nodetest12345"), "placeholder leaked: {}", content);
    }

    #[test]
    fn dylib_no_false_positive_non_env() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("map.tsv");
        std::fs::write(&map_path, "unsee:fptest1234567\tfp-real-secret\n").unwrap();

        let txt_path = dir.path().join("config.txt");
        let script = format!(
            "f = open('{}', 'w')\nf.write('KEY=unsee:fptest1234567\\n')\nf.close()",
            txt_path.display()
        );

        let output = std::process::Command::new("python3")
            .args(["-c", &script])
            .env(WriteGuard::preload_env_var(), WriteGuard::dylib_path())
            .env("UNSEE_MAP_FILE", map_path.to_str().unwrap())
            .output()
            .expect("python3 is required for this test");

        assert!(output.status.success());

        let content = std::fs::read_to_string(&txt_path).unwrap();
        assert!(content.contains("unsee:fptest1234567"), "non-env file was intercepted: {}", content);
        assert!(!content.contains("fp-real-secret"), "real secret leaked to non-env file: {}", content);
    }

    #[test]
    fn dylib_skips_env_example() {
        let dir = tempfile::tempdir().unwrap();
        let map_path = dir.path().join("map.tsv");
        std::fs::write(&map_path, "unsee:exmpl1234567\texample-real-secret\n").unwrap();

        let example_path = dir.path().join(".env.example");
        let script = format!(
            "f = open('{}', 'w')\nf.write('KEY=unsee:exmpl1234567\\n')\nf.close()",
            example_path.display()
        );

        let output = std::process::Command::new("python3")
            .args(["-c", &script])
            .env(WriteGuard::preload_env_var(), WriteGuard::dylib_path())
            .env("UNSEE_MAP_FILE", map_path.to_str().unwrap())
            .output()
            .expect("python3 is required for this test");

        assert!(output.status.success());

        let content = std::fs::read_to_string(&example_path).unwrap();
        assert!(content.contains("unsee:exmpl1234567"), ".env.example was intercepted: {}", content);
        assert!(!content.contains("example-real-secret"), "real secret leaked to .env.example: {}", content);
    }
}
