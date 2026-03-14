use std::path::PathBuf;
use std::process::Command;

/// Find the unsee binary relative to the test executable.
/// Works in both native `cargo test` and `cross test` environments.
fn unsee_bin() -> PathBuf {
    let test_exe = std::env::current_exe().expect("current_exe");
    // test binary:   .../deps/e2e-<hash>
    // unsee binary: .../shield
    let bin = test_exe
        .parent()
        .unwrap() // deps/
        .parent()
        .unwrap() // debug/
        .join("unsee");
    assert!(
        bin.exists(),
        "unsee binary not found at {}",
        bin.display()
    );
    bin
}

#[test]
fn init_creates_unsee_ignore() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), "SECRET=value\nAPI_KEY=key123\n").unwrap();

    let output = Command::new(unsee_bin())
        .args(["init", "--dir", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "init failed (exit {:?}):\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        dir.path().join(".unsee.ignore").exists(),
        ".unsee.ignore not created"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SECRET"), "should list SECRET key: {}", stdout);
    assert!(stdout.contains("API_KEY"), "should list API_KEY key: {}", stdout);
}

#[test]
fn status_shows_secret_count() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), "A=1\nB=2\nC=3\n").unwrap();

    let output = Command::new(unsee_bin())
        .args(["status", "--dir", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "status failed (exit {:?}):\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("3"),
        "should show secret count of 3: {}",
        stdout
    );
}

#[test]
fn ignore_appends_to_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".unsee.ignore"), "EXISTING\n").unwrap();

    let output = Command::new(unsee_bin())
        .args(["ignore", "NEW_VAR", "--dir", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "ignore failed (exit {:?}):\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let content = std::fs::read_to_string(dir.path().join(".unsee.ignore")).unwrap();
    assert!(content.contains("EXISTING"), "lost existing entry");
    assert!(content.contains("NEW_VAR"), "new var not added");
}

#[test]
fn install_writes_shell_wrappers() {
    let dir = tempfile::tempdir().unwrap();

    let output = Command::new(unsee_bin())
        .args(["install"])
        .env("HOME", dir.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "install failed (exit {:?}):\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // zsh (always available on macOS, usually on Linux)
    let zshenv_path = dir.path().join(".zshenv");
    if zshenv_path.exists() {
        let content = std::fs::read_to_string(&zshenv_path).unwrap();
        assert!(content.contains("claude"), "zsh missing claude: {}", content);
        assert!(content.contains("codex"), "zsh missing codex: {}", content);
        assert!(content.contains("gemini"), "zsh missing gemini: {}", content);
        assert!(content.contains("unsee protect"), "zsh missing unsee protect: {}", content);
        assert!(content.contains("\"$@\""), "zsh should use POSIX syntax: {}", content);
    }

    // bash (always available on Linux, usually on macOS)
    let bashrc_path = dir.path().join(".bashrc");
    if bashrc_path.exists() {
        let content = std::fs::read_to_string(&bashrc_path).unwrap();
        assert!(content.contains("claude"), "bash missing claude: {}", content);
        assert!(content.contains("unsee protect"), "bash missing unsee protect: {}", content);
        assert!(content.contains("\"$@\""), "bash should use POSIX syntax: {}", content);
        assert!(content.contains("__UNSEE_ACTIVE"), "bash missing re-entrancy guard: {}", content);
    }

    // fish (only if installed)
    let fish_path = dir.path().join(".config/fish/config.fish");
    if fish_path.exists() {
        let content = std::fs::read_to_string(&fish_path).unwrap();
        assert!(content.contains("function claude"), "fish missing claude function: {}", content);
        assert!(content.contains("$argv"), "fish should use $argv not $@: {}", content);
    }

    // At least one shell must have been configured
    assert!(
        zshenv_path.exists() || bashrc_path.exists() || fish_path.exists(),
        "no shell config was written"
    );
}

#[test]
fn install_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();

    // Install twice
    for _ in 0..2 {
        let output = Command::new(unsee_bin())
            .args(["install"])
            .env("HOME", dir.path())
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    // Check that block appears only once
    let zshenv_path = dir.path().join(".zshenv");
    if zshenv_path.exists() {
        let content = std::fs::read_to_string(&zshenv_path).unwrap();
        let count = content.matches("unsee credential protection >>>").count();
        assert_eq!(count, 1, "block duplicated after double install:\n{}", content);
    }
}

#[test]
fn uninstall_removes_all_shells() {
    let dir = tempfile::tempdir().unwrap();

    // Install first
    let output = Command::new(unsee_bin())
        .args(["install"])
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    // Uninstall
    let output = Command::new(unsee_bin())
        .args(["uninstall"])
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "uninstall failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // Verify no unsee blocks remain
    for name in &[".zshenv", ".bashrc", ".config/fish/config.fish"] {
        let path = dir.path().join(name);
        if path.exists() {
            let content = std::fs::read_to_string(&path).unwrap();
            assert!(
                !content.contains("unsee credential protection"),
                "unsee block still in {} after uninstall:\n{}",
                name,
                content
            );
        }
    }
}

#[test]
fn protect_redacts_output() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), "SECRET=my-real-secret-value-xyz\n").unwrap();

    let output = Command::new(unsee_bin())
        .args(["protect", "--", "cat", ".env"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("my-real-secret-value-xyz"),
        "secret leaked in output: {}",
        stdout
    );
    assert!(
        stdout.contains("unsee:"),
        "output should contain placeholder: {}",
        stdout
    );
}

#[test]
fn protect_reexec_cleans_parent_procargs() {
    // Verify that unsee's own process environment (visible via procargs/environ)
    // does NOT contain secret values after double-exec.
    //
    // Strategy: run `unsee protect -- sleep 2`, then from outside inspect
    // the unsee process's environment. The secret should NOT appear.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), "PROCARGS_SECRET=super-secret-procargs-value\n").unwrap();

    // Start unsee protect with a long-running child so we have time to inspect
    let mut child = Command::new(unsee_bin())
        .args(["protect", "--", "sleep", "5"])
        .current_dir(dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Wait a moment for re-exec to complete
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Read procargs of the unsee process tree.
    // On macOS: ps eww <pid> shows env vars from kernel snapshot.
    // On Linux: /proc/<pid>/environ has the env snapshot.
    let unsee_pid = child.id();

    let env_snapshot = if cfg!(target_os = "macos") {
        let ps = Command::new("ps")
            .args(["eww", "-p", &unsee_pid.to_string()])
            .output()
            .unwrap();
        String::from_utf8_lossy(&ps.stdout).to_string()
    } else {
        // On Linux, read /proc/PID/environ (may need same-user)
        let environ_path = format!("/proc/{}/environ", unsee_pid);
        std::fs::read_to_string(&environ_path).unwrap_or_default()
    };

    // Clean up
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !env_snapshot.contains("super-secret-procargs-value"),
        "secret leaked in unsee process procargs!\nsnapshot: {}",
        &env_snapshot[..env_snapshot.len().min(2000)]
    );
}

#[test]
fn protect_sets_unsee_active() {
    // Verify __UNSEE_ACTIVE is set in the child's environment,
    // so shell wrappers skip re-wrapping in nested shells.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), "SECRET=long-secret-value-xyz\n").unwrap();

    let output = Command::new(unsee_bin())
        .args(["protect", "--", "sh", "-c", "echo ACTIVE=$__UNSEE_ACTIVE"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ACTIVE=1"),
        "__UNSEE_ACTIVE not set in child env: {}",
        stdout
    );
}

#[test]
fn protect_preserves_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), "A=1\n").unwrap();

    let output = Command::new(unsee_bin())
        .args(["protect", "--", "sh", "-c", "exit 42"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert_eq!(
        output.status.code().unwrap(),
        42,
        "exit code should be preserved, stderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn protect_blocks_credential_file() {
    // Verify that unsee protect blocks access to credential files
    // when kernel sandbox is available. Without sandbox (e.g., Docker
    // Desktop where Landlock isn't available), credential blocking is
    // not possible — verify unsee runs without crashing and emits a warning.
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();

    // Create fake credential file
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("id_rsa"), "FAKE_PRIVATE_KEY_CONTENT").unwrap();

    // Create .env file (required for unsee protect to work)
    std::fs::write(home.join(".env"), "A=1\n").unwrap();

    let output = Command::new(unsee_bin())
        .args(["protect", "--", "cat", &format!("{}/.ssh/id_rsa", home.display())])
        .current_dir(home)
        .env("HOME", home)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    if stderr.contains("kernel sandbox not available") || stderr.contains("kernel sandbox probe failed") {
        // No sandbox support (e.g., Docker Desktop) — verify unsee ran
        // without crashing. Credential blocking requires kernel support;
        // other defense layers (StreamRedactor, WriteGuard) still protect
        // .env secrets.
        assert!(
            output.status.success(),
            "unsee should not crash when sandbox is unavailable, exit: {:?}\nstderr: {}",
            output.status.code(),
            stderr
        );
    } else {
        // Sandbox available — credential content must NOT appear in output
        assert!(
            !combined.contains("FAKE_PRIVATE_KEY_CONTENT"),
            "credential file content leaked! stdout: {}\nstderr: {}",
            stdout,
            stderr
        );
    }
}

#[test]
fn protect_allows_normal_files() {
    // Verify that unsee protect allows reading normal project files.
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();

    // Create .env file
    std::fs::write(home.join(".env"), "A=1\n").unwrap();

    // Create a normal file in the project directory
    std::fs::write(home.join("readme.txt"), "Hello World").unwrap();

    let output = Command::new(unsee_bin())
        .args(["protect", "--", "cat", "readme.txt"])
        .current_dir(home)
        .env("HOME", home)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Hello World"),
        "normal file should be readable, stdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn protect_credential_plus_env_redaction() {
    // Verify both credential blocking AND .env redaction work simultaneously.
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();

    // Create fake credential file
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("id_rsa"), "SSH_PRIVATE_KEY_DATA").unwrap();

    // Create .env with a secret
    std::fs::write(home.join(".env"), "SECRET=my-super-secret-value-abc\n").unwrap();

    // Try to read the .env file (should show placeholders, not real values)
    let output = Command::new(unsee_bin())
        .args(["protect", "--", "cat", ".env"])
        .current_dir(home)
        .env("HOME", home)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // .env redaction should still work
    assert!(
        !stdout.contains("my-super-secret-value-abc"),
        ".env secret leaked in output: {}",
        stdout
    );
    assert!(
        stdout.contains("unsee:"),
        "output should contain placeholder: {}",
        stdout
    );

    // Now try to read the credential file — should fail if sandbox available
    let output2 = Command::new(unsee_bin())
        .args(["protect", "--", "cat", &format!("{}/.ssh/id_rsa", home.display())])
        .current_dir(home)
        .env("HOME", home)
        .output()
        .unwrap();

    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    let combined2 = format!("{}{}", stdout2, stderr2);

    if !stderr2.contains("kernel sandbox not available") && !stderr2.contains("kernel sandbox probe failed") {
        // Sandbox available — credential content must NOT appear in output
        assert!(
            !combined2.contains("SSH_PRIVATE_KEY_DATA"),
            "credential content leaked! stdout: {}\nstderr: {}",
            stdout2,
            stderr2
        );
    }
    // Without sandbox, credential blocking is not possible — the .env
    // redaction part above already verified Shield's core functionality.
}

// ---- Per-process credential access control E2E tests ----
// These tests verify that trusted system binaries (ssh) can access
// credential files while untrusted processes (cat) cannot.
// These tests will FAIL until the feature is implemented.

#[test]
#[cfg(target_os = "macos")]
fn test_protect_ssh_allowed_under_sandbox() {
    // Trusted binaries like ssh must still function under the sandbox.
    // ssh -V just prints the version string and exits — it does not
    // need actual keys, but it does probe ~/.ssh for config. This test
    // verifies that ssh is not blocked by the sandbox.
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();

    // Create fake credential file and .env
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("id_rsa"), "FAKE_SSH_KEY_CONTENT").unwrap();
    std::fs::write(home.join(".env"), "A=1\n").unwrap();

    let output = Command::new(unsee_bin())
        .args(["protect", "--", "ssh", "-V"])
        .current_dir(home)
        .env("HOME", home)
        .output()
        .unwrap();

    // ssh -V prints to stderr and exits 0
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "ssh -V should succeed under sandbox, exit: {:?}\nstderr: {}",
        output.status.code(),
        stderr
    );
}

#[test]
#[cfg(target_os = "macos")]
fn test_protect_cat_blocked_from_ssh_key() {
    // Untrusted processes like cat must NOT be able to read credential
    // files. Even if cat succeeds (exit 0 with empty output), the key
    // content must not appear anywhere in the output.
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();

    // Create fake credential file and .env
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::write(ssh_dir.join("id_rsa"), "CAT_TEST_PRIVATE_KEY_CONTENT").unwrap();
    std::fs::write(home.join(".env"), "A=1\n").unwrap();

    let output = Command::new(unsee_bin())
        .args([
            "protect",
            "--",
            "cat",
            &format!("{}/.ssh/id_rsa", home.display()),
        ])
        .current_dir(home)
        .env("HOME", home)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // The private key content must NOT appear in any output channel
    assert!(
        !combined.contains("CAT_TEST_PRIVATE_KEY_CONTENT"),
        "cat must be blocked from reading credential files!\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}
