use std::path::PathBuf;

use anyhow::{Context, Result};

const UNSEE_MARKER_START: &str = "# >>> unsee credential protection >>>";
const UNSEE_MARKER_END: &str = "# <<< unsee credential protection <<<";

fn rc_files() -> Vec<(&'static str, PathBuf)> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let home = PathBuf::from(home);

    vec![
        ("zsh", home.join(".zshenv")),
        ("bash", home.join(".bashrc")),
        ("fish", home.join(".config/fish/config.fish")),
    ]
}

fn remove_block(path: &PathBuf) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;

    if !content.contains(UNSEE_MARKER_START) {
        return Ok(false);
    }

    let mut result = String::new();
    let mut in_block = false;
    for line in content.lines() {
        if line.contains(UNSEE_MARKER_START) {
            in_block = true;
            continue;
        }
        if line.contains(UNSEE_MARKER_END) {
            in_block = false;
            continue;
        }
        if !in_block {
            result.push_str(line);
            result.push('\n');
        }
    }

    let result = result.trim_end().to_string();

    if result.is_empty() {
        std::fs::remove_file(path)
            .with_context(|| format!("removing empty {}", path.display()))?;
    } else {
        std::fs::write(path, format!("{}\n", result))
            .with_context(|| format!("writing {}", path.display()))?;
    }

    Ok(true)
}

fn is_homebrew_install() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let path = exe.to_string_lossy();
    path.contains("/Cellar/") || path.contains("/homebrew/")
}

pub fn run() -> Result<()> {
    let mut removed = Vec::new();

    for (name, path) in rc_files() {
        if remove_block(&path)? {
            removed.push((name, path));
        }
    }

    if removed.is_empty() {
        println!("No unsee wrappers found in any shell config.");
    } else {
        for (name, path) in &removed {
            println!("Removed unsee wrappers from {} ({})", name, path.display());
        }
    }

    if is_homebrew_install() {
        println!("Uninstalling Homebrew package...");
        let status = std::process::Command::new("brew")
            .args(["uninstall", "unsee"])
            .status()
            .context("running brew uninstall")?;
        if status.success() {
            println!("Done. unsee has been fully removed.");
        } else {
            eprintln!("brew uninstall failed. Run `brew uninstall unsee` manually.");
        }
    }

    Ok(())
}
