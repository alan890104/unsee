use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum UnseeError {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parse error in {path}: {message}")]
    Parse { path: PathBuf, message: String },
}

/// Discovered env files with their parsed key-value pairs and raw content.
pub struct EnvFileSet {
    /// path → parsed key-value pairs
    pub files: HashMap<PathBuf, HashMap<String, String>>,
    /// path → raw file content (preserves comments, ordering, blank lines)
    pub raw_contents: HashMap<PathBuf, String>,
}

/// Discover all .env* files in a directory.
///
/// Matches: .env, .env.local, .env.staging, .env.production, etc.
/// Does NOT match: .envrc, .environment, env.txt, .env.swp
pub fn discover_env_files(dir: &Path) -> Result<Vec<PathBuf>, UnseeError> {
    let entries = fs::read_dir(dir).map_err(|e| UnseeError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;

    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| UnseeError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if is_env_file(&name_str) {
            let path = entry.path();
            let meta = fs::metadata(&path).map_err(|e| UnseeError::Io {
                path: path.clone(),
                source: e,
            })?;
            if meta.is_file() {
                found.push(path);
            }
        }
    }

    found.sort();
    Ok(found)
}

/// Suffixes that indicate template/example files — not real secrets.
const TEMPLATE_SUFFIXES: &[&str] = &[".example", ".sample", ".template"];

/// Vim swap file suffixes — binary format, can't parse as key=value text.
const EDITOR_SWAP_SUFFIXES: &[&str] = &[".swp", ".swo", ".swn"];

/// Check if a filename matches .env patterns.
///
/// Matches: .env, .env.local, .env.staging, .env.production, .env.dev, .env.test
///          .env~ (editor backup), #.env# (emacs auto-save)
/// Rejects: .envrc, .environment, .env.example, .env.sample, .env.template
///          .env.swp, .env.swo, .env.swn (vim swap — binary, not parseable)
pub fn is_env_file(name: &str) -> bool {
    // Emacs auto-save: #.env# or #.env.local#
    // These are text copies of the buffer, contain real secrets.
    if name.starts_with('#') && name.ends_with('#') {
        let inner = &name[1..name.len() - 1];
        return is_env_file(inner);
    }

    // Vim/Emacs/Nano backup: .env~ or .env.local~
    // These are text copies of the file, contain real secrets.
    if name.ends_with('~') {
        let inner = &name[..name.len() - 1];
        return is_env_file(inner);
    }

    // Standard .env matching
    if !name.starts_with(".env") {
        return false;
    }
    if name == ".env" {
        return true;
    }
    // ".env.xxx" → yes; ".envxxx" → no
    if name.as_bytes().get(4) != Some(&b'.') {
        return false;
    }
    let suffix = &name[4..]; // e.g. ".local", ".example"

    // Reject template files — not real secrets
    if TEMPLATE_SUFFIXES.contains(&suffix) {
        return false;
    }

    // Reject vim swap files — binary format, can't parse as text
    if EDITOR_SWAP_SUFFIXES.contains(&suffix) {
        return false;
    }

    true
}

/// Parse multiple .env files, returning an EnvFileSet.
pub fn parse_env_files(paths: &[PathBuf]) -> Result<EnvFileSet, UnseeError> {
    let mut files = HashMap::new();
    let mut raw_contents = HashMap::new();

    for path in paths {
        let raw = fs::read_to_string(path).map_err(|e| UnseeError::Io {
            path: path.clone(),
            source: e,
        })?;
        raw_contents.insert(path.clone(), raw);

        let parsed = dotenvy::from_path_iter(path)
            .map_err(|e| UnseeError::Parse {
                path: path.clone(),
                message: e.to_string(),
            })?
            .collect::<Result<HashMap<String, String>, _>>()
            .map_err(|e| UnseeError::Parse {
                path: path.clone(),
                message: e.to_string(),
            })?;
        files.insert(path.clone(), parsed);
    }

    Ok(EnvFileSet { files, raw_contents })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_env_file_accepts_dotenv_variants() {
        assert!(is_env_file(".env"));
        assert!(is_env_file(".env.local"));
        assert!(is_env_file(".env.staging"));
        assert!(is_env_file(".env.production"));
        assert!(is_env_file(".env.dev"));
        assert!(is_env_file(".env.test"));
    }

    #[test]
    fn is_env_file_rejects_envrc_environment() {
        assert!(!is_env_file(".envrc"));
        assert!(!is_env_file(".environment"));
        assert!(!is_env_file("env.txt"));
        assert!(!is_env_file("test.env"));
    }

    #[test]
    fn is_env_file_rejects_templates() {
        assert!(!is_env_file(".env.example"));
        assert!(!is_env_file(".env.sample"));
        assert!(!is_env_file(".env.template"));
    }

    #[test]
    fn discover_finds_only_env_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), "A=1\n").unwrap();
        fs::write(dir.path().join(".env.local"), "B=2\n").unwrap();
        fs::write(dir.path().join(".envrc"), "nope\n").unwrap();
        fs::write(dir.path().join("readme.txt"), "nope\n").unwrap();

        let found = discover_env_files(dir.path()).unwrap();
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec![".env", ".env.local"]);
    }

    #[test]
    fn test_env_backup_tilde_matched() {
        // Editor backup files (.env~) are text copies containing real secrets.
        assert!(is_env_file(".env~"));
        assert!(is_env_file(".env.local~"));
        assert!(is_env_file(".env.staging~"));
    }

    #[test]
    fn test_env_emacs_autosave_matched() {
        // Emacs auto-save files (#.env#) are text copies containing real secrets.
        assert!(is_env_file("#.env#"));
        assert!(is_env_file("#.env.local#"));
        assert!(is_env_file("#.env.production#"));
    }

    #[test]
    fn test_env_swap_rejected() {
        // Vim swap files are binary — can't parse as key=value text.
        assert!(!is_env_file(".env.swp"));
        assert!(!is_env_file(".env.swo"));
        assert!(!is_env_file(".env.swn"));
    }

    #[test]
    fn test_env_templates_still_rejected() {
        // Template files don't contain real secrets — unchanged behavior.
        assert!(!is_env_file(".env.example"));
        assert!(!is_env_file(".env.sample"));
        assert!(!is_env_file(".env.template"));
        // Tilde backup of template is also not a secret file.
        assert!(!is_env_file(".env.example~"));
        assert!(!is_env_file("#.env.example#"));
    }

    #[test]
    fn test_discover_finds_backup_files() {
        // Editor backup files should be discovered alongside regular .env files.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), "A=1\n").unwrap();
        fs::write(dir.path().join(".env~"), "A=1\n").unwrap();
        fs::write(dir.path().join("#.env#"), "A=1\n").unwrap();
        // Swap file should NOT be discovered
        fs::write(dir.path().join(".env.swp"), "binary junk\n").unwrap();

        let found = discover_env_files(dir.path()).unwrap();
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&".env".to_string()));
        assert!(names.contains(&".env~".to_string()));
        assert!(names.contains(&"#.env#".to_string()));
        assert!(!names.contains(&".env.swp".to_string()));
    }

    #[test]
    fn parse_reads_key_values() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        fs::write(&env_path, "KEY=value\nOTHER=123\n").unwrap();

        let set = parse_env_files(&[env_path.clone()]).unwrap();
        assert_eq!(set.files.len(), 1);
        let vars = &set.files[&env_path];
        assert_eq!(vars.get("KEY").unwrap(), "value");
        assert_eq!(vars.get("OTHER").unwrap(), "123");
    }

    #[test]
    fn parse_preserves_raw_content() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let content = "# comment\nKEY=value\n\nOTHER=123\n";
        fs::write(&env_path, content).unwrap();

        let set = parse_env_files(&[env_path.clone()]).unwrap();
        assert_eq!(set.raw_contents[&env_path], content);
    }
}
