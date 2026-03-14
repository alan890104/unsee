use std::collections::{HashMap, HashSet};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::parser::EnvFileSet;

type HmacSha256 = Hmac<Sha256>;

/// Multi-file mapping: each (filename, var_name) pair gets a unique HMAC placeholder.
pub struct MultiFileMapping {
    session_key: Vec<u8>,
    /// placeholder → real secret value
    forward: HashMap<String, String>,
    /// (filename, var_name) → placeholder
    placeholders: HashMap<(String, String), String>,
    /// ignored variable names (passed through as-is)
    ignored: HashSet<String>,
}

impl Drop for MultiFileMapping {
    fn drop(&mut self) {
        self.session_key.zeroize();
        for val in self.forward.values_mut() {
            val.zeroize();
        }
        self.forward.clear();
        self.placeholders.clear();
    }
}

impl MultiFileMapping {
    /// Build mapping from an EnvFileSet.
    ///
    /// HMAC input includes filename so the same key in different files gets different placeholders.
    pub fn build(
        file_set: &EnvFileSet,
        ignorelist: &HashSet<String>,
        session_key: Option<Vec<u8>>,
    ) -> Self {
        let session_key = session_key.unwrap_or_else(|| {
            let mut key = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            key
        });

        let mut forward = HashMap::new();
        let mut placeholders = HashMap::new();
        let ignored = ignorelist.clone();

        for (path, vars) in &file_set.files {
            let filename = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            for (name, value) in vars {
                if ignorelist.contains(name) {
                    continue;
                }
                let placeholder = generate_placeholder(&session_key, &filename, name);
                forward.insert(placeholder.clone(), value.clone());
                placeholders.insert((filename.clone(), name.clone()), placeholder);
            }
        }

        MultiFileMapping {
            session_key,
            forward,
            placeholders,
            ignored,
        }
    }

    /// Produce redacted content for a given file, preserving comments, blank lines, key order.
    pub fn redacted_content(&self, filename: &str, raw_content: &str) -> String {
        let mut output = String::with_capacity(raw_content.len());
        for line in raw_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim();
                let val_part = &line[eq_pos + 1..];

                if self.ignored.contains(key) {
                    output.push_str(line);
                    output.push('\n');
                } else if let Some(placeholder) =
                    self.placeholders.get(&(filename.to_string(), key.to_string()))
                {
                    let (quote_start, quote_end) = detect_quotes(val_part);
                    output.push_str(key);
                    output.push('=');
                    output.push_str(quote_start);
                    output.push_str(placeholder);
                    output.push_str(quote_end);
                    output.push('\n');
                } else {
                    output.push_str(line);
                    output.push('\n');
                }
            } else {
                output.push_str(line);
                output.push('\n');
            }
        }
        output
    }

    /// Resolve a placeholder back to its real value.
    pub fn resolve(&self, placeholder: &str) -> Option<&str> {
        self.forward.get(placeholder).map(|s| s.as_str())
    }

    /// Get the placeholder for a specific (filename, var_name) pair.
    pub fn get_placeholder(&self, filename: &str, var_name: &str) -> Option<&str> {
        self.placeholders
            .get(&(filename.to_string(), var_name.to_string()))
            .map(|s| s.as_str())
    }

    /// Get all (real_value, placeholder) pairs for StreamRedactor.
    pub fn redacted_secrets(&self) -> Vec<(String, String)> {
        self.forward
            .iter()
            .map(|(placeholder, real)| (real.clone(), placeholder.clone()))
            .collect()
    }

    /// Get reverse map: placeholder → real value, for WriteGuard.
    pub fn reverse_map(&self) -> HashMap<String, String> {
        self.forward.clone()
    }

    /// Serialize mapping as TSV (placeholder\treal_value per line) for UNSEE_MAP_FILE.
    pub fn to_tsv(&self) -> String {
        let mut lines: Vec<String> = self
            .forward
            .iter()
            .map(|(placeholder, real)| format!("{}\t{}", placeholder, real))
            .collect();
        lines.sort(); // deterministic output
        lines.join("\n")
    }

    /// Number of secrets mapped.
    pub fn secrets_count(&self) -> usize {
        self.forward.len()
    }

    /// Session key as hex string.
    pub fn session_key_hex(&self) -> String {
        hex::encode(&self.session_key)
    }
}

/// Detect quoting style of a value part (after the '=').
fn detect_quotes(val: &str) -> (&str, &str) {
    let trimmed = val.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') {
        ("\"", "\"")
    } else if trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        ("'", "'")
    } else {
        ("", "")
    }
}

/// Generate a placeholder: `unsee:<16 hex chars>`
/// HMAC-SHA256(session_key, "filename:var_name"), taking first 8 bytes.
fn generate_placeholder(session_key: &[u8], filename: &str, var_name: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(session_key).expect("HMAC can take key of any size");
    let input = format!("{}:{}", filename, var_name);
    mac.update(input.as_bytes());
    let result = mac.finalize().into_bytes();
    let tag = hex::encode(&result[..8]);
    format!("unsee:{}", tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::EnvFileSet;
    use std::path::PathBuf;

    fn make_file_set(
        entries: &[(&str, &[(&str, &str)])],
    ) -> EnvFileSet {
        let mut files = HashMap::new();
        let raw_contents = HashMap::new();
        for (filename, vars) in entries {
            let path = PathBuf::from(format!("/tmp/{}", filename));
            let mut map = HashMap::new();
            for (k, v) in *vars {
                map.insert(k.to_string(), v.to_string());
            }
            files.insert(path, map);
        }
        EnvFileSet { files, raw_contents }
    }

    #[test]
    fn placeholder_format_is_unsee_16hex() {
        let key = vec![0u8; 32];
        let ph = generate_placeholder(&key, ".env", "TEST_VAR");
        let re = regex_lite::Regex::new(r"^unsee:[0-9a-f]{16}$").unwrap();
        assert!(re.is_match(&ph), "placeholder '{}' doesn't match format", ph);
    }

    #[test]
    fn deterministic_same_session_same_file_same_var() {
        let key = vec![42u8; 32];
        let ph1 = generate_placeholder(&key, ".env", "SECRET");
        let ph2 = generate_placeholder(&key, ".env", "SECRET");
        assert_eq!(ph1, ph2);
    }

    #[test]
    fn different_session_keys_different_placeholders() {
        let key1 = vec![1u8; 32];
        let key2 = vec![2u8; 32];
        let ph1 = generate_placeholder(&key1, ".env", "SECRET");
        let ph2 = generate_placeholder(&key2, ".env", "SECRET");
        assert_ne!(ph1, ph2);
    }

    #[test]
    fn same_var_different_files_different_placeholders() {
        let key = vec![42u8; 32];
        let ph1 = generate_placeholder(&key, ".env", "SECRET_KEY");
        let ph2 = generate_placeholder(&key, ".env.staging", "SECRET_KEY");
        assert_ne!(ph1, ph2);
    }

    #[test]
    fn ignored_vars_excluded() {
        let file_set = make_file_set(&[
            (".env", &[("SECRET", "real"), ("DEBUG", "true")]),
        ]);
        let mut ignorelist = HashSet::new();
        ignorelist.insert("DEBUG".to_string());

        let mapping = MultiFileMapping::build(&file_set, &ignorelist, Some(vec![0u8; 32]));
        assert_eq!(mapping.secrets_count(), 1);
        assert!(mapping.get_placeholder(".env", "SECRET").is_some());
        assert!(mapping.get_placeholder(".env", "DEBUG").is_none());
    }

    #[test]
    fn redacted_content_preserves_comments_and_blanks() {
        let raw = "# comment\n\nSECRET=real\nDEBUG=true\n";
        let file_set = make_file_set(&[
            (".env", &[("SECRET", "real"), ("DEBUG", "true")]),
        ]);
        let mut ignorelist = HashSet::new();
        ignorelist.insert("DEBUG".to_string());

        let mapping = MultiFileMapping::build(&file_set, &ignorelist, Some(vec![0u8; 32]));
        let redacted = mapping.redacted_content(".env", raw);

        assert!(redacted.contains("# comment"), "comment preserved");
        assert!(redacted.contains("\n\n"), "blank line preserved");
    }

    #[test]
    fn redacted_content_ignored_var_passes_through() {
        let raw = "SECRET=real\nDEBUG=true\n";
        let file_set = make_file_set(&[
            (".env", &[("SECRET", "real"), ("DEBUG", "true")]),
        ]);
        let mut ignorelist = HashSet::new();
        ignorelist.insert("DEBUG".to_string());

        let mapping = MultiFileMapping::build(&file_set, &ignorelist, Some(vec![0u8; 32]));
        let redacted = mapping.redacted_content(".env", raw);

        assert!(redacted.contains("DEBUG=true"), "ignored var passed through");
        assert!(!redacted.contains("SECRET=real"), "secret not leaked");
        assert!(redacted.contains("unsee:"), "secret replaced with placeholder");
    }

    #[test]
    fn to_tsv_roundtrip() {
        let file_set = make_file_set(&[
            (".env", &[("KEY1", "val1"), ("KEY2", "val2")]),
        ]);
        let mapping = MultiFileMapping::build(&file_set, &HashSet::new(), Some(vec![0u8; 32]));
        let tsv = mapping.to_tsv();

        // Parse TSV back
        for line in tsv.lines() {
            let parts: Vec<&str> = line.splitn(2, '\t').collect();
            assert_eq!(parts.len(), 2);
            let placeholder = parts[0];
            let real = parts[1];
            assert!(placeholder.starts_with("unsee:"));
            assert_eq!(mapping.resolve(placeholder).unwrap(), real);
        }
    }

    #[test]
    fn redacted_secrets_pairs() {
        let file_set = make_file_set(&[
            (".env", &[("SECRET", "real-value")]),
        ]);
        let mapping = MultiFileMapping::build(&file_set, &HashSet::new(), Some(vec![0u8; 32]));
        let pairs = mapping.redacted_secrets();
        assert_eq!(pairs.len(), 1);
        let (real, placeholder) = &pairs[0];
        assert_eq!(real, "real-value");
        assert!(placeholder.starts_with("unsee:"));
    }

    #[test]
    fn reverse_map_matches_forward() {
        let file_set = make_file_set(&[
            (".env", &[("A", "val-a"), ("B", "val-b")]),
        ]);
        let mapping = MultiFileMapping::build(&file_set, &HashSet::new(), Some(vec![0u8; 32]));
        let rev = mapping.reverse_map();

        for (placeholder, real) in &rev {
            assert_eq!(mapping.resolve(placeholder).unwrap(), real);
        }
    }

    #[test]
    fn empty_env_empty_mapping() {
        let file_set = EnvFileSet {
            files: HashMap::new(),
            raw_contents: HashMap::new(),
        };
        let mapping = MultiFileMapping::build(&file_set, &HashSet::new(), Some(vec![0u8; 32]));
        assert_eq!(mapping.secrets_count(), 0);
        assert!(mapping.to_tsv().is_empty());
        assert!(mapping.redacted_secrets().is_empty());
    }
}
