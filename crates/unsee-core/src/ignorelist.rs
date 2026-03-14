use std::collections::HashSet;
use std::path::Path;

/// Parse a `.unsee.ignore` file into a set of variable names to ignore (pass through unredacted).
///
/// Format: one variable name per line. Comments (#) and empty lines are ignored.
pub fn parse_ignorelist(path: &Path) -> Result<HashSet<String>, crate::parser::UnseeError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        crate::parser::UnseeError::Io {
            path: path.to_path_buf(),
            source: e,
        }
    })?;
    Ok(parse_ignorelist_content(&content))
}

/// Parse ignorelist content from a string.
pub fn parse_ignorelist_content(content: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        set.insert(trimmed.to_string());
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_comments_and_blanks() {
        let content = "# this is a comment\n\n# another comment\n";
        let set = parse_ignorelist_content(content);
        assert!(set.is_empty());
    }

    #[test]
    fn parse_trims_whitespace() {
        let content = "  SAFE_VAR  \n  ANOTHER  \n";
        let set = parse_ignorelist_content(content);
        assert!(set.contains("SAFE_VAR"));
        assert!(set.contains("ANOTHER"));
    }

    #[test]
    fn parse_returns_correct_set() {
        let content = "SAFE_VAR\n# comment\n\nANOTHER_VAR\nDEBUG\n";
        let set = parse_ignorelist_content(content);
        assert_eq!(set.len(), 3);
        assert!(set.contains("SAFE_VAR"));
        assert!(set.contains("ANOTHER_VAR"));
        assert!(set.contains("DEBUG"));
    }
}
