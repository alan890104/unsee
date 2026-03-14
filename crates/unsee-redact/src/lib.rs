use zeroize::Zeroize;

/// Streaming redactor: replaces real secret values with placeholders in a byte stream.
///
/// Handles chunk boundaries correctly by holding back bytes that could be
/// the start of a partial match.
pub struct StreamRedactor {
    /// (real_value_bytes, placeholder_bytes), sorted longest-first
    patterns: Vec<(Vec<u8>, Vec<u8>)>,
    /// Bytes held back from emission (might be partial match prefix)
    holdback: Vec<u8>,
    /// max(pattern.len()) - 1, or 0 if no patterns
    max_hold: usize,
}

impl Drop for StreamRedactor {
    fn drop(&mut self) {
        for (real, _) in &mut self.patterns {
            real.zeroize();
        }
        self.holdback.zeroize();
    }
}

impl StreamRedactor {
    /// Create a new redactor from (real_value, placeholder) pairs.
    pub fn new(secrets: &[(String, String)]) -> Self {
        let mut patterns: Vec<(Vec<u8>, Vec<u8>)> = secrets
            .iter()
            .filter(|(real, _)| !real.is_empty())
            .map(|(real, placeholder)| (real.as_bytes().to_vec(), placeholder.as_bytes().to_vec()))
            .collect();
        // Sort longest first so longer secrets match before shorter substrings
        patterns.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        let max_pattern_len = patterns.iter().map(|(p, _)| p.len()).max().unwrap_or(0);
        let max_hold = max_pattern_len.saturating_sub(1);

        StreamRedactor {
            patterns,
            holdback: Vec::new(),
            max_hold,
        }
    }

    /// Feed a chunk of bytes. Returns bytes safe to emit.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.patterns.is_empty() {
            return chunk.to_vec();
        }

        self.holdback.extend_from_slice(chunk);
        self.replace_all_matches();

        // Only hold back bytes that are an actual prefix of some pattern.
        let keep = self.find_tail_prefix_len();
        if self.holdback.len() > keep {
            let split_at = self.holdback.len() - keep;
            let emit = self.holdback[..split_at].to_vec();
            self.holdback = self.holdback[split_at..].to_vec();
            emit
        } else {
            Vec::new()
        }
    }

    /// Flush remaining holdback bytes (call at EOF).
    pub fn finish(&mut self) -> Vec<u8> {
        if self.patterns.is_empty() {
            return Vec::new();
        }
        self.replace_all_matches();
        std::mem::take(&mut self.holdback)
    }

    /// Scan holdback for all pattern matches and replace them.
    fn replace_all_matches(&mut self) {
        for (pattern, replacement) in &self.patterns {
            let mut i = 0;
            while i + pattern.len() <= self.holdback.len() {
                if &self.holdback[i..i + pattern.len()] == pattern.as_slice() {
                    let mut new = Vec::with_capacity(
                        self.holdback.len() - pattern.len() + replacement.len(),
                    );
                    new.extend_from_slice(&self.holdback[..i]);
                    new.extend_from_slice(replacement);
                    new.extend_from_slice(&self.holdback[i + pattern.len()..]);
                    self.holdback = new;
                    i += replacement.len();
                } else {
                    i += 1;
                }
            }
        }
    }

    /// Find the longest suffix of holdback that is a prefix of any pattern.
    fn find_tail_prefix_len(&self) -> usize {
        let hb = &self.holdback;
        if hb.is_empty() {
            return 0;
        }
        let max_check = self.max_hold.min(hb.len());
        for tail_len in (1..=max_check).rev() {
            let tail = &hb[hb.len() - tail_len..];
            for (pattern, _) in &self.patterns {
                if pattern.len() >= tail_len && pattern[..tail_len] == *tail {
                    return tail_len;
                }
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_replace() {
        let mut r = StreamRedactor::new(&[
            ("real-secret-123".into(), "unsee:aaaa1111".into()),
        ]);
        let out = r.feed(b"the key is real-secret-123 ok");
        let rest = r.finish();
        let full: Vec<u8> = [out, rest].concat();
        let s = String::from_utf8(full).unwrap();
        assert!(s.contains("unsee:aaaa1111"), "got: {}", s);
        assert!(!s.contains("real-secret-123"), "leaked: {}", s);
    }

    #[test]
    fn split_across_chunks() {
        let mut r = StreamRedactor::new(&[
            ("real-secret-123".into(), "unsee:aaaa1111".into()),
        ]);
        let o1 = r.feed(b"key=real-sec");
        let o2 = r.feed(b"ret-123 done");
        let o3 = r.finish();
        let full: Vec<u8> = [o1, o2, o3].concat();
        let s = String::from_utf8(full).unwrap();
        assert!(s.contains("unsee:aaaa1111"), "not replaced: {}", s);
        assert!(!s.contains("real-secret-123"), "leaked: {}", s);
    }

    #[test]
    fn no_match_passthrough() {
        let mut r = StreamRedactor::new(&[
            ("secret".into(), "unsee:xxxx".into()),
        ]);
        let o1 = r.feed(b"hello world");
        let o2 = r.finish();
        let full: Vec<u8> = [o1, o2].concat();
        assert_eq!(full, b"hello world");
    }

    #[test]
    fn multiple_secrets_one_chunk() {
        let mut r = StreamRedactor::new(&[
            ("aaa".into(), "unsee:1111".into()),
            ("bbb".into(), "unsee:2222".into()),
        ]);
        let o1 = r.feed(b"got aaa and bbb here");
        let o2 = r.finish();
        let s = String::from_utf8([o1, o2].concat()).unwrap();
        assert!(s.contains("unsee:1111"), "aaa not replaced");
        assert!(s.contains("unsee:2222"), "bbb not replaced");
        assert!(!s.contains("aaa"), "aaa leaked");
        assert!(!s.contains("bbb"), "bbb leaked");
    }

    #[test]
    fn longer_secret_first() {
        let mut r = StreamRedactor::new(&[
            ("abc".into(), "unsee:short".into()),
            ("abcdef".into(), "unsee:long".into()),
        ]);
        let o1 = r.feed(b"got abcdef here");
        let o2 = r.finish();
        let s = String::from_utf8([o1, o2].concat()).unwrap();
        assert!(s.contains("unsee:long"), "long not matched: {}", s);
        assert!(!s.contains("abcdef"), "leaked");
    }

    #[test]
    fn empty_patterns_passthrough() {
        let mut r = StreamRedactor::new(&[]);
        let o1 = r.feed(b"anything goes");
        let o2 = r.finish();
        assert_eq!([o1, o2].concat(), b"anything goes");
    }

    #[test]
    fn finish_flushes_holdback() {
        let mut r = StreamRedactor::new(&[
            ("longpattern".into(), "unsee:xxxx".into()),
        ]);
        let o1 = r.feed(b"long");
        assert!(o1.is_empty());
        let o2 = r.finish();
        assert_eq!(o2, b"long");
    }

    #[test]
    fn overlapping_prefix_not_replaced() {
        let mut r = StreamRedactor::new(&[
            ("abcdef".into(), "unsee:xxxx".into()),
        ]);
        let o1 = r.feed(b"abcXYZ");
        let o2 = r.finish();
        let s = String::from_utf8([o1, o2].concat()).unwrap();
        assert_eq!(s, "abcXYZ");
    }

    #[test]
    fn secret_at_chunk_end() {
        let mut r = StreamRedactor::new(&[
            ("secret".into(), "unsee:xxxx".into()),
        ]);
        let o1 = r.feed(b"my secret");
        let o2 = r.finish();
        let s = String::from_utf8([o1, o2].concat()).unwrap();
        assert!(s.contains("unsee:xxxx"));
        assert!(!s.contains("secret"));
    }
}
