//! Streaming output masking for `vp run`.
//!
//! Replaces every injected value, and its common encodings, with `<vp:NAME>` as
//! the child writes. A chunk boundary can split a value, so the masker holds
//! back the longest tail that could still grow into a match, and releases it
//! once it cannot.

use aho_corasick::{AhoCorasick, MatchKind};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

/// Values shorter than this are not masked: masking `1` or `true` everywhere
/// would wreck the output without protecting anything.
pub const MIN_MASKED_LEN: usize = 6;

pub struct Masker {
    automaton: AhoCorasick,
    patterns: Vec<Zeroizing<Vec<u8>>>,
    replacements: Vec<Vec<u8>>,
    pending: Zeroizing<Vec<u8>>,
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn json_escape(value: &str) -> String {
    let quoted = serde_json::to_string(value).unwrap_or_default();
    quoted[1..quoted.len().saturating_sub(1).max(1)].to_string()
}

impl Masker {
    /// `secrets` pairs a label (the variable name) with its value.
    pub fn new<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<Self> {
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut replacements = Vec::new();
        for (label, value) in secrets {
            let value = value.strip_suffix('\n').unwrap_or(value);
            if value.len() < MIN_MASKED_LEN {
                continue;
            }
            let forms = [
                value.to_string(),
                STANDARD.encode(value),
                URL_SAFE_NO_PAD.encode(value),
                percent_encode(value),
                json_escape(value),
            ];
            for form in forms {
                let form = Zeroizing::new(form.into_bytes());
                if !patterns.iter().any(|p| **p == *form) {
                    patterns.push(form);
                    replacements.push(format!("<vp:{label}>").into_bytes());
                }
            }
        }
        if patterns.is_empty() {
            return None;
        }
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(patterns.iter().map(|p| p.as_slice()))
            .ok()?;
        Some(Self {
            automaton,
            patterns,
            replacements,
            pending: Zeroizing::new(Vec::new()),
        })
    }

    // Longest suffix of `pending` that is a proper prefix of some pattern.
    fn held(&self) -> usize {
        let longest = self.patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        let limit = longest.saturating_sub(1).min(self.pending.len());
        (1..=limit)
            .rev()
            .find(|&k| {
                let tail = &self.pending[self.pending.len() - k..];
                self.patterns
                    .iter()
                    .any(|p| p.len() > k && p.starts_with(tail))
            })
            .unwrap_or(0)
    }

    fn drain(&mut self, everything: bool) -> Vec<u8> {
        let cut = if everything {
            self.pending.len()
        } else {
            self.pending.len() - self.held()
        };
        let mut out = Vec::with_capacity(self.pending.len());
        let mut position = 0;
        for m in self.automaton.find_iter(self.pending.as_slice()) {
            if m.start() >= cut {
                break;
            }
            out.extend_from_slice(&self.pending[position..m.start()]);
            out.extend_from_slice(&self.replacements[m.pattern().as_usize()]);
            position = m.end();
        }
        let end = cut.max(position);
        if position < end {
            out.extend_from_slice(&self.pending[position..end]);
        }
        let rest = Zeroizing::new(self.pending[end..].to_vec());
        self.pending = rest;
        out
    }

    /// Feeds child output; returns what is safe to show now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        self.drain(false)
    }

    /// The child is done; release everything held back.
    pub fn finish(&mut self) -> Vec<u8> {
        self.drain(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-sentinel-secret-123";

    fn run(masker: &mut Masker, chunks: &[&[u8]]) -> String {
        let mut out = Vec::new();
        for c in chunks {
            out.extend(masker.push(c));
        }
        out.extend(masker.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn masks_whole_and_split_values() {
        let mut m = Masker::new([("OPENAI_API_KEY", SECRET)]).unwrap();
        let text = format!("key={SECRET} done");
        for split in 0..text.len() {
            let (a, b) = text.as_bytes().split_at(split);
            let mut m2 = Masker::new([("OPENAI_API_KEY", SECRET)]).unwrap();
            assert_eq!(
                run(&mut m2, &[a, b]),
                "key=<vp:OPENAI_API_KEY> done",
                "split at {split}"
            );
        }
        let bytes: Vec<&[u8]> = text.as_bytes().chunks(1).collect();
        assert_eq!(run(&mut m, &bytes), "key=<vp:OPENAI_API_KEY> done");
    }

    #[test]
    fn masks_encodings() {
        let mut m = Masker::new([("K", SECRET)]).unwrap();
        let b64 = STANDARD.encode(SECRET);
        assert_eq!(
            run(&mut m, &[format!("auth: {b64}\n").as_bytes()]),
            "auth: <vp:K>\n"
        );
        let mut m = Masker::new([("K", "p@ss word!")]).unwrap();
        assert_eq!(run(&mut m, &[b"u=p%40ss%20word%21&x"]), "u=<vp:K>&x");
    }

    #[test]
    fn releases_partial_prefix_that_never_completes() {
        let mut m = Masker::new([("K", SECRET)]).unwrap();
        let first = m.push(b"hello sk-sent");
        assert_eq!(first, b"hello ");
        let second = m.push(b"ence\n");
        assert_eq!(second, b"sk-sentence\n");
    }

    #[test]
    fn ignores_short_values() {
        assert!(Masker::new([("K", "true")]).is_none());
    }

    #[test]
    fn prefers_longest_overlapping_value() {
        let mut m = Masker::new([("A", "abcdef"), ("B", "abcdefgh")]).unwrap();
        assert_eq!(
            run(&mut m, &[b"x abcdefgh y abcdef z"]),
            "x <vp:B> y <vp:A> z"
        );
        let mut m = Masker::new([("A", "abcdef"), ("B", "abcdefgh")]).unwrap();
        assert_eq!(run(&mut m, &[b"x abcdef", b"gh"]), "x <vp:B>");
    }
}
