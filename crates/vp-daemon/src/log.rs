//! The access log: append-only JSON lines, each hashed together with the one
//! before it, so an edit or deletion breaks the chain. Never holds a value.
//! (Entries are signed once the native store has an account key, in M0.5.)

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub at: String,
    pub agent: String,
    pub pid: u32,
    pub project: String,
    pub request: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<vp_core::ipc::Operation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    pub outcome: String,
}

pub struct AccessLog {
    file: PathBuf,
    previous: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl AccessLog {
    pub fn open(file: PathBuf) -> Self {
        let previous = std::fs::read_to_string(&file)
            .ok()
            .and_then(|text| text.lines().last().map(str::to_string))
            .and_then(|line| serde_json::from_str::<serde_json::Value>(&line).ok())
            .and_then(|v| v.get("hash").and_then(|h| h.as_str()).map(String::from))
            .unwrap_or_else(|| "0".repeat(64));
        Self { file, previous }
    }

    pub fn append(&mut self, entry: &Entry) -> std::io::Result<()> {
        let mut value = serde_json::to_value(entry)?;
        value["prev"] = self.previous.clone().into();
        let body = serde_json::to_string(&value)?;
        let hash = hex(&Sha256::digest(body.as_bytes()));
        value["hash"] = hash.clone().into();
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&self.file)?;
        writeln!(file, "{}", serde_json::to_string(&value)?)?;
        self.previous = hash;
        Ok(())
    }

    /// The last `limit` entries, plus whether the whole chain verifies.
    pub fn tail(&self, limit: usize) -> serde_json::Value {
        let text = std::fs::read_to_string(&self.file).unwrap_or_default();
        let mut previous = "0".repeat(64);
        let mut intact = true;
        let mut entries = Vec::new();
        for line in text.lines() {
            let Ok(mut value) = serde_json::from_str::<serde_json::Value>(line) else {
                intact = false;
                continue;
            };
            let hash = value
                .as_object_mut()
                .and_then(|o| o.remove("hash"))
                .and_then(|h| h.as_str().map(String::from));
            let body = serde_json::to_string(&value).unwrap_or_default();
            let ok = value.get("prev").and_then(|p| p.as_str()) == Some(previous.as_str())
                && hash.as_deref() == Some(hex(&Sha256::digest(body.as_bytes())).as_str());
            intact &= ok;
            previous = hash.unwrap_or_default();
            if let Some(o) = value.as_object_mut() {
                o.remove("prev");
            }
            entries.push(value);
        }
        let skip = entries.len().saturating_sub(limit);
        serde_json::json!({ "intact": intact, "entries": entries.split_off(skip) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(outcome: &str) -> Entry {
        Entry {
            at: "2026-10-12T00:00:00Z".into(),
            agent: "Claude Code".into(),
            pid: 1,
            project: "/p".into(),
            request: "resolve".into(),
            operation: None,
            refs: vec!["op://a/b/c".into()],
            detail: None,
            grant: None,
            outcome: outcome.into(),
        }
    }

    #[test]
    fn chains_and_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("access.log");
        let mut log = AccessLog::open(file.clone());
        log.append(&entry("allowed")).unwrap();
        log.append(&entry("denied")).unwrap();
        let mut reopened = AccessLog::open(file.clone());
        reopened.append(&entry("allowed")).unwrap();
        let tail = reopened.tail(2);
        assert_eq!(tail["intact"], true);
        assert_eq!(tail["entries"].as_array().unwrap().len(), 2);

        let text = std::fs::read_to_string(&file)
            .unwrap()
            .replacen("denied", "allowed", 1);
        std::fs::write(&file, text).unwrap();
        assert_eq!(AccessLog::open(file).tail(10)["intact"], false);
    }
}
