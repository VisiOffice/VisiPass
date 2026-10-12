//! Agent tokens: pre-approved, scoped access for agents with no human at the
//! keyboard. Creating one always needs a human approval. A token is checked,
//! never prompted for: outside its scope the request is refused.
//!
//! Only a SHA-256 hash of each token is stored.

use crate::grants::Need;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use vp_core::ipc::Operation;
use vp_core::time::{now_unix, rfc3339};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id: String,
    pub name: String,
    hash: String,
    pub vaults: BTreeSet<String>,
    pub operations: BTreeSet<Operation>,
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_hex(len: usize) -> Option<String> {
    let mut bytes = vec![0u8; len];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
        .ok()?;
    Some(hex(&bytes))
}

/// The vault segment of `op://Vault/Item/field`.
fn vault_of(reference: &str) -> &str {
    reference
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(reference)
        .split('/')
        .next()
        .unwrap_or("")
}

impl TokenRecord {
    fn live(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|t| now < t)
    }

    /// Whether this token allows the request without asking anyone.
    pub fn covers(&self, need: &Need) -> bool {
        self.operations.contains(&need.operation)
            && need.vaults.is_subset(&self.vaults)
            && need.refs.iter().all(|r| self.vaults.contains(vault_of(r)))
    }

    pub fn view(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name,
            "vaults": self.vaults,
            "operations": self.operations,
            "createdAt": rfc3339(self.created_at),
            "expires": self.expires_at.map(rfc3339).unwrap_or_else(|| "never".into()),
        })
    }
}

pub struct Tokens {
    file: PathBuf,
    records: Vec<TokenRecord>,
}

impl Tokens {
    pub fn load(file: PathBuf) -> Self {
        let records = std::fs::read_to_string(&file)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self { file, records }
    }

    fn save(&self) -> std::io::Result<()> {
        crate::write_private(
            &self.file,
            serde_json::to_string_pretty(&self.records)?.as_bytes(),
        )
    }

    /// Creates a token and returns its record and the only copy of its secret.
    pub fn create(
        &mut self,
        name: &str,
        vaults: BTreeSet<String>,
        operations: BTreeSet<Operation>,
        days: Option<u64>,
    ) -> std::io::Result<(TokenRecord, String)> {
        let unavailable = || std::io::Error::other("no randomness");
        let id = format!("t_{}", random_hex(6).ok_or_else(unavailable)?);
        let secret = format!(
            "vpt_{}_{}",
            &id[2..],
            random_hex(32).ok_or_else(unavailable)?
        );
        let now = now_unix();
        let record = TokenRecord {
            id,
            name: name.to_string(),
            hash: hex(&Sha256::digest(secret.as_bytes())),
            vaults,
            operations,
            created_at: now,
            expires_at: days.map(|d| now + d * 86_400),
        };
        self.records.push(record.clone());
        self.save()?;
        Ok((record, secret))
    }

    pub fn verify(&self, token: &str) -> Option<TokenRecord> {
        let presented = hex(&Sha256::digest(token.as_bytes()));
        let now = now_unix();
        // Compare every hash in full, so timing says nothing about near misses.
        let mut found = None;
        for record in &self.records {
            let same = record.hash.len() == presented.len()
                && record
                    .hash
                    .bytes()
                    .zip(presented.bytes())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0;
            if same && record.live(now) {
                found = Some(record.clone());
            }
        }
        found
    }

    pub fn list(&self) -> Vec<serde_json::Value> {
        let now = now_unix();
        self.records
            .iter()
            .filter(|r| r.live(now))
            .map(TokenRecord::view)
            .collect()
    }

    pub fn revoke(&mut self, id: &str) -> std::io::Result<bool> {
        let before = self.records.len();
        self.records.retain(|r| r.id != id);
        let removed = self.records.len() != before;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn need(op: Operation, refs: &[&str], vaults: &[&str]) -> Need {
        Need {
            operation: op,
            refs: refs.iter().map(|r| r.to_string()).collect(),
            vaults: vaults.iter().map(|v| v.to_string()).collect(),
        }
    }

    #[test]
    fn tokens_verify_scope_and_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let mut tokens = Tokens::load(dir.path().join("tokens.json"));
        let (record, secret) = tokens
            .create(
                "nightly",
                BTreeSet::from(["Automation".to_string()]),
                BTreeSet::from([Operation::Run]),
                Some(30),
            )
            .unwrap();
        assert!(secret.starts_with("vpt_"));
        assert!(
            !std::fs::read_to_string(dir.path().join("tokens.json"))
                .unwrap()
                .contains(&secret),
            "only the hash is stored"
        );
        let found = tokens.verify(&secret).unwrap();
        assert!(found.covers(&need(
            Operation::Run,
            &["op://Automation/Deploy Key/credential"],
            &[]
        )));
        assert!(
            !found.covers(&need(Operation::Run, &["op://Private/Bank/password"], &[])),
            "other vault"
        );
        assert!(
            !found.covers(&need(
                Operation::Reveal,
                &["op://Automation/Deploy Key/credential"],
                &[]
            )),
            "other operation"
        );
        assert!(tokens.verify("vpt_wrong").is_none());
        assert!(tokens.revoke(&record.id).unwrap());
        assert!(tokens.verify(&secret).is_none());
    }
}
