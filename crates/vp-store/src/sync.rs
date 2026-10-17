//! §11.1 in the store: the files one device writes for the others (change
//! files, snapshots and account records), and applying another device's.
//!
//! Every file is sealed under `sync_key` and signed by the keyset; inside, the
//! rows are the ciphertexts the store already keeps. Where they go (a folder,
//! a bucket) is `vp-sync`'s business, not the store's.

use super::*;

/// A change file or snapshot, named by its device and seq.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub device: [u8; 16],
    pub seq: u64,
    pub bytes: Vec<u8>,
}

/// What applying another device's change file did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// Applied; this many revisions were new here.
    Changes(usize),
    /// Already applied.
    Already,
    /// An earlier file from that device has not been applied yet.
    Gap,
    /// That device's log forked (two different files claim one place in it):
    /// sync with it stops until the human looks.
    Forked,
}

/// Another device's log as this device has followed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLog {
    pub device: [u8; 16],
    /// The last of its change files applied here.
    pub seq: u64,
    pub forked: bool,
}

/// This device's place in sync, for status and for `vp-sync`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    pub account_id: [u8; 16],
    pub ak_generation: u64,
    pub device: [u8; 16],
    /// Every ID this device has written under, current last.
    pub mine: Vec<[u8; 16]>,
    /// Its own last change file.
    pub seq: u64,
    /// Its own seq at its last snapshot.
    pub snapshot: Option<u64>,
    pub devices: Vec<DeviceLog>,
}

impl Unlocked {
    pub fn position(&self) -> Position {
        Position {
            account_id: self.account_id,
            ak_generation: self.ak_generation,
            device: self.local.device(),
            mine: self.local.mine.clone(),
            seq: self.local.seq,
            snapshot: self.local.snapshot,
            devices: self
                .local
                .peers
                .iter()
                .map(|(id, p)| DeviceLog {
                    device: *id,
                    seq: p.seq,
                    forked: p.forked,
                })
                .collect(),
        }
    }

    /// Items with more than one current revision: (vault ID, item ID, heads).
    pub fn conflicts(&self) -> Vec<(String, String, Vec<Rev>)> {
        let mut out = Vec::new();
        for (vault_id, v) in &self.vaults {
            let mut heads: BTreeMap<&str, Vec<Rev>> = BTreeMap::new();
            for ((item_id, rev), s) in &v.revisions {
                if s.head {
                    heads.entry(item_id).or_default().push(*rev);
                }
            }
            out.extend(
                heads
                    .into_iter()
                    .filter(|(_, revs)| revs.len() > 1)
                    .map(|(item_id, revs)| (vault_id.clone(), item_id.to_string(), revs)),
            );
        }
        out
    }

    fn sync_key(&self) -> Key {
        self.derived("VisiPass sync")
    }
}

/// Account records [`Store::join`] tries, newest first.
const MAX_RECORDS: usize = 16;

/// `H(file)`, what `prev` and the device state record.
pub fn file_hash(bytes: &[u8]) -> [u8; 32] {
    hash("VisiPass sync file", &[Part::Bytes(bytes)])
}

fn clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct Kind {
    magic: &'static [u8; 3],
    label: &'static str,
    signature: &'static str,
}

const CHANGE: Kind = Kind {
    magic: b"VPC",
    label: "VisiPass sync change",
    signature: "VisiPass sync change signature",
};

const SNAPSHOT: Kind = Kind {
    magic: b"VPS",
    label: "VisiPass sync snapshot",
    signature: "VisiPass sync snapshot signature",
};

fn file_ad(kind: &Kind, u: &Unlocked, device: &[u8; 16], seq: u64, generation: u64) -> Vec<u8> {
    ad(
        kind.label,
        &[
            Part::Bytes(&u.account_id),
            Part::Bytes(device),
            Part::Uint(seq),
            Part::Uint(generation),
        ],
    )
}

/// `magic ‖ format ‖ ak_generation ‖ nonce ‖ AEAD(sync_key, pad(plaintext)) ‖ signature`.
fn seal_file(kind: &Kind, u: &Unlocked, device: &[u8; 16], seq: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut out = kind.magic.to_vec();
    out.push(vp_crypto::FORMAT as u8);
    out.extend((u.ak_generation as u32).to_be_bytes());
    out.extend(vp_crypto::seal(
        &u.sync_key(),
        &file_ad(kind, u, device, seq, u.ak_generation),
        &vp_crypto::pad(plaintext),
    ));
    let signature = u.signing.sign(&ad(
        kind.signature,
        &[Part::Bytes(&hash(kind.signature, &[Part::Bytes(&out)]))],
    ));
    out.extend(signature);
    out
}

fn open_file(
    kind: &Kind,
    u: &Unlocked,
    device: &[u8; 16],
    seq: u64,
    bytes: &[u8],
) -> Result<Vec<Value>> {
    let refused = |what: &str| Error(format!("A sync file was refused ({what})"));
    if bytes.len() < 8 + 64 || &bytes[..3] != kind.magic {
        return Err(refused("not a VisiPass sync file"));
    }
    if bytes[3] as u64 != vp_crypto::FORMAT {
        return Err(Error(
            "Another device writes a newer sync format; update VisiPass here".into(),
        ));
    }
    let generation = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as u64;
    if generation != u.ak_generation {
        return Err(refused("written under other account keys"));
    }
    let (body, signature) = bytes.split_at(bytes.len() - 64);
    let signed = ad(
        kind.signature,
        &[Part::Bytes(&hash(kind.signature, &[Part::Bytes(body)]))],
    );
    if !vp_crypto::verify(&u.signing.public(), &signed, signature) {
        return Err(refused("bad signature"));
    }
    let padded = vp_crypto::open(
        &u.sync_key(),
        &file_ad(kind, u, device, seq, generation),
        &body[8..],
    )
    .map_err(|_| refused("does not decrypt"))?;
    let plaintext = vp_crypto::unpad(&padded)?;
    let parts = vp_crypto::decode(kind.label, plaintext).map_err(|_| refused("malformed"))?;
    match parts.as_slice() {
        [account, d, s, ..]
            if account.bytes()? == u.account_id && d.bytes()? == device && s.uint()? == seq =>
        {
            Ok(parts)
        }
        _ => Err(refused("named for another place")),
    }
}

type VaultEntry = (String, u64, Vec<u8>, Vec<u8>);

/// `[vault_id, vk_generation, wrapped_VK, attrs]`, as stored.
fn vault_rows(store: &Store, ids: &[&str]) -> Result<Vec<VaultEntry>> {
    let mut out = Vec::new();
    for id in ids {
        out.push(store.conn.query_row(
            "SELECT vault_id, vk_generation, wrapped_vk, attrs FROM vault WHERE vault_id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?);
    }
    Ok(out)
}

fn vault_parts(rows: &[VaultEntry]) -> Part<'_> {
    Part::List(
        rows.iter()
            .map(|(id, generation, wrapped, attrs)| {
                Part::List(vec![
                    Part::Text(id),
                    Part::Uint(*generation),
                    Part::Bytes(wrapped),
                    Part::Bytes(attrs),
                ])
            })
            .collect(),
    )
}

/// Rows read for a file, each checked against the in-memory manifest first,
/// so a row changed on disk is never sent on.
fn checked_rows(store: &Store, u: &Unlocked, filter: &str) -> Result<Vec<RevisionRow>> {
    let rows = store.revision_rows(filter)?;
    for (vault_id, item_id, rev, _, _, overview, details) in &rows {
        let state = u.vault(vault_id)?;
        match state.revisions.get(&(item_id.clone(), *rev)) {
            Some(s) if s.details == h(details) && s.overview == overview.as_deref().map(h) => {}
            _ => return Err(tampered("a revision being sent")),
        }
        if overview.is_none() {
            return Err(tampered("a revision being sent"));
        }
    }
    Ok(rows)
}

fn parents_of(rows: &[RevisionRow]) -> Result<Vec<Vec<Rev>>> {
    rows.iter().map(|row| decode_revs(&row.3)).collect()
}

fn revision_parts<'a>(rows: &'a [RevisionRow], parents: &'a [Vec<Rev>]) -> Part<'a> {
    Part::List(
        rows.iter()
            .zip(parents)
            .map(
                |((vault_id, item_id, rev, _, _, overview, details), parents)| {
                    Part::List(vec![
                        Part::Text(vault_id),
                        Part::Text(item_id),
                        rev.part(),
                        revs_part(parents),
                        Part::Bytes(overview.as_deref().unwrap_or_default()),
                        Part::Bytes(details),
                    ])
                },
            )
            .collect(),
    )
}

/// The other devices' logs as a file's `seen`: `[device, seq, hash]`.
fn seen_part(local: &Local) -> Part<'_> {
    Part::List(
        local
            .peers
            .iter()
            .map(|(id, p)| {
                Part::List(vec![
                    Part::Bytes(id),
                    Part::Uint(p.seq),
                    Part::Bytes(&p.hash),
                ])
            })
            .collect(),
    )
}

/// The previous file of a log as `prev`: nothing before the first.
fn prev_of(seq: u64, head: &[u8; 32]) -> &[u8] {
    if seq == 0 { &[] } else { head }
}

impl Store {
    /// Seals every own revision and vault not yet in a change file into the
    /// next one, and keeps it in the outbox until [`Store::confirm`]: recorded in
    /// the same transaction as the device's new position, so a crash can
    /// neither lose it nor give its number to different contents. `None` when
    /// there is nothing to send.
    pub fn commit_change(&mut self, u: &mut Unlocked) -> Result<Option<Sealed>> {
        if u.local.snapshot.is_none() {
            return Err(Error("Sync is not set up on this device".into()));
        }
        let filter = format!(
            "rev_n > {} AND rev_device = x'{}'",
            u.local.exported,
            hex(&u.local.device())
        );
        let rows = checked_rows(self, u, &filter)?;
        let mut vault_ids: Vec<&str> = u
            .vaults
            .iter()
            .filter(|(_, v)| v.origin > u.local.exported)
            .map(|(id, _)| id.as_str())
            .collect();
        for (vault_id, ..) in &rows {
            if !vault_ids.contains(&vault_id.as_str()) {
                vault_ids.push(vault_id);
            }
        }
        if rows.is_empty() && vault_ids.is_empty() {
            return Ok(None);
        }
        vault_ids.sort();
        let vaults = vault_rows(self, &vault_ids)?;
        let parents = parents_of(&rows)?;
        let device = u.local.device();
        let seq = u.local.seq + 1;
        let plaintext = ad(
            CHANGE.label,
            &[
                Part::Bytes(&u.account_id),
                Part::Bytes(&device),
                Part::Uint(seq),
                Part::Bytes(prev_of(u.local.seq, &u.local.head)),
                Part::Uint(clock()),
                seen_part(&u.local),
                Part::List(vec![Part::Bytes(&device)]),
                vault_parts(&vaults),
                revision_parts(&rows, &parents),
            ],
        );
        let bytes = seal_file(&CHANGE, u, &device, seq, &plaintext);
        let checkpoint = u.checkpoint();
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO outbox VALUES (?1, ?2, ?3, ?4)",
            params![
                seq,
                u.local.exported,
                prev_of(u.local.seq, &u.local.head),
                &bytes
            ],
        )?;
        u.local.seq = seq;
        u.local.head = file_hash(&bytes);
        u.local.exported = u.local.next_rev - 1;
        if let Err(e) = commit(&self.sequence_file, u, &[], tx) {
            u.restore(checkpoint);
            return Err(e);
        }
        Ok(Some(Sealed { device, seq, bytes }))
    }

    /// Change files written here but not yet seen in the storage.
    pub fn outbox(&self, u: &Unlocked) -> Result<Vec<Sealed>> {
        let mut statement = self
            .conn
            .prepare("SELECT seq, body FROM outbox ORDER BY seq")?;
        let rows = statement
            .query_map([], |r| {
                Ok(Sealed {
                    device: u.local.device(),
                    seq: r.get(0)?,
                    bytes: r.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }

    /// The storage holds this change file now.
    pub fn confirm(&mut self, seq: u64) -> Result<()> {
        self.conn
            .execute("DELETE FROM outbox WHERE seq = ?1", [seq])?;
        Ok(())
    }

    /// Everything current, as of this device's last change file, for a device
    /// that joins (§11.1). The first one also marks every revision so far as
    /// sent, so change files carry only what comes after.
    pub fn snapshot(&mut self, u: &mut Unlocked) -> Result<Sealed> {
        // Anything not yet sent goes into a change file first, so a device that
        // follows the log misses nothing the snapshot holds.
        if u.local.snapshot.is_some() {
            self.commit_change(u)?;
        }
        let rows = checked_rows(self, u, "head = 1")?;
        let ids = u.vault_ids();
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        let vaults = vault_rows(self, &ids)?;
        let parents = parents_of(&rows)?;
        let device = u.local.device();
        let seq = u.local.seq;
        let plaintext = ad(
            SNAPSHOT.label,
            &[
                Part::Bytes(&u.account_id),
                Part::Bytes(&device),
                Part::Uint(seq),
                Part::Bytes(prev_of(seq, &u.local.head)),
                Part::Uint(clock()),
                seen_part(&u.local),
                vault_parts(&vaults),
                revision_parts(&rows, &parents),
            ],
        );
        let bytes = seal_file(&SNAPSHOT, u, &device, seq, &plaintext);
        let checkpoint = u.checkpoint();
        let tx = self.conn.transaction()?;
        if u.local.snapshot.is_none() {
            u.local.exported = u.local.next_rev - 1;
        }
        u.local.snapshot = Some(seq);
        if let Err(e) = commit(&self.sequence_file, u, &[], tx) {
            u.restore(checkpoint);
            return Err(e);
        }
        Ok(Sealed { device, seq, bytes })
    }

    /// The account record a new device unlocks with (§11.1): clear but signed.
    pub fn account_record(&self, u: &Unlocked) -> Result<Vec<u8>> {
        let row = self.account_row()?;
        if account_row_hash(&row.wrapped_ak, &row.params, &row.salt, &row.keyset)
            != u.account_row_hash
            || row.account_id != u.account_id
        {
            return Err(tampered("account row"));
        }
        let record = ad(
            "VisiPass account record",
            &[
                Part::Bytes(&row.account_id),
                Part::Uint(row.ak_generation),
                Part::Bytes(&row.salt),
                row.params.part(),
                Part::Bytes(&row.wrapped_ak),
                Part::Bytes(&row.keyset),
                Part::Uint(clock()),
            ],
        );
        let signature = u.signing.sign(&ad(
            "VisiPass account record signature",
            &[Part::Bytes(&record)],
        ));
        let mut out = record;
        out.extend(signature);
        Ok(out)
    }

    /// Makes this device's vault from an account record, given the master
    /// password and Secret Key: a new file holding the account and no vaults,
    /// which a snapshot then fills. Records are tried newest first; one is
    /// accepted only if it unlocks and its signature verifies under the keyset
    /// it unlocks.
    pub fn join(
        path: &Path,
        sequence_file: &Path,
        records: &[Vec<u8>],
        password: &str,
        secret_key: &SecretKey,
    ) -> Result<(Store, Unlocked)> {
        let mut parsed = Vec::new();
        for bytes in records {
            if bytes.len() < 64 {
                continue;
            }
            let (record, signature) = bytes.split_at(bytes.len() - 64);
            let Ok(parts) = vp_crypto::decode("VisiPass account record", record) else {
                continue;
            };
            let [
                account_id,
                generation,
                salt,
                params,
                wrapped_ak,
                keyset,
                clock,
            ] = parts.as_slice()
            else {
                continue;
            };
            let read = || -> vp_crypto::Result<_> {
                let [m_kib, t, p] = params.list()? else {
                    return Err(vp_crypto::Error("bad parameters"));
                };
                let narrow = |v: &Value| -> vp_crypto::Result<u32> {
                    u32::try_from(v.uint()?).map_err(|_| vp_crypto::Error("bad parameters"))
                };
                Ok((
                    clock.uint()?,
                    AccountRow {
                        account_id: account_id.fixed()?,
                        format: SCHEMA_VERSION,
                        ak_generation: generation.uint()?,
                        salt: salt.fixed()?,
                        params: KdfParams {
                            m_kib: narrow(m_kib)?,
                            t: narrow(t)?,
                            p: narrow(p)?,
                        },
                        wrapped_ak: wrapped_ak.bytes()?.to_vec(),
                        keyset: keyset.bytes()?.to_vec(),
                        sequence: 1,
                        manifest: Vec::new(),
                        signature: Vec::new(),
                        device: Vec::new(),
                    },
                    record.to_vec(),
                    signature.to_vec(),
                ))
            };
            if let Ok(entry) = read() {
                parsed.push(entry);
            }
        }
        parsed.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        let mut out_of_bounds = false;
        // Each try costs a full password derivation, so a folder stuffed with
        // records cannot make joining take forever.
        for (_, row, record, signature) in parsed.into_iter().take(MAX_RECORDS) {
            if row.params.check().is_err() {
                out_of_bounds = true;
                continue;
            }
            let auk = vp_crypto::account_unlock_key(
                &vp_crypto::password_key(password, &row.salt, &row.params)?,
                secret_key,
                &row.account_id,
            );
            let Ok(ak) = vp_crypto::unwrap(
                &auk,
                &ak_ad(&row.account_id, row.ak_generation, &row.params, &row.salt),
                &row.wrapped_ak,
            ) else {
                continue;
            };
            let Ok(seed) = vp_crypto::open(
                &derive(&ak, "VisiPass keyset", &row.account_id, row.ak_generation),
                &keyset_ad(&row.account_id, row.ak_generation),
                &row.keyset,
            ) else {
                continue;
            };
            let signing = SigningKey::from_seed(&seed)?;
            let signed = ad("VisiPass account record signature", &[Part::Bytes(&record)]);
            if !vp_crypto::verify(&signing.public(), &signed, &signature) {
                continue;
            }
            return Store::create_with(path, sequence_file, row, ak, signing);
        }
        Err(Error(if out_of_bounds {
            "The account record asks for password parameters out of bounds; it was refused".into()
        } else {
            "Wrong master password or Secret Key".into()
        }))
    }

    /// Applies change file `seq` of another device after the §11.1 checks: it
    /// opens and verifies under this account's keys, follows the last applied
    /// file of that device by `prev`, and every row in it verifies as in §7.
    pub fn apply_change(
        &mut self,
        u: &mut Unlocked,
        device: [u8; 16],
        seq: u64,
        bytes: &[u8],
    ) -> Result<Applied> {
        if device == u.local.device() {
            return Err(Error("That is this device's own log".into()));
        }
        let peer = u.local.peers.get(&device).cloned().unwrap_or_default();
        if peer.forked {
            return Ok(Applied::Forked);
        }
        let digest = file_hash(bytes);
        if seq <= peer.seq {
            if seq == peer.seq && digest != peer.hash {
                self.mark_forked(u, device)?;
                return Ok(Applied::Forked);
            }
            return Ok(Applied::Already);
        }
        if seq > peer.seq + 1 {
            return Ok(Applied::Gap);
        }
        let parts = open_file(&CHANGE, u, &device, seq, bytes)?;
        let [_, _, _, prev, _clock, _seen, writers, vaults, revisions] = parts.as_slice() else {
            return Err(Error("A sync file was refused (malformed)".into()));
        };
        let writers: Vec<[u8; 16]> = writers
            .list()?
            .iter()
            .map(|w| w.fixed())
            .collect::<vp_crypto::Result<_>>()?;
        if writers.last() != Some(&device) {
            return Err(Error("A sync file was refused (malformed)".into()));
        }
        if prev.bytes()? != prev_of(peer.seq, &peer.hash) {
            self.mark_forked(u, device)?;
            return Ok(Applied::Forked);
        }
        let checkpoint = u.checkpoint();
        let tx = self.conn.transaction()?;
        let applied = apply_rows(&tx, u, vaults, revisions, Some(&writers));
        let result = applied.and_then(|(touched, count)| {
            u.local.peers.insert(
                device,
                Peer {
                    seq,
                    hash: digest,
                    forked: false,
                },
            );
            let touched: Vec<&str> = touched.iter().map(String::as_str).collect();
            commit(&self.sequence_file, u, &touched, tx).map(|_| count)
        });
        match result {
            Ok(count) => Ok(Applied::Changes(count)),
            Err(e) => {
                u.restore(checkpoint);
                Err(e)
            }
        }
    }

    fn mark_forked(&mut self, u: &mut Unlocked, device: [u8; 16]) -> Result<()> {
        let checkpoint = u.checkpoint();
        u.local.peers.entry(device).or_default().forked = true;
        let tx = self.conn.transaction()?;
        commit(&self.sequence_file, u, &[], tx).inspect_err(|_| u.restore(checkpoint))
    }

    /// Fills a vault that has just joined from another device's snapshot, then
    /// follows every log from where the snapshot says it had them.
    pub fn apply_snapshot(
        &mut self,
        u: &mut Unlocked,
        device: [u8; 16],
        seq: u64,
        bytes: &[u8],
    ) -> Result<usize> {
        if !u.vaults.is_empty() || !u.local.peers.is_empty() {
            return Err(Error(
                "A snapshot only fills a device that has just joined".into(),
            ));
        }
        let parts = open_file(&SNAPSHOT, u, &device, seq, bytes)?;
        let [_, _, _, head, _clock, seen, vaults, revisions] = parts.as_slice() else {
            return Err(Error("A sync file was refused (malformed)".into()));
        };
        let checkpoint = u.checkpoint();
        let tx = self.conn.transaction()?;
        let result = (|| {
            let (touched, count) = apply_rows(&tx, u, vaults, revisions, None)?;
            for entry in seen.list()? {
                let [id, seq, hash] = entry.list()? else {
                    return Err(Error("A sync file was refused (malformed)".into()));
                };
                let id: [u8; 16] = id.fixed()?;
                if !u.local.mine.contains(&id) {
                    u.local.peers.insert(
                        id,
                        Peer {
                            seq: seq.uint()?,
                            hash: hash.fixed()?,
                            forked: false,
                        },
                    );
                }
            }
            let hash = match head.bytes()? {
                [] if seq == 0 => [0; 32],
                bytes => bytes
                    .try_into()
                    .map_err(|_| Error("A sync file was refused (malformed)".into()))?,
            };
            u.local.peers.insert(
                device,
                Peer {
                    seq,
                    hash,
                    forked: false,
                },
            );
            // Nothing here was written on this device, so its log starts empty.
            u.local.exported = u.local.next_rev - 1;
            u.local.snapshot = Some(0);
            let touched: Vec<&str> = touched.iter().map(String::as_str).collect();
            commit(&self.sequence_file, u, &touched, tx).map(|_| count)
        })();
        if result.is_err() {
            u.restore(checkpoint);
        }
        result
    }

    /// Another machine writes under this device's ID (a cloned disk or a
    /// restored backup). This device takes a new ID and follows the old one as
    /// another device from the last file it knows is its own. Change files not
    /// yet seen in the storage are dropped, and the revisions in them move to
    /// the new ID (re-sealed, since a revision is bound to its ID) before they
    /// go out again: the other machine counts on from the same numbers, and two
    /// different revisions must never share an ID.
    pub fn new_device_id(&mut self, u: &mut Unlocked) -> Result<()> {
        let first: Option<(u64, u64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT seq, exported, prev FROM outbox ORDER BY seq LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let checkpoint = u.checkpoint();
        let old = u.local.device();
        let (seq, hash) = match &first {
            Some((seq, exported, prev)) => {
                u.local.exported = *exported;
                (
                    seq - 1,
                    if prev.is_empty() {
                        [0; 32]
                    } else {
                        prev.as_slice().try_into().map_err(|_| tampered("outbox"))?
                    },
                )
            }
            None => (u.local.seq, u.local.head),
        };
        let unsent = checked_rows(
            self,
            u,
            &format!(
                "rev_device = x'{}' AND rev_n > {}",
                hex(&old),
                u.local.exported
            ),
        )?;
        let new: [u8; 16] = vp_crypto::random();
        let moved = |vault_id: &str, item_id: &str, rev: &Rev| {
            if rev.device == old
                && unsent
                    .iter()
                    .any(|r| r.0 == vault_id && r.1 == item_id && r.2 == *rev)
            {
                Rev {
                    device: new,
                    n: rev.n,
                }
            } else {
                *rev
            }
        };
        u.local.peers.insert(
            old,
            Peer {
                seq,
                hash,
                forked: false,
            },
        );
        u.local.mine.push(new);
        u.local.seq = 0;
        u.local.head = [0; 32];
        let tx = self.conn.transaction()?;
        let result = (|| {
            tx.execute("DELETE FROM outbox", [])?;
            let mut touched: Vec<&str> = Vec::new();
            for (vault_id, item_id, rev, parents, head, overview, details) in &unsent {
                let state = u
                    .vaults
                    .get_mut(vault_id)
                    .ok_or_else(|| tampered("vault"))?;
                let g = state.generation;
                let to = moved(vault_id, item_id, rev);
                let parents: Vec<Rev> = decode_revs(parents)?
                    .iter()
                    .map(|p| moved(vault_id, item_id, p))
                    .collect();
                let reseal = |part: &str, sealed: &[u8]| -> Result<Vec<u8>> {
                    let plain = open_item(
                        &state.key,
                        g,
                        &item_ad(vault_id, g, item_id, part, rev),
                        sealed,
                    )?;
                    Ok(seal_item(
                        &state.key,
                        g,
                        &item_ad(vault_id, g, item_id, part, &to),
                        &plain,
                    ))
                };
                let overview = reseal("overview", overview.as_deref().unwrap_or_default())?;
                let details = reseal("details", details)?;
                tx.execute(
                    "UPDATE revision SET rev_device = ?5, parents = ?6, overview = ?7, details = ?8 WHERE vault_id = ?1 AND item_id = ?2 AND rev_device = ?3 AND rev_n = ?4",
                    params![
                        vault_id,
                        item_id,
                        &old[..],
                        rev.n,
                        &new[..],
                        encode_revs(&parents),
                        overview,
                        details
                    ],
                )?;
                state.revisions.remove(&(item_id.clone(), *rev));
                state.revisions.insert(
                    (item_id.clone(), to),
                    RevState {
                        parents,
                        head: *head,
                        overview: Some(h(&overview)),
                        details: h(&details),
                    },
                );
                if !touched.contains(&vault_id.as_str()) {
                    touched.push(vault_id);
                }
            }
            commit(&self.sequence_file, u, &touched, tx)
        })();
        result.inspect_err(|_| u.restore(checkpoint))
    }

    /// One revision's decrypted overview, for showing each side of a conflict.
    pub fn overview(
        &self,
        u: &Unlocked,
        vault_id: &str,
        item_id: &str,
        rev: &Rev,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let state = u.vault(vault_id)?;
        let expected = state
            .revisions
            .get(&(item_id.to_string(), *rev))
            .and_then(|s| s.overview)
            .ok_or_else(|| Error(format!("No revision {rev} of {item_id}")))?;
        let sealed: Vec<u8> = self
            .conn
            .query_row(
                "SELECT overview FROM revision WHERE vault_id = ?1 AND item_id = ?2 AND rev_device = ?3 AND rev_n = ?4",
                params![vault_id, item_id, &rev.device[..], rev.n],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| tampered("missing item"))?;
        if h(&sealed) != expected {
            return Err(tampered("item overview"));
        }
        let ad = item_ad(vault_id, state.generation, item_id, "overview", rev);
        open_item(&state.key, state.generation, &ad, &sealed)
    }
}

/// Stores a file's vault and revision rows after checking each one. A vault
/// already here under another key (made on two devices before they synced)
/// keeps its own key; the other device's rows are re-sealed under it.
/// `writers` limits revisions to the IDs one device has written under, as in a
/// change file.
fn apply_rows(
    tx: &Transaction,
    u: &mut Unlocked,
    vaults: &Value,
    revisions: &Value,
    writers: Option<&[[u8; 16]]>,
) -> Result<(Vec<String>, usize)> {
    let malformed = || Error("A sync file was refused (malformed)".into());
    let wrap_key = u.derived("VisiPass vault key wrap");
    let mut keys: BTreeMap<String, (Key, u64, bool)> = BTreeMap::new();
    let mut touched = Vec::new();
    for entry in vaults.list()? {
        let [id, generation, wrapped, attrs] = entry.list()? else {
            return Err(malformed());
        };
        let (id, generation) = (id.text()?.to_string(), generation.uint()?);
        let (wrapped, attrs) = (wrapped.bytes()?, attrs.bytes()?);
        let key = vp_crypto::unwrap(&wrap_key, &vk_ad(&u.account_id, &id, generation), wrapped)
            .map_err(|_| tampered("a synced vault key"))?;
        vp_crypto::open(&key, &attrs_ad(&id, generation), attrs)
            .map_err(|_| tampered("synced vault attributes"))?;
        let same = match u.vaults.get(&id) {
            Some(v) => v.generation == generation && v.key.expose() == key.expose(),
            None => {
                tx.execute(
                    "INSERT INTO vault VALUES (?1, ?2, ?3, ?4, 0, x'', x'', 0)",
                    params![id, generation, wrapped, attrs],
                )?;
                u.vaults.insert(
                    id.clone(),
                    VaultState {
                        key: Key::from_slice(key.expose())?,
                        generation,
                        sequence: 0,
                        attrs_hash: h(attrs),
                        wrapped_hash: h(wrapped),
                        origin: 0,
                        revisions: BTreeMap::new(),
                    },
                );
                touched.push(id.clone());
                true
            }
        };
        keys.insert(id, (key, generation, same));
    }
    let mut count = 0;
    for entry in revisions.list()? {
        let [vault_id, item_id, rev, parents, overview, details] = entry.list()? else {
            return Err(malformed());
        };
        let (vault_id, item_id) = (vault_id.text()?, item_id.text()?);
        let rev = Rev::from_value(rev)?;
        if writers.is_some_and(|w| !w.contains(&rev.device)) {
            return Err(tampered(
                "a revision another device wrote, in a change file",
            ));
        }
        let parents = revs_of(parents)?;
        let (sealed_overview, sealed_details) = (overview.bytes()?, details.bytes()?);
        let (key, generation, same) = keys
            .get(vault_id)
            .ok_or_else(|| tampered("a revision of a vault the file does not carry"))?;
        let plain_overview = open_item(
            key,
            *generation,
            &item_ad(vault_id, *generation, item_id, "overview", &rev),
            sealed_overview,
        )?;
        let plain_details = open_item(
            key,
            *generation,
            &item_ad(vault_id, *generation, item_id, "details", &rev),
            sealed_details,
        )?;
        let state = u.vaults.get_mut(vault_id).ok_or_else(malformed)?;
        if state.revisions.contains_key(&(item_id.to_string(), rev)) {
            continue;
        }
        let (overview, details) = if *same {
            (sealed_overview.to_vec(), sealed_details.to_vec())
        } else {
            let g = state.generation;
            (
                seal_item(
                    &state.key,
                    g,
                    &item_ad(vault_id, g, item_id, "overview", &rev),
                    &plain_overview,
                ),
                seal_item(
                    &state.key,
                    g,
                    &item_ad(vault_id, g, item_id, "details", &rev),
                    &plain_details,
                ),
            )
        };
        insert_revision(
            tx,
            &mut state.revisions,
            vault_id,
            item_id,
            rev,
            &parents,
            Some(&overview),
            &details,
        )?;
        if !touched.iter().any(|t| t == vault_id) {
            touched.push(vault_id.to_string());
        }
        count += 1;
    }
    Ok((touched, count))
}
