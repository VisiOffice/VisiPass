//! Schema 1, which kept one version counter per item. Read only to check a file
//! exactly as it was written and migrate it to schema 2: every row re-sealed
//! under its revision, in one transaction, after a backup beside the file.

use super::*;

fn item_ad(vault_id: &str, generation: u64, item_id: &str, part: &str, version: u64) -> Vec<u8> {
    ad(
        "VisiPass item",
        &[
            Part::Text(vault_id),
            Part::Uint(generation),
            Part::Text(item_id),
            Part::Text(part),
            Part::Uint(version),
        ],
    )
}

struct Vault {
    id: String,
    key: Key,
    generation: u64,
    sequence: u64,
    attrs_hash: [u8; 32],
    wrapped_hash: [u8; 32],
    /// item_id, version, overview, details
    items: Vec<(String, u64, Vec<u8>, Vec<u8>)>,
    /// item_id, version, details
    history: Vec<(String, u64, Vec<u8>)>,
}

fn vault_manifest(v: &Vault) -> Vec<u8> {
    let commit = vk_commit(&v.id, v.generation, &v.key);
    let mut items: Vec<_> = v.items.iter().collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let mut history: Vec<_> = v.history.iter().collect();
    history.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    let (ov, det): (Vec<[u8; 32]>, Vec<[u8; 32]>) =
        items.iter().map(|(_, _, o, d)| (h(o), h(d))).unzip();
    let old: Vec<[u8; 32]> = history.iter().map(|(_, _, d)| h(d)).collect();
    let items = items
        .iter()
        .enumerate()
        .map(|(i, (id, version, _, _))| {
            Part::List(vec![
                Part::Text(id),
                Part::Uint(*version),
                Part::Bytes(&ov[i]),
                Part::Bytes(&det[i]),
            ])
        })
        .collect();
    let history = history
        .iter()
        .enumerate()
        .map(|(i, (id, version, _))| {
            Part::List(vec![
                Part::Text(id),
                Part::Uint(*version),
                Part::Bytes(&old[i]),
            ])
        })
        .collect();
    ad(
        "VisiPass vault manifest",
        &[
            Part::Text(&v.id),
            Part::Uint(v.generation),
            Part::Bytes(&commit),
            Part::Uint(v.sequence),
            Part::Bytes(&v.attrs_hash),
            Part::Bytes(&v.wrapped_hash),
            Part::List(items),
            Part::List(history),
        ],
    )
}

pub(crate) fn open_and_migrate(
    store: &Store,
    row: AccountRow,
    ak: Key,
    signing: SigningKey,
) -> Result<Unlocked> {
    let conn = &store.conn;
    let wrap_key = derive(
        &ak,
        "VisiPass vault key wrap",
        &row.account_id,
        row.ak_generation,
    );
    let mut statement = conn.prepare(
        "SELECT vault_id, vk_generation, wrapped_vk, attrs, sequence, manifest, signature FROM vault",
    )?;
    type Row = (String, u64, Vec<u8>, Vec<u8>, u64, Vec<u8>, Vec<u8>);
    let rows: Vec<Row> = statement
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    drop(statement);
    let mut vaults = Vec::new();
    for (id, generation, wrapped_vk, attrs, sequence, stored, signature) in rows {
        let key = vp_crypto::unwrap(
            &wrap_key,
            &vk_ad(&row.account_id, &id, generation),
            &wrapped_vk,
        )
        .map_err(|_| tampered("vault key"))?;
        let mut items = conn.prepare(
            "SELECT item_id, item_version, overview, details FROM item WHERE vault_id = ?1",
        )?;
        let items = items
            .query_map([&id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut history =
            conn.prepare("SELECT item_id, item_version, details FROM history WHERE vault_id = ?1")?;
        let history = history
            .query_map([&id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let vault = Vault {
            id,
            key,
            generation,
            sequence,
            attrs_hash: h(&attrs),
            wrapped_hash: h(&wrapped_vk),
            items,
            history,
        };
        if vault_manifest(&vault) != stored || !check_manifest(&signing, &stored, &signature) {
            return Err(tampered(&format!("vault {}", vault.id)));
        }
        vaults.push(vault);
    }
    vaults.sort_by(|a, b| a.id.cmp(&b.id));
    let account_row_hash = account_row_hash(&row.wrapped_ak, &row.params, &row.salt, &row.keyset);
    let digests: Vec<[u8; 32]> = vaults.iter().map(|v| h(&vault_manifest(v))).collect();
    let account = ad(
        "VisiPass account manifest",
        &[
            Part::Bytes(&row.account_id),
            Part::Uint(row.ak_generation),
            Part::Uint(row.sequence),
            Part::List(
                vaults
                    .iter()
                    .zip(&digests)
                    .map(|(v, d)| {
                        Part::List(vec![
                            Part::Text(&v.id),
                            Part::Uint(v.sequence),
                            Part::Bytes(d),
                        ])
                    })
                    .collect(),
            ),
            Part::Bytes(&account_row_hash),
        ],
    );
    if account != row.manifest || !check_manifest(&signing, &row.manifest, &row.signature) {
        return Err(tampered("account manifest"));
    }

    // Checked. Keep a copy of the file as it was, then migrate.
    let mut name = store.path.as_os_str().to_owned();
    name.push(".schema1-backup");
    let backup = PathBuf::from(name);
    if !backup.exists() {
        conn.execute(
            "VACUUM INTO ?1",
            [backup
                .to_str()
                .ok_or_else(|| Error("Unusable vault path".into()))?],
        )
        .map_err(|_| {
            Error("Could not back up the vault before upgrading it; nothing was changed".into())
        })?;
    }
    let last = vaults
        .iter()
        .flat_map(|v| v.items.iter().map(|i| i.1))
        .max()
        .unwrap_or(0);
    let mut unlocked = Unlocked {
        account_id: row.account_id,
        ak_generation: row.ak_generation,
        ak,
        signing,
        sequence: row.sequence,
        account_row_hash,
        vaults: BTreeMap::new(),
        local: Local::new(last + 1),
    };
    let device = unlocked.local.device();
    let rev = |version: u64| Rev { device, n: version };
    let parents = |version: u64| {
        if version > 1 {
            vec![rev(version - 1)]
        } else {
            vec![]
        }
    };
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "ALTER TABLE account ADD COLUMN device BLOB NOT NULL DEFAULT x'';
         ALTER TABLE vault ADD COLUMN origin INTEGER NOT NULL DEFAULT 0;",
    )?;
    tx.execute_batch(TABLES)?;
    for v in vaults {
        let mut revisions = Revisions::new();
        let reseal = |item_id: &str, part: &str, version: u64, sealed: &[u8]| -> Result<Vec<u8>> {
            let plain = open_item(
                &v.key,
                v.generation,
                &item_ad(&v.id, v.generation, item_id, part, version),
                sealed,
            )?;
            Ok(seal_item(
                &v.key,
                v.generation,
                &super::item_ad(&v.id, v.generation, item_id, part, &rev(version)),
                &plain,
            ))
        };
        for (item_id, version, details) in &v.history {
            let details = reseal(item_id, "details", *version, details)?;
            insert_revision(
                &tx,
                &mut revisions,
                &v.id,
                item_id,
                rev(*version),
                &parents(*version),
                None,
                &details,
            )?;
        }
        for (item_id, version, overview, details) in &v.items {
            let overview = reseal(item_id, "overview", *version, overview)?;
            let details = reseal(item_id, "details", *version, details)?;
            insert_revision(
                &tx,
                &mut revisions,
                &v.id,
                item_id,
                rev(*version),
                &parents(*version),
                Some(&overview),
                &details,
            )?;
        }
        unlocked.vaults.insert(
            v.id.clone(),
            VaultState {
                key: v.key,
                generation: v.generation,
                sequence: v.sequence,
                attrs_hash: v.attrs_hash,
                wrapped_hash: v.wrapped_hash,
                origin: 0,
                revisions,
            },
        );
    }
    tx.execute_batch(
        "DROP TABLE item; DROP TABLE history; UPDATE account SET format_version = 2;",
    )?;
    let ids = unlocked.vault_ids();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    commit(&store.sequence_file, &mut unlocked, &ids, tx)?;
    Ok(unlocked)
}
