//! The backend visipassd serves: VisiPass's own vault once it exists, 1Password
//! (`op`) until then. Both stay reachable so `vp import op` can copy one into
//! the other.

use crate::approval::{self, Approver, Prompt};
use serde_json::{Value, json};
use vp_core::Failure;
use vp_core::backend::{Backend, EmergencyKit, NativeStatus, SyncOp};
use vp_core::ipc::{PasteMode, PasteSpec};
use vp_core::model::{
    Destination, Item, ItemDetail, Listed, PasswordOutcome, PasswordRequest, Receipt, Scope,
    VaultRef,
};
use vp_core::refs::SecretRef;
use vp_core::secret::Secret;
use vp_native::{NativeBackend, Unlock};
use vp_op::OpBackend;

/// Asks for the master password in the VisiPass window (or zenity, or the terminal).
pub struct WindowUnlock<A>(pub A);

impl<A: Approver> Unlock for WindowUnlock<A> {
    async fn password(
        &self,
        retry: bool,
        purpose: Option<&str>,
    ) -> Result<Option<Secret>, Failure> {
        let prompt = Prompt {
            who: "VisiPass".into(),
            action: purpose.unwrap_or("unlock your vault").into(),
            details: vec![],
            secrets: vec![],
            purpose: None,
            timeout_secs: approval::TIMEOUT.as_secs(),
            paste: Some(PasteSpec {
                mode: PasteMode::Unlock {
                    retry,
                    purpose: purpose.map(String::from),
                },
                ..PasteSpec::default()
            }),
        };
        self.0.paste(&prompt).await
    }

    async fn confirm_presence(&self) -> vp_native::Presence {
        self.0.confirm_presence().await
    }
}

pub struct Routed<U> {
    pub op: OpBackend,
    pub native: NativeBackend<U>,
}

macro_rules! route {
    ($self:ident, $method:ident ( $($arg:expr),* )) => {
        if $self.native.exists() {
            $self.native.$method($($arg),*).await
        } else {
            $self.op.$method($($arg),*).await
        }
    };
}

impl<U: Unlock> Backend for Routed<U> {
    fn name(&self) -> &'static str {
        if self.native.exists() {
            self.native.name()
        } else {
            self.op.name()
        }
    }

    async fn list(&self, scope: &Scope) -> Result<Vec<Listed>, Failure> {
        route!(self, list(scope))
    }

    async fn details(&self, entries: &[Listed], scope: &Scope) -> Result<Vec<ItemDetail>, Failure> {
        route!(self, details(entries, scope))
    }

    async fn resolve(&self, refs: &[SecretRef]) -> Result<Vec<Secret>, Failure> {
        route!(self, resolve(refs))
    }

    async fn create_api_credential(
        &self,
        destination: &Destination,
        value: Secret,
    ) -> Result<Receipt, Failure> {
        route!(self, create_api_credential(destination, value))
    }

    async fn vaults(&self, account: Option<&str>) -> Result<Vec<VaultRef>, Failure> {
        route!(self, vaults(account))
    }

    async fn create_vault(&self, name: &str) -> Result<VaultRef, Failure> {
        route!(self, create_vault(name))
    }

    async fn item(&self, id: &str, vault: &str) -> Result<Item, Failure> {
        route!(self, item(id, vault))
    }

    async fn save_item(&self, item: &Item) -> Result<Item, Failure> {
        route!(self, save_item(item))
    }

    async fn set_favorite(&self, id: &str, vault: &str, favorite: bool) -> Result<(), Failure> {
        route!(self, set_favorite(id, vault, favorite))
    }

    async fn archive(&self, id: &str, vault: &str) -> Result<(), Failure> {
        route!(self, archive(id, vault))
    }

    async fn password(
        &self,
        request: &PasswordRequest,
        value: Secret,
    ) -> Result<PasswordOutcome, Failure> {
        route!(self, password(request, value))
    }

    fn native_status(&self) -> Option<NativeStatus> {
        let quick = self.native.quick_unlock();
        Some(NativeStatus {
            exists: self.native.exists(),
            unlocked: self.native.is_unlocked(),
            quick_unlock: quick.as_ref().map(|q| q.window),
            quick_unlock_remaining: quick.and_then(|q| q.remaining),
        })
    }

    async fn native_init(&self, password: Secret) -> Result<Secret, Failure> {
        let shown = self.native.init(password).await?;
        Ok(Secret::new(shown.to_string()))
    }

    fn native_lock(&self, full: bool) {
        if full {
            self.native.lock_fully();
        } else {
            self.native.lock();
        }
    }

    async fn native_emergency_kit(&self, password: Secret) -> Result<EmergencyKit, Failure> {
        let kit = self.native.emergency_kit(password).await?;
        Ok(EmergencyKit {
            account_id: kit.account_id,
            secret_key: Secret::new(kit.secret_key.to_string()),
            vault_file: kit.vault_file,
        })
    }

    async fn native_quick_unlock(
        &self,
        window: Option<std::time::Duration>,
    ) -> Result<(), Failure> {
        if !self.native.exists() {
            return Err(Failure::new(
                "Create your VisiPass vault first with `vp init`",
            ));
        }
        self.native.set_quick_unlock(window).await
    }

    async fn native_import(&self, vault: Option<String>) -> Result<Value, Failure> {
        if !self.native.exists() {
            return Err(Failure::new(
                "Create your VisiPass vault first with `vp init`",
            ));
        }
        let all = self.op.vaults(None).await?;
        let chosen: Vec<VaultRef> = match vault.as_deref() {
            None => all,
            Some(wanted) => {
                let found: Vec<VaultRef> = all
                    .into_iter()
                    .filter(|v| v.id == wanted || v.name.eq_ignore_ascii_case(wanted))
                    .collect();
                if found.is_empty() {
                    return Err(Failure::new(format!(
                        "1Password has no vault named {wanted}"
                    )));
                }
                found
            }
        };
        let mut report = Vec::new();
        for vault in chosen {
            let listed = self
                .op
                .list(&Scope {
                    account: None,
                    vault: Some(vault.id.clone()),
                })
                .await?;
            let items = self.op.items_with_values(&listed).await?;
            let count = items.len();
            let (created, skipped) = self.native.import(&vault, items).await?;
            report.push(json!({
                "vault": vault.name,
                "items": count,
                "created": created,
                "skipped": skipped,
            }));
        }
        Ok(json!({ "imported": report }))
    }

    async fn native_sync(&self, op: SyncOp) -> Result<Value, Failure> {
        let native = &self.native;
        if !native.exists() && !matches!(op, SyncOp::Join { .. } | SyncOp::Status) {
            return Err(Failure::new(
                "Create your VisiPass vault first with `vp init`, or join one with `vp sync join <folder>`",
            ));
        }
        let report = |r: vp_sync::Report| json!({ "written": r.written, "applied": r.applied, "newDeviceId": r.new_device_id });
        match op {
            SyncOp::Setup { folder } => {
                let r = native.sync_setup(&folder).await?;
                let mut status = native.sync_status();
                status["round"] = report(r);
                status["next"] = json!(
                    "On each other device: install VisiPass, make sure this folder is synced there, then run `vp sync join <folder>` and enter your Secret Key and master password"
                );
                Ok(status)
            }
            SyncOp::Join {
                folder,
                secret_key,
                password,
            } => {
                let secret = vp_crypto::SecretKey::parse(secret_key.expose()).map_err(|e| {
                    Failure::new(format!(
                        "That Secret Key is not right ({e}); nothing was changed"
                    ))
                })?;
                let r = native.sync_join(&folder, secret, password).await?;
                let mut status = native.sync_status();
                status["round"] = report(r);
                Ok(status)
            }
            SyncOp::Round => {
                if let Some(result) = native.sync_round().await {
                    result?;
                }
                Ok(native.sync_status())
            }
            SyncOp::Status => Ok(native.sync_status()),
            SyncOp::Off => {
                native.sync_off()?;
                Ok(
                    json!({ "on": false, "note": "This device stops syncing; the files in the folder stay, and other devices go on syncing" }),
                )
            }
            SyncOp::Conflicts => {
                let conflicts = native.conflicts().await?;
                Ok(json!({
                    "conflicts": conflicts.into_iter().map(|versions| {
                        versions.into_iter().map(|(rev, item)| json!({ "version": rev, "item": item })).collect::<Vec<_>>()
                    }).collect::<Vec<_>>()
                }))
            }
            SyncOp::Resolve { id, vault, keep } => {
                let item = native.resolve_conflict(&id, &vault, &keep).await?;
                Ok(json!({ "settled": item.id, "item": item }))
            }
        }
    }

    async fn native_import_items(
        &self,
        vault: &VaultRef,
        items: Vec<Item>,
    ) -> Result<(usize, usize), Failure> {
        if !self.native.exists() {
            return Err(Failure::new(
                "Create your VisiPass vault first with `vp init`",
            ));
        }
        self.native.import(vault, items).await
    }
}
