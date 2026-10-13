//! The backend visipassd serves: VisiPass's own vault once it exists, 1Password
//! (`op`) until then. Both stay reachable so `vp import op` can copy one into
//! the other.

use crate::approval::{self, Approver, Prompt};
use serde_json::{Value, json};
use vp_core::Failure;
use vp_core::backend::Backend;
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
    async fn password(&self, retry: bool) -> Result<Option<Secret>, Failure> {
        let prompt = Prompt {
            who: "VisiPass".into(),
            action: "unlock your vault".into(),
            details: vec![],
            secrets: vec![],
            purpose: None,
            timeout_secs: approval::TIMEOUT.as_secs(),
            paste: Some(PasteSpec {
                mode: PasteMode::Unlock { retry },
                ..PasteSpec::default()
            }),
        };
        self.0.paste(&prompt).await
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

    fn native_status(&self) -> Option<(bool, bool)> {
        Some((self.native.exists(), self.native.is_unlocked()))
    }

    async fn native_init(&self, password: Secret) -> Result<Secret, Failure> {
        let shown = self.native.init(password).await?;
        Ok(Secret::new(shown.to_string()))
    }

    fn native_lock(&self) {
        self.native.lock();
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
}
