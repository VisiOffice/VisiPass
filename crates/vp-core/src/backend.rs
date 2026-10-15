use crate::Failure;
use crate::model::{
    Destination, Item, ItemDetail, Listed, PasswordOutcome, PasswordRequest, Receipt, Scope,
    VaultRef,
};
use crate::refs::SecretRef;
use crate::secret::Secret;
use std::future::Future;

/// Where items live. M0 ships the 1Password (`op`) backend; the native store
/// arrives in M0.5 behind the same trait. Grants, approvals, masking and the
/// access log all sit above it, in the daemon.
///
/// Every call may prompt the human, so callers batch: one `list` + one
/// `details` per discovery command, one `resolve` per consumption command.
pub trait Backend: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn list(&self, scope: &Scope) -> impl Future<Output = Result<Vec<Listed>, Failure>> + Send;

    /// Metadata for many items in one call. Never returns values.
    fn details(
        &self,
        entries: &[Listed],
        scope: &Scope,
    ) -> impl Future<Output = Result<Vec<ItemDetail>, Failure>> + Send;

    /// One value per reference, in order, in one call.
    fn resolve(
        &self,
        refs: &[SecretRef],
    ) -> impl Future<Output = Result<Vec<Secret>, Failure>> + Send;

    /// Creates exactly once, then reads back and compares before claiming success.
    fn create_api_credential(
        &self,
        destination: &Destination,
        value: Secret,
    ) -> impl Future<Output = Result<Receipt, Failure>> + Send;

    /// Vaults the backend can reach.
    fn vaults(
        &self,
        account: Option<&str>,
    ) -> impl Future<Output = Result<Vec<VaultRef>, Failure>> + Send;

    /// Creates an empty vault, once, and confirms it exists. Refuses a name
    /// already in use (ignoring case), so a retry never makes a second one.
    fn create_vault(&self, name: &str) -> impl Future<Output = Result<VaultRef, Failure>> + Send;

    /// One item with its values. Human surfaces only.
    fn item(&self, id: &str, vault: &str) -> impl Future<Output = Result<Item, Failure>> + Send;

    /// Creates (empty `id`) or updates an item, then reads it back and compares.
    fn save_item(&self, item: &Item) -> impl Future<Output = Result<Item, Failure>> + Send;

    /// Marks or unmarks an item as a favourite, and confirms the change.
    fn set_favorite(
        &self,
        id: &str,
        vault: &str,
        favorite: bool,
    ) -> impl Future<Output = Result<(), Failure>> + Send;

    /// Moves an item to the archive. Never deletes.
    fn archive(&self, id: &str, vault: &str) -> impl Future<Output = Result<(), Failure>> + Send;

    /// Compares, or with `apply` updates and verifies, a login's password.
    fn password(
        &self,
        request: &PasswordRequest,
        value: Secret,
    ) -> impl Future<Output = Result<PasswordOutcome, Failure>> + Send;

    // ---- VisiPass's own vault, for backends that have one ----

    /// `Some` when this backend has a native vault.
    fn native_status(&self) -> Option<NativeStatus> {
        None
    }

    /// Creates the native vault. Returns the Secret Key's display form, which
    /// only ever goes to the human's window.
    fn native_init(
        &self,
        _password: Secret,
    ) -> impl Future<Output = Result<Secret, Failure>> + Send {
        async { Err(Failure::new(NO_NATIVE)) }
    }

    /// Erases the native vault's keys from memory. Without `full`, a quick-unlock
    /// window keeps the Account Key.
    fn native_lock(&self, _full: bool) {}

    /// Checks the master password afresh and returns the Emergency Kit's contents.
    fn native_emergency_kit(
        &self,
        _password: Secret,
    ) -> impl Future<Output = Result<EmergencyKit, Failure>> + Send {
        async { Err(Failure::new(NO_NATIVE)) }
    }

    /// Turns quick unlock on for `window` (after the master password) or off.
    fn native_quick_unlock(
        &self,
        _window: Option<std::time::Duration>,
    ) -> impl Future<Output = Result<(), Failure>> + Send {
        async { Err(Failure::new(NO_NATIVE)) }
    }

    /// Copies 1Password vaults (all, or the one named) into the native vault.
    fn native_import(
        &self,
        _vault: Option<String>,
    ) -> impl Future<Output = Result<serde_json::Value, Failure>> + Send {
        async { Err(Failure::new(NO_NATIVE)) }
    }
}

/// What the Emergency Kit page shows. The Secret Key goes only to that page.
pub struct EmergencyKit {
    pub account_id: String,
    pub secret_key: Secret,
    pub vault_file: std::path::PathBuf,
}

/// The native vault, for `vp status`.
#[derive(Clone, Debug, Default)]
pub struct NativeStatus {
    pub exists: bool,
    pub unlocked: bool,
    /// Quick unlock's window, when it is on.
    pub quick_unlock: Option<std::time::Duration>,
    /// Time left in the open quick-unlock window.
    pub quick_unlock_remaining: Option<std::time::Duration>,
}

const NO_NATIVE: &str = "This visipassd has no native vault";
