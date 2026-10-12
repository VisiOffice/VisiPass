use crate::Failure;
use crate::model::{
    Destination, ItemDetail, Listed, PasswordOutcome, PasswordRequest, Receipt, Scope,
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

    /// Compares, or with `apply` updates and verifies, a login's password.
    fn password(
        &self,
        request: &PasswordRequest,
        value: Secret,
    ) -> impl Future<Output = Result<PasswordOutcome, Failure>> + Send;
}
