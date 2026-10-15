//! The 1Password backend: every vault operation is a call to `op`.
//!
//! Rules carried over from 2password:
//! - Plaintext reaches `op` only on stdin, never argv or the environment.
//! - Any call that sends or reveals plaintext passes a fixed `failure` message,
//!   which suppresses op's stderr so none of its output can reach an error.
//! - Writes run once, are read back and compared, and are never retried.
//! - No `op whoami` preflight: the operation itself is the capability check.
//! - Batch: one `item get -` for many items, one `op run` for many references.

mod edit;
mod items;

use serde::Deserialize;
use serde_json::{Value, json};
use std::ffi::OsString;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use vp_core::Failure;
use vp_core::backend::Backend;
use vp_core::model::{
    Destination, ItemDetail, ItemSummary, Listed, PasswordOutcome, PasswordRequest, Receipt, Scope,
    VaultRef,
};
use vp_core::refs::SecretRef;
use vp_core::secret::Secret;

/// Environment variable carrying the index'th reference into `op run`.
pub const SECRET_VAR_PREFIX: &str = "VISIPASS_SECRET_";

pub struct OpBackend {
    program: OsString,
    /// argv of a helper that prints `[$VISIPASS_SECRET_0, ...]` as JSON. `op run`
    /// resolves the references in its environment and runs it. The daemon
    /// passes itself with a hidden subcommand.
    helper: Vec<OsString>,
}

#[derive(Default)]
pub(crate) struct Call<'a> {
    account: Option<&'a str>,
    input: Option<&'a str>,
    failure: Option<&'a str>,
    env: Vec<(String, String)>,
}

pub(crate) fn is_id(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn service_account() -> bool {
    std::env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_some_and(|v| !v.is_empty())
}

impl OpBackend {
    /// `op` from PATH. Never from an environment override: whoever starts the
    /// daemon must not be able to swap the program every later request uses.
    pub fn new(helper: Vec<OsString>) -> Self {
        Self::with_program("op", helper)
    }

    pub fn with_program(program: impl Into<OsString>, helper: Vec<OsString>) -> Self {
        Self {
            program: program.into(),
            helper,
        }
    }

    pub(crate) async fn op(&self, args: &[&str], call: Call<'_>) -> Result<String, Failure> {
        let fixed = |default: &str| Failure::new(call.failure.unwrap_or(default));
        let mut command = Command::new(&self.program);
        command.args(args);
        if let Some(account) = call.account {
            command.args(["--account", account]);
        }
        command
            .envs(call.env.iter().map(|(k, v)| (k, v)))
            .stdin(if call.input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(if call.failure.is_some() {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|_| fixed("Failed to run 1Password's op; run vp doctor"))?;
        // op accepts piped input only from a real pipe, which this is. It is
        // written while the output is read: op starts printing before it has read
        // everything, and a full output pipe would otherwise stall both sides.
        let stdin = child.stdin.take();
        let write = async {
            if let (Some(input), Some(mut stdin)) = (call.input, stdin) {
                stdin.write_all(input.as_bytes()).await?;
            }
            Ok::<_, std::io::Error>(())
        };
        let (written, output) = tokio::join!(write, child.wait_with_output());
        let output = output.map_err(|_| fixed("Failed to run 1Password's op"))?;
        written.map_err(|_| fixed("Failed to run 1Password's op"))?;
        if output.status.success() {
            return String::from_utf8(output.stdout)
                .map_err(|_| fixed("1Password returned invalid output"));
        }
        let code = output.status.code().unwrap_or(-1);
        Err(match call.failure {
            Some(message) => Failure::new(message),
            None if service_account() => Failure::new(format!(
                "1Password operation failed with service-account authentication (exit {code}; details suppressed)"
            )),
            None => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                Failure::new(if stderr.is_empty() {
                    format!("op exited with {code}")
                } else {
                    stderr
                })
            }
        })
    }

    pub(crate) async fn json<T: for<'de> Deserialize<'de>>(
        &self,
        args: &[&str],
        call: Call<'_>,
    ) -> Result<T, Failure> {
        let failure = call
            .failure
            .unwrap_or("1Password returned invalid JSON")
            .to_string();
        let text = self.op(args, call).await?;
        serde_json::from_str(&text).map_err(|_| Failure::new(failure))
    }

    // Case-insensitive and whitespace-tolerant. Not an atomic lock against concurrent writers.
    async fn title_taken(
        &self,
        vault: &str,
        title: &str,
        account: Option<&str>,
        failure: &str,
    ) -> Result<bool, Failure> {
        #[derive(Deserialize)]
        struct Titled {
            title: String,
        }
        let items: Vec<Titled> = self
            .json(
                &["item", "list", "--vault", vault, "--format", "json"],
                Call {
                    account,
                    failure: Some(failure),
                    ..Call::default()
                },
            )
            .await?;
        Ok(items
            .iter()
            .any(|i| i.title.trim().to_lowercase() == title.to_lowercase()))
    }
}

/// `op item get -` prints one JSON document per item, concatenated.
pub(crate) fn json_documents(input: &str) -> Result<Vec<Value>, Failure> {
    let mut out = Vec::new();
    for document in serde_json::Deserializer::from_str(input).into_iter::<Value>() {
        match document.map_err(|_| Failure::new("1Password returned invalid JSON"))? {
            Value::Array(items) => out.extend(items),
            other => out.push(other),
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
struct ReceiptJson {
    id: String,
    title: String,
    category: String,
    vault: VaultRef,
}

#[derive(Deserialize)]
struct StoredField {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    section: Option<Value>,
}

#[derive(Deserialize)]
struct StoredUrl {
    href: String,
}

#[derive(Deserialize)]
struct StoredItem {
    id: String,
    title: String,
    category: String,
    vault: VaultRef,
    #[serde(default)]
    urls: Vec<StoredUrl>,
    #[serde(default)]
    fields: Vec<StoredField>,
}

impl StoredItem {
    fn builtin_passwords(&self) -> Vec<&StoredField> {
        self.fields
            .iter()
            .filter(|f| {
                f.id == "password"
                    && f.purpose.as_deref() == Some("PASSWORD")
                    && f.kind == "CONCEALED"
                    && f.section.is_none()
            })
            .collect()
    }
}

impl Backend for OpBackend {
    fn name(&self) -> &'static str {
        "1password"
    }

    async fn list(&self, scope: &Scope) -> Result<Vec<Listed>, Failure> {
        let mut args = vec!["item", "list", "--format", "json"];
        if let Some(vault) = scope.vault.as_deref() {
            args.extend(["--vault", vault]);
        }
        let raw: Vec<Value> = self
            .json(
                &args,
                Call {
                    account: scope.account.as_deref(),
                    ..Call::default()
                },
            )
            .await?;
        raw.into_iter()
            .map(|raw| {
                let summary: ItemSummary = serde_json::from_value(raw.clone())
                    .map_err(|_| Failure::new("1Password returned invalid JSON"))?;
                Ok(Listed { summary, raw })
            })
            .collect()
    }

    // One op call for every item, so one authorization prompt covers them all.
    async fn details(&self, entries: &[Listed], scope: &Scope) -> Result<Vec<ItemDetail>, Failure> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let input = format!(
            "{}\n",
            Value::Array(entries.iter().map(|e| e.raw.clone()).collect())
        );
        // The output holds field values; it never reaches an error and is decoded into value-free types.
        let output = self
            .op(
                &["item", "get", "-", "--format", "json"],
                Call {
                    account: scope.account.as_deref(),
                    input: Some(&input),
                    ..Call::default()
                },
            )
            .await?;
        json_documents(&output)?
            .into_iter()
            .map(|v| {
                serde_json::from_value(v)
                    .map_err(|_| Failure::new("1Password returned invalid JSON"))
            })
            .collect()
    }

    // Resolves every reference with a single `op run`, so one authorization covers them all.
    async fn resolve(&self, refs: &[SecretRef]) -> Result<Vec<Secret>, Failure> {
        if refs.is_empty() {
            return Ok(Vec::new());
        }
        let count = refs.len().to_string();
        let mut args: Vec<&str> = vec!["run", "--no-masking", "--"];
        let helper: Vec<String> = self
            .helper
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        args.extend(helper.iter().map(String::as_str));
        args.push(&count);
        let env = refs
            .iter()
            .enumerate()
            .map(|(i, r)| (format!("{SECRET_VAR_PREFIX}{i}"), r.to_op()))
            .collect();
        let failure = "Could not resolve the secret references (1Password details suppressed). Check them with vp find";
        let output = Secret::new(
            self.op(
                &args,
                Call {
                    failure: Some(failure),
                    env,
                    ..Call::default()
                },
            )
            .await?,
        );
        let values: Vec<String> = serde_json::from_str(output.expose())
            .map_err(|_| Failure::new("1Password returned an invalid secret batch"))?;
        if values.len() != refs.len() {
            return Err(Failure::new("1Password returned an invalid secret batch"));
        }
        Ok(values.into_iter().map(Secret::new).collect())
    }

    async fn create_api_credential(
        &self,
        destination: &Destination,
        value: Secret,
    ) -> Result<Receipt, Failure> {
        let title = destination.title.trim();
        let vault = destination.vault.trim();
        let account = destination.account.as_deref();
        if title.is_empty() || vault.is_empty() || value.is_blank() {
            return Err(Failure::new(
                "A title, explicit vault, and non-empty credential are required; nothing was created",
            ));
        }
        if self
            .title_taken(vault, title, account, "Could not check for an existing title; nothing was created (1Password details suppressed)")
            .await?
        {
            return Err(Failure::new(
                "An item with this title already exists in the selected vault; nothing was created or overwritten. Use vp find to inspect it",
            ));
        }

        let mut fields = vec![
            json!({"id": "credential", "type": "CONCEALED", "label": "credential", "value": value.expose()}),
        ];
        if let Some(notes) = &destination.notes {
            fields.push(json!({"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": notes}));
        }
        let mut template = json!({"title": title, "category": "API_CREDENTIAL", "fields": fields});
        if let Some(url) = &destination.url {
            template["urls"] = json!([{"href": url, "primary": true}]);
        }
        let template = Secret::new(template.to_string());

        let receipt: ReceiptJson = self
            .json(
                &["item", "create", "-", "--vault", vault, "--format", "json"],
                Call {
                    account,
                    input: Some(template.expose()),
                    failure: Some("Creation may have succeeded, but its receipt could not be verified. Do not retry creation; inspect the destination with vp find first (1Password details suppressed)"),
                    ..Call::default()
                },
            )
            .await?;
        // Only validated IDs, never op's arbitrary reference strings, reach output.
        if !is_id(&receipt.id) || !is_id(&receipt.vault.id) {
            return Err(Failure::new(
                "Creation is unverified. Do not retry creation; inspect the destination by title with vp find first (1Password details suppressed)",
            ));
        }
        let reference = format!("op://{}/{}/credential", receipt.vault.id, receipt.id);
        let unverified = format!(
            "Creation is unverified. Do not retry creation; inspect the destination by title with vp find first. Item reference: {reference} (1Password details suppressed)"
        );
        if receipt.title != title
            || receipt.category != "API_CREDENTIAL"
            || (receipt.vault.name != vault && receipt.vault.id != vault)
        {
            return Err(Failure::new(unverified));
        }
        let stored = Secret::new(
            self.op(
                &[
                    "item",
                    "get",
                    &receipt.id,
                    "--vault",
                    &receipt.vault.id,
                    "--format",
                    "json",
                    "--reveal",
                ],
                Call {
                    account,
                    failure: Some(&unverified),
                    ..Call::default()
                },
            )
            .await?,
        );
        let stored: StoredItem =
            serde_json::from_str(stored.expose()).map_err(|_| Failure::new(unverified.clone()))?;
        let credentials: Vec<&StoredField> = stored
            .fields
            .iter()
            .filter(|f| f.id == "credential")
            .collect();
        let stored_notes = stored
            .fields
            .iter()
            .find(|f| f.id == "notesPlain" && f.section.is_none());
        let matches = stored.id == receipt.id
            && stored.vault.id == receipt.vault.id
            && stored.vault.name == receipt.vault.name
            && stored.title == title
            && stored.category == "API_CREDENTIAL"
            && credentials.len() == 1
            && credentials[0].kind == "CONCEALED"
            && credentials[0].section.is_none()
            && credentials[0].value.as_deref() == Some(value.expose())
            && destination
                .notes
                .as_ref()
                .is_none_or(|n| stored_notes.and_then(|f| f.value.as_deref()).unwrap_or("") == n)
            && destination
                .url
                .as_ref()
                .is_none_or(|u| stored.urls.iter().any(|s| &s.href == u));
        if !matches {
            return Err(Failure::new(unverified));
        }
        Ok(Receipt {
            id: receipt.id,
            title: title.to_string(),
            vault: vault.to_string(),
            kind: "api-credential".into(),
            field: "credential".into(),
            reference,
            verified: true,
        })
    }

    async fn vaults(&self, account: Option<&str>) -> Result<Vec<VaultRef>, Failure> {
        self.vault_list(account).await
    }

    async fn create_vault(&self, name: &str) -> Result<VaultRef, Failure> {
        self.new_vault(name.trim()).await
    }

    async fn item(&self, id: &str, vault: &str) -> Result<vp_core::model::Item, Failure> {
        self.get_item(id, vault).await
    }

    async fn save_item(
        &self,
        item: &vp_core::model::Item,
    ) -> Result<vp_core::model::Item, Failure> {
        self.put_item(item).await
    }

    async fn set_favorite(&self, id: &str, vault: &str, favorite: bool) -> Result<(), Failure> {
        self.favorite_item(id, vault, favorite).await
    }

    async fn archive(&self, id: &str, vault: &str) -> Result<(), Failure> {
        self.archive_item(id, vault).await
    }

    async fn password(
        &self,
        request: &PasswordRequest,
        value: Secret,
    ) -> Result<PasswordOutcome, Failure> {
        if request.item.trim().is_empty() || request.vault.trim().is_empty() {
            return Err(Failure::new("An item and explicit vault are required"));
        }
        let account = request.account.as_deref();
        let inspect = "Could not inspect login; nothing was changed (1Password details suppressed)";
        let raw = Secret::new(
            self.op(
                &[
                    "item",
                    "get",
                    &request.item,
                    "--vault",
                    &request.vault,
                    "--format",
                    "json",
                    "--reveal",
                ],
                Call {
                    account,
                    failure: Some(inspect),
                    ..Call::default()
                },
            )
            .await?,
        );
        let item: StoredItem =
            serde_json::from_str(raw.expose()).map_err(|_| Failure::new(inspect))?;
        let current = item.builtin_passwords();
        if item.category != "LOGIN"
            || current.len() != 1
            || !is_id(&item.id)
            || !is_id(&item.vault.id)
        {
            return Err(Failure::new(
                "Expected a Login with exactly one built-in password; nothing was changed",
            ));
        }
        let same = current[0].value.as_deref() == Some(value.expose());
        let mut outcome = PasswordOutcome {
            id: item.id.clone(),
            title: item.title.clone(),
            vault: item.vault.name.clone(),
            reference: format!("op://{}/{}/password", item.vault.id, item.id),
            matches: None,
            changed: None,
            verified: None,
        };
        if !request.apply {
            outcome.matches = Some(same);
            return Ok(outcome);
        }
        if same {
            outcome.changed = Some(false);
            outcome.verified = Some(true);
            return Ok(outcome);
        }

        let template =
            edit::with_password(raw.expose(), value.expose(), request.repair_imported_fields)?;
        let uncertain = "Password update is unverified; check this item before retrying (1Password details suppressed)";
        self.op(
            &[
                "item",
                "edit",
                &item.id,
                "--vault",
                &item.vault.id,
                "--format",
                "json",
            ],
            Call {
                account,
                input: Some(template.expose()),
                failure: Some(&format!("{uncertain}; edit request failed")),
                ..Call::default()
            },
        )
        .await?;
        let stored = Secret::new(
            self.op(
                &[
                    "item",
                    "get",
                    &item.id,
                    "--vault",
                    &item.vault.id,
                    "--format",
                    "json",
                    "--reveal",
                ],
                Call {
                    account,
                    failure: Some(&format!("{uncertain}; read-back failed")),
                    ..Call::default()
                },
            )
            .await?,
        );
        let stored: StoredItem = serde_json::from_str(stored.expose())
            .map_err(|_| Failure::new(format!("{uncertain}; read-back format invalid")))?;
        let passwords = stored.builtin_passwords();
        if stored.id != item.id
            || stored.vault.id != item.vault.id
            || stored.title != item.title
            || stored.category != item.category
            || passwords.len() != 1
            || passwords[0].value.as_deref() != Some(value.expose())
        {
            return Err(Failure::new(format!(
                "{uncertain}; read-back did not match"
            )));
        }
        outcome.changed = Some(true);
        outcome.verified = Some(true);
        Ok(outcome)
    }
}

/// The hidden helper `op run` executes: prints the resolved references as a
/// JSON array on stdout. Returns false if the environment is incomplete.
pub fn dump_secrets(count: usize) -> bool {
    let values: Option<Vec<String>> = (0..count)
        .map(|i| std::env::var(format!("{SECRET_VAR_PREFIX}{i}")).ok())
        .collect();
    match values.and_then(|v| serde_json::to_string(&v).ok()) {
        Some(json) => {
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(json.as_bytes()).is_ok() && stdout.flush().is_ok()
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for op that, like op, prints while it is still reading.
    #[tokio::test]
    async fn large_input_and_output_do_not_stall() {
        let backend = OpBackend::with_program("cat", vec![]);
        let input = "x".repeat(1 << 20);
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            backend.op(
                &[],
                Call {
                    input: Some(&input),
                    ..Call::default()
                },
            ),
        )
        .await
        .expect("stalled")
        .unwrap();
        assert_eq!(output.len(), input.len());
    }

    #[test]
    fn splits_concatenated_documents() {
        let docs = json_documents("{\"id\":\"a\"}\n{\"id\":\"b\"}[{\"id\":\"c\"}]").unwrap();
        assert_eq!(docs.len(), 3);
    }

    #[test]
    fn validates_ids() {
        assert!(is_id("abcdefghijklmnopqrstuvwxyz"));
        assert!(!is_id("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        assert!(!is_id("short"));
    }
}
