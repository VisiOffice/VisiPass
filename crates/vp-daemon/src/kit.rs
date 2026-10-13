//! The Emergency Kit (crypto design §5.1): a printable page with the account ID,
//! the Secret Key and a space to write the master password by hand.

use vp_core::backend::EmergencyKit;
use zeroize::Zeroizing;

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The page, self-contained: no scripts or styles from anywhere else.
pub fn page(kit: &EmergencyKit, date: &str) -> Zeroizing<String> {
    let vault = escape(&kit.vault_file.display().to_string());
    let key_file = escape(
        &kit.vault_file
            .with_file_name("secret-key")
            .display()
            .to_string(),
    );
    Zeroizing::new(format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>VisiPass Emergency Kit</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font: 15px/1.5 system-ui, sans-serif; color: #111; background: #fff; max-width: 720px; margin: 32px auto; padding: 0 24px; }}
  h1 {{ font-size: 26px; margin: 0 0 4px; }}
  .date {{ color: #555; margin-bottom: 24px; }}
  .box {{ border: 2px solid #111; border-radius: 8px; padding: 14px 18px; margin: 14px 0; }}
  .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: #555; }}
  .value {{ font: 600 20px/1.4 ui-monospace, monospace; word-break: break-all; }}
  .line {{ border-bottom: 1px solid #111; height: 34px; }}
  ol {{ padding-left: 20px; }}
  code {{ font: 13px ui-monospace, monospace; background: #f2f2f2; padding: 1px 4px; border-radius: 3px; }}
  button {{ font: inherit; padding: 8px 16px; margin-top: 8px; cursor: pointer; }}
  @media print {{ button, .screen {{ display: none; }} body {{ margin: 0; }} }}
</style></head>
<body>
<h1>VisiPass Emergency Kit</h1>
<div class="date">Made {date}</div>
<p class="screen"><button onclick="print()">Print</button> This page is in memory only and is deleted in 10 minutes. Print it or copy the Secret Key by hand.</p>

<div class="box"><div class="label">Secret Key</div><div class="value">{secret}</div></div>
<div class="box"><div class="label">Master password: write it by hand, or keep it only in your head</div><div class="line"></div></div>
<div class="box"><div class="label">Account ID</div><div class="value">{account}</div></div>

<h2>What these are</h2>
<p>Your vault opens only with <b>both</b> your master password and your Secret Key. The Secret Key is saved on this
computer at <code>{key_file}</code>, so day to day you only type the password. You need this page when that file is
gone: a new computer, a reinstall, a lost laptop.</p>
<p>Nobody, including VisiPass, can recover your vault without them. Keep this page somewhere safe, apart from the
computer, and do not write the master password on it if the page is stored with your backups.</p>

<h2>Your items are not on this page</h2>
<p>They are in the vault file, <code>{vault}</code>. Back that file up (it is encrypted). VisiPass does not sync yet,
so the vault file and this page together are what you need to get your items back.</p>

<h2>Restoring on a new computer</h2>
<ol>
<li>Install VisiPass.</li>
<li>Copy your backed-up vault file to <code>~/.local/share/visipass/vault.vpdb</code>.</li>
<li>Save the Secret Key above, on one line, in <code>~/.local/share/visipass/secret-key</code>
    (<code>chmod 600</code> it).</li>
<li>Run any <code>vp</code> command and enter your master password.</li>
</ol>
</body></html>
"#,
        date = escape(date),
        secret = escape(kit.secret_key.expose()),
        account = escape(&kit.account_id),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vp_core::secret::Secret;

    #[test]
    fn the_page_shows_the_key_and_escapes_everything() {
        let kit = EmergencyKit {
            account_id: "0011-2233".into(),
            secret_key: Secret::new("VP1-ABCDEF".into()),
            vault_file: "/home/a<b>/.local/share/visipass/vault.vpdb".into(),
        };
        let page = page(&kit, "2026-10-13");
        assert!(page.contains("VP1-ABCDEF"));
        assert!(page.contains("0011-2233"));
        assert!(page.contains("/home/a&lt;b&gt;/.local/share/visipass/secret-key"));
        assert!(
            !page.contains("src=") && !page.contains("href="),
            "nothing loads from elsewhere"
        );
    }
}
