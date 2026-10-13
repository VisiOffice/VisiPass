//! Quick unlock's presence check (crypto design §4.3): polkit asks the human for
//! their fingerprint or login password through the desktop's authentication agent.
//!
//! The action is `com.visioffice.visipass.unlock`, `auth_self` and never
//! `auth_self_keep`, so every quick unlock asks. The daemon talks to polkitd on
//! the system bus itself; no same-user process can answer in its place.

use std::collections::HashMap;
use std::time::Duration;
use vp_native::Presence;
use zbus::zvariant::Value;

pub const ACTION: &str = "com.visioffice.visipass.unlock";
const ALLOW_USER_INTERACTION: u32 = 1;

#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
trait Authority {
    fn check_authorization(
        &self,
        subject: &(&str, HashMap<&str, Value<'_>>),
        action_id: &str,
        details: HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;
}

/// Asks polkit. Anything short of a clear answer (no system bus, no policy, no
/// agent, a timeout) is [`Presence::Unavailable`], and the master password is asked instead.
pub async fn check(timeout: Duration) -> Presence {
    tokio::time::timeout(timeout, ask())
        .await
        .unwrap_or(Presence::Unavailable)
}

async fn ask() -> Presence {
    let Ok(bus) = zbus::Connection::system().await else {
        return Presence::Unavailable;
    };
    let Some(name) = bus.unique_name().map(|n| n.to_string()) else {
        return Presence::Unavailable;
    };
    let Ok(authority) = AuthorityProxy::new(&bus).await else {
        return Presence::Unavailable;
    };
    let subject = (
        "system-bus-name",
        HashMap::from([("name", Value::from(name.as_str()))]),
    );
    match authority
        .check_authorization(&subject, ACTION, HashMap::new(), ALLOW_USER_INTERACTION, "")
        .await
    {
        Ok((true, _, _)) => Presence::Confirmed,
        Ok((false, _, details))
            if details.get("polkit.dismissed").map(String::as_str) == Some("true") =>
        {
            Presence::Dismissed
        }
        _ => Presence::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against the real polkitd, without user interaction, so no dialog opens:
    /// `cargo test -p vp-daemon presence -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "needs the system bus and polkitd"]
    async fn the_call_reaches_polkit() {
        let bus = zbus::Connection::system().await.unwrap();
        let name = bus.unique_name().unwrap().to_string();
        let authority = AuthorityProxy::new(&bus).await.unwrap();
        let subject = (
            "system-bus-name",
            HashMap::from([("name", Value::from(name.as_str()))]),
        );
        let answer = authority
            .check_authorization(
                &subject,
                "org.freedesktop.policykit.exec",
                HashMap::new(),
                0,
                "",
            )
            .await
            .unwrap();
        println!("{answer:?}");
        assert!(!answer.0 && answer.1, "an auth_admin action is a challenge");
        let missing = authority
            .check_authorization(&subject, ACTION, HashMap::new(), 0, "")
            .await;
        println!("{missing:?}");
    }
}
