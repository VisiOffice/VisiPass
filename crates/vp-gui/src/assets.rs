//! Images compiled into the binaries. GPUI's `svg()` draws these in one colour
//! (the element's text colour), so the mark and icons follow the theme.

use gpui::{AssetSource, SharedString, Styled, Svg, px};
use std::borrow::Cow;

pub const MARK: &str = "brand/visipass-mark.svg";

/// Interface icons, from Lucide (ISC licence, `assets/icons/LICENSE`). Drawn
/// as SVG rather than font glyphs so they don't depend on an installed font.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    List,
    Star,
    StarFilled,
    Login,
    Password,
    Code,
    Note,
    Card,
    Server,
    Database,
    Lock,
    Vault,
    Wifi,
    Warning,
    Copy,
    Bot,
}

macro_rules! icons {
    ($($icon:ident => $file:literal),* $(,)?) => {
        impl Icon {
            pub const ALL: &[Icon] = &[$(Icon::$icon),*];

            pub fn path(self) -> &'static str {
                match self { $(Icon::$icon => concat!("icons/", $file, ".svg")),* }
            }

            fn bytes(path: &str) -> Option<&'static [u8]> {
                match path {
                    $(concat!("icons/", $file, ".svg") => {
                        Some(include_bytes!(concat!("../assets/icons/", $file, ".svg")))
                    })*
                    _ => None,
                }
            }
        }
    };
}

icons! {
    List => "list",
    Star => "star",
    StarFilled => "star-filled",
    Login => "key-round",
    Password => "rectangle-ellipsis",
    Code => "code-xml",
    Note => "sticky-note",
    Card => "credit-card",
    Server => "server",
    Database => "database",
    Lock => "lock",
    Vault => "folder",
    Wifi => "wifi",
    Warning => "triangle-alert",
    Copy => "copy",
    Bot => "bot",
}

/// An icon `size` pixels square. Give it a colour with `.text_color`: GPUI's svg
/// doesn't inherit one from its parent.
pub fn icon(icon: Icon, size: f32) -> Svg {
    gpui::svg().path(icon.path()).flex_none().size(px(size))
}

pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> gpui::Result<Option<Cow<'static, [u8]>>> {
        Ok(match path {
            MARK => Some(Cow::Borrowed(include_bytes!(
                "../../../assets/brand/visipass-mark.svg"
            ))),
            other => Icon::bytes(other).map(Cow::Borrowed),
        })
    }

    fn list(&self, _path: &str) -> gpui::Result<Vec<SharedString>> {
        Ok(std::iter::once(MARK)
            .chain(Icon::ALL.iter().map(|i| i.path()))
            .map(SharedString::from)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_icon_loads() {
        for icon in Icon::ALL {
            let bytes = Assets.load(icon.path()).unwrap().unwrap();
            assert!(std::str::from_utf8(&bytes).unwrap().contains("<svg"));
        }
    }
}
