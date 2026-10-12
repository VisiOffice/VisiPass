//! Images compiled into the binaries. GPUI's `svg()` draws these in one colour
//! (the element's text colour), so the mark follows the theme's accent.

use gpui::{AssetSource, SharedString};
use std::borrow::Cow;

pub const MARK: &str = "brand/visipass-mark.svg";

pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> gpui::Result<Option<Cow<'static, [u8]>>> {
        Ok(match path {
            MARK => Some(Cow::Borrowed(include_bytes!(
                "../../../assets/brand/visipass-mark.svg"
            ))),
            _ => None,
        })
    }

    fn list(&self, _path: &str) -> gpui::Result<Vec<SharedString>> {
        Ok(vec![MARK.into()])
    }
}
