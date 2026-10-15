//! Reads a two-factor setup QR code from a screenshot of the page, so a login
//! can get its one-time-code secret without a phone.

use base64::Engine;
use vp_core::Failure;
use vp_core::secret::Secret;

/// Larger screenshots are refused rather than decoded.
const MAX_PIXELS: u64 = 40_000_000;

/// The first `otpauth://totp/` link in any QR code in `image` (base64 PNG or
/// JPEG, optionally as a `data:` URL).
pub fn otpauth_in(image: &str) -> Result<Secret, Failure> {
    let unreadable = || Failure::new("Could not read the screenshot of the page");
    let encoded = image
        .split_once("base64,")
        .map_or(image, |(_, data)| data)
        .trim();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| unreadable())?;
    let reader = image::ImageReader::new(std::io::Cursor::new(&bytes))
        .with_guessed_format()
        .map_err(|_| unreadable())?;
    let (width, height) = reader.into_dimensions().map_err(|_| unreadable())?;
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(Failure::new("The screenshot of the page is too large"));
    }
    let picture = image::load_from_memory(&bytes).map_err(|_| unreadable())?;
    let mut prepared = rqrr::PreparedImage::prepare(picture.to_luma8());
    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok().map(|(_, text)| text))
        .find(|text| text.trim().to_ascii_lowercase().starts_with("otpauth://totp/"))
        .map(|text| Secret::new(text.trim().to_string()))
        .ok_or_else(|| {
            Failure::new(
                "No two-factor QR code is visible on the page. Scroll it into view and try again, or paste the setup key",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page-sized screenshot with a QR code somewhere in it.
    fn screenshot(text: &str) -> String {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let modules = code.width();
        let scale = 6;
        let mut page = image::GrayImage::from_pixel(1200, 800, image::Luma([255]));
        for (i, colour) in code.to_colors().into_iter().enumerate() {
            if colour == qrcode::Color::Dark {
                let (x, y) = ((i % modules) as u32, (i / modules) as u32);
                for dx in 0..scale {
                    for dy in 0..scale {
                        page.put_pixel(
                            500 + x * scale + dx,
                            300 + y * scale + dy,
                            image::Luma([0]),
                        );
                    }
                }
            }
        }
        let mut png = Vec::new();
        image::DynamicImage::ImageLuma8(page)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(&png)
    }

    #[test]
    fn reads_the_setup_link_from_a_qr_code_on_the_page() {
        let link =
            "otpauth://totp/VisiGrid:robert@payvy.com?secret=JBSWY3DPEHPK3PXP&issuer=VisiGrid";
        assert_eq!(otpauth_in(&screenshot(link)).unwrap().expose(), link);
        let err = otpauth_in(&screenshot("https://example.com"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("No two-factor QR code"),
            "a QR code that is not a 2FA setup is ignored: {err}"
        );
    }

    #[test]
    fn a_page_without_a_qr_code_says_so() {
        let mut png = Vec::new();
        image::DynamicImage::new_luma8(64, 64)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        let data = format!(
            "data:image/png;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(&png)
        );
        let err = otpauth_in(&data).unwrap_err().to_string();
        assert!(err.contains("No two-factor QR code"), "{err}");
        assert!(otpauth_in("not base64!").is_err());
    }
}
