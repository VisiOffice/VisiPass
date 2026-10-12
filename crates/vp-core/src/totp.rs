//! One-time codes (RFC 6238 TOTP), computed locally from the stored secret so
//! showing a ticking code costs no vault calls.

use crate::Failure;
use hmac::{Hmac, Mac};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Totp {
    secret: Vec<u8>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
}

fn base32(input: &str) -> Option<Vec<u8>> {
    let mut bits = 0u64;
    let mut count = 0u32;
    let mut out = Vec::new();
    for c in input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
    {
        let value = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u64 - 'A' as u64,
            c @ '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return None,
        };
        bits = (bits << 5) | value;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        pair.split_once('=')
            .filter(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    })
}

impl Totp {
    /// Accepts an `otpauth://totp/...` URI or a bare base32 secret.
    pub fn parse(input: &str) -> Result<Self, Failure> {
        let invalid = || Failure::new("Not a valid one-time password secret");
        let input = input.trim();
        let (secret, digits, period, algorithm) = match input.strip_prefix("otpauth://") {
            Some(rest) => {
                if !rest.to_ascii_lowercase().starts_with("totp/") {
                    return Err(Failure::new("Only time-based (TOTP) codes are supported"));
                }
                let query = rest.split_once('?').map(|(_, q)| q).ok_or_else(invalid)?;
                let algorithm = match query_value(query, "algorithm")
                    .map(str::to_ascii_uppercase)
                    .as_deref()
                {
                    None | Some("SHA1") => Algorithm::Sha1,
                    Some("SHA256") => Algorithm::Sha256,
                    Some("SHA512") => Algorithm::Sha512,
                    _ => return Err(invalid()),
                };
                (
                    query_value(query, "secret")
                        .ok_or_else(invalid)?
                        .to_string(),
                    query_value(query, "digits")
                        .and_then(|d| d.parse().ok())
                        .unwrap_or(6),
                    query_value(query, "period")
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(30),
                    algorithm,
                )
            }
            None => (input.to_string(), 6, 30, Algorithm::Sha1),
        };
        if !(6..=8).contains(&digits) || period == 0 {
            return Err(invalid());
        }
        Ok(Totp {
            secret: base32(&secret).ok_or_else(invalid)?,
            digits,
            period,
            algorithm,
        })
    }

    pub fn code_at(&self, unix: u64) -> String {
        let counter = (unix / self.period).to_be_bytes();
        let digest = match self.algorithm {
            Algorithm::Sha1 => mac::<Hmac<sha1::Sha1>>(&self.secret, &counter),
            Algorithm::Sha256 => mac::<Hmac<sha2::Sha256>>(&self.secret, &counter),
            Algorithm::Sha512 => mac::<Hmac<sha2::Sha512>>(&self.secret, &counter),
        };
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        format!(
            "{:0width$}",
            binary % 10u32.pow(self.digits),
            width = self.digits as usize
        )
    }

    /// The current code and the seconds it stays valid.
    pub fn now(&self) -> (String, u64) {
        let now = crate::time::now_unix();
        (self.code_at(now), self.period - now % self.period)
    }
}

fn mac<M: Mac + hmac::digest::KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut m =
        <M as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(message);
    m.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B. Seeds are ASCII "12345678901234567890" repeated to the hash size.
    fn rfc(seed: &str, algorithm: &str) -> Totp {
        let encoded: String = {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let bytes = seed.as_bytes();
            let mut out = String::new();
            let (mut buffer, mut bits) = (0u32, 0);
            for &b in bytes {
                buffer = (buffer << 8) | b as u32;
                bits += 8;
                while bits >= 5 {
                    bits -= 5;
                    out.push(A[((buffer >> bits) & 31) as usize] as char);
                }
            }
            if bits > 0 {
                out.push(A[((buffer << (5 - bits)) & 31) as usize] as char);
            }
            out
        };
        Totp::parse(&format!(
            "otpauth://totp/x?secret={encoded}&digits=8&algorithm={algorithm}"
        ))
        .unwrap()
    }

    #[test]
    fn matches_rfc_6238_vectors() {
        let sha1 = rfc("12345678901234567890", "SHA1");
        let sha256 = rfc("12345678901234567890123456789012", "SHA256");
        let sha512 = rfc(
            "1234567890123456789012345678901234567890123456789012345678901234",
            "SHA512",
        );
        for (time, a, b, c) in [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (2000000000, "69279037", "90698825", "38618901"),
        ] {
            assert_eq!(sha1.code_at(time), a);
            assert_eq!(sha256.code_at(time), b);
            assert_eq!(sha512.code_at(time), c);
        }
    }

    #[test]
    fn parses_bare_secrets_and_rejects_hotp() {
        let t = Totp::parse("JBSW Y3DP EHPK 3PXP").unwrap();
        assert_eq!(t.code_at(0).len(), 6);
        assert!(Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(Totp::parse("not base32!").is_err());
    }
}
