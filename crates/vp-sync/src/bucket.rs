//! An S3-compatible bucket as sync storage: AWS, Cloudflare R2, Backblaze B2,
//! MinIO. Blocking, and only the handful of calls §11.1 needs, signed here
//! with AWS Signature Version 4 rather than through a provider's SDK. Buckets
//! are addressed by path (`host/bucket/key`), which they all accept.
//!
//! Secrets stay out of every error: failures name the endpoint and the
//! storage's own error code, never a key, a signature or a response body.

use crate::{Created, Storage};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};
use vp_core::bucket::{BucketConfig, BucketKeys};
use vp_store::{Error, Result, hex};

/// More than any vault's snapshot; a storage cannot make a device fill memory.
const MOST_BYTES: u64 = 512 * 1024 * 1024;
const MOST_PAGES: usize = 1000;

pub struct Bucket {
    config: BucketConfig,
    keys: BucketKeys,
    root: String,
    host: String,
    agent: ureq::Agent,
}

struct Reply {
    status: u16,
    body: Vec<u8>,
    modified: Option<SystemTime>,
}

fn sha256(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Everything but RFC 3986's unreserved characters; `/` too when `slash`.
fn encode(text: &str, slash: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~')
            || (!slash && byte == b'/')
        {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The query string, sorted as signing and sending both need it.
fn query_string(query: &[(&str, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (encode(k, true), encode(v, true)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// One request, as Signature Version 4 sees it.
struct Signing<'a> {
    method: &'a str,
    /// Already percent-encoded.
    path: &'a str,
    query: &'a str,
    /// Lower-case names, sorted, `host` and the `x-amz-` ones included.
    headers: &'a [(&'a str, &'a str)],
    payload_hash: &'a str,
    /// `20130524T000000Z`.
    amz_date: &'a str,
    region: &'a str,
}

/// The `Authorization` header's value.
fn authorization(signing: &Signing, access_key: &str, secret_key: &str) -> String {
    let date = &signing.amz_date[..8];
    let scope = format!("{date}/{}/s3/aws4_request", signing.region);
    let canonical_headers: String = signing
        .headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let signed_headers = signing
        .headers
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let canonical = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{}",
        signing.method, signing.path, signing.query, signing.payload_hash
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        signing.amz_date,
        sha256(canonical.as_bytes())
    );
    let key = [signing.region, "s3", "aws4_request"].iter().fold(
        hmac(format!("AWS4{secret_key}").as_bytes(), date.as_bytes()),
        |key, part| hmac(&key, part.as_bytes()),
    );
    let signature = hex(&hmac(&key, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope},SignedHeaders={signed_headers},Signature={signature}"
    )
}

/// `20130524T000000Z`.
fn amz_date(unix: u64) -> String {
    vp_core::time::rfc3339(unix)
        .chars()
        .filter(|c| !matches!(c, '-' | ':'))
        .collect()
}

/// The storage's error code, if it sent a plausible one. Only the code: the
/// rest of an error body is the storage's to fill with anything.
fn error_code(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let start = text.find("<Code>")? + "<Code>".len();
    let code = &text[start..start + text[start..].find("</Code>")?];
    (!code.is_empty() && code.len() <= 64 && code.chars().all(|c| c.is_ascii_alphanumeric()))
        .then(|| code.to_string())
}

/// One page of a listing: names under the prefix and the next page's token.
fn parse_listing(body: &[u8], base: &str) -> Result<(Vec<String>, Option<String>)> {
    use quick_xml::events::Event;
    let refused = || Error("The bucket sent a listing that could not be read".to_string());
    let mut reader = quick_xml::Reader::from_reader(body);
    let mut buffer = Vec::new();
    let mut path: Vec<Vec<u8>> = Vec::new();
    let mut names = Vec::new();
    let mut token = None;
    let mut truncated = false;
    loop {
        match reader.read_event_into(&mut buffer).map_err(|_| refused())? {
            Event::Start(e) => {
                if path.len() >= 8 {
                    return Err(refused());
                }
                path.push(e.local_name().as_ref().to_vec());
            }
            Event::End(_) => {
                path.pop();
            }
            Event::Text(e) => {
                let text = String::from_utf8_lossy(e.as_ref()).into_owned();
                let parts: Vec<&[u8]> = path.iter().map(Vec::as_slice).collect();
                match parts.as_slice() {
                    [_, b"Contents", b"Key"] | [_, b"CommonPrefixes", b"Prefix"] => {
                        if let Some(name) = text.strip_prefix(base) {
                            let name = name.trim_end_matches('/');
                            if !name.is_empty() && !name.contains('/') {
                                names.push(name.to_string());
                            }
                        }
                    }
                    [_, b"NextContinuationToken"] => token = Some(text),
                    [_, b"IsTruncated"] => truncated = text.trim() == "true",
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok((names, token.filter(|_| truncated)))
}

impl Bucket {
    /// Sync files go in `visipass-sync` inside the bucket path chosen, as
    /// they do inside a folder.
    pub fn new(config: BucketConfig, keys: BucketKeys) -> Result<Bucket> {
        config.check().map_err(Error)?;
        for key in [keys.access_key.expose(), keys.secret_key.expose()] {
            if key.is_empty() || key.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(Error("A bucket key is empty or has spaces in it".into()));
            }
        }
        let url = url::Url::parse(&config.endpoint)
            .map_err(|_| Error(format!("{} is not a usable endpoint", config.endpoint)))?;
        let name = url.host_str().unwrap_or_default();
        let host = match url.port() {
            Some(port) => format!("{name}:{port}"),
            None => name.to_string(),
        };
        let root = if config.prefix.is_empty() {
            "visipass-sync".to_string()
        } else {
            format!("{}/visipass-sync", config.prefix)
        };
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(120)))
            .http_status_as_error(false)
            // A redirect would carry a signature made for another address.
            .max_redirects(0)
            .build()
            .into();
        Ok(Bucket {
            config,
            keys,
            root,
            host,
            agent,
        })
    }

    fn key(&self, relative: &str) -> String {
        let relative = relative.trim_matches('/');
        if relative.is_empty() {
            self.root.clone()
        } else {
            format!("{}/{relative}", self.root)
        }
    }

    fn unreachable(&self) -> Error {
        Error(format!(
            "Could not reach the bucket at {}. Is this device online?",
            self.config.endpoint
        ))
    }

    /// Anything that is not an answer the caller expected.
    fn failed(&self, reply: &Reply) -> Error {
        let code = error_code(&reply.body);
        Error(match (reply.status, code.as_deref()) {
            (_, Some("NoSuchBucket")) => format!(
                "There is no bucket {} at {}",
                self.config.bucket, self.config.endpoint
            ),
            (_, Some("RequestTimeTooSkewed")) => {
                "The bucket refused the request because this device's clock is wrong".to_string()
            }
            (_, Some("AuthorizationHeaderMalformed")) | (301, _) => format!(
                "The bucket is not in region {}; set it with --region",
                self.config.region
            ),
            (401 | 403, code) => format!(
                "The bucket refused these keys ({}). Check they can read, write and list {}",
                code.unwrap_or("access denied"),
                self.config.bucket
            ),
            (status, Some(code)) => format!("The bucket answered {status} ({code})"),
            (status, None) => format!("The bucket answered {status}"),
        })
    }

    fn send(
        &self,
        method: &str,
        key: Option<&str>,
        query: &[(&str, String)],
        body: Option<&[u8]>,
        only_if_new: bool,
    ) -> Result<Reply> {
        let bucket = encode(&self.config.bucket, true);
        let path = match key {
            Some(key) => format!("/{bucket}/{}", encode(key, false)),
            None => format!("/{bucket}"),
        };
        let query = query_string(query);
        let payload_hash = sha256(body.unwrap_or_default());
        let date = amz_date(vp_core::time::now_unix());
        let mut headers = Vec::new();
        headers.push(("host", self.host.as_str()));
        if only_if_new {
            headers.push(("if-none-match", "*"));
        }
        headers.push(("x-amz-content-sha256", payload_hash.as_str()));
        headers.push(("x-amz-date", date.as_str()));
        let authorization = authorization(
            &Signing {
                method,
                path: &path,
                query: &query,
                headers: &headers,
                payload_hash: &payload_hash,
                amz_date: &date,
                region: &self.config.region,
            },
            self.keys.access_key.expose(),
            self.keys.secret_key.expose(),
        );
        let mut uri = format!("{}{path}", self.config.endpoint);
        if !query.is_empty() {
            uri.push('?');
            uri.push_str(&query);
        }
        let mut request = ureq::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", authorization);
        for (name, value) in headers.iter().filter(|(name, _)| *name != "host") {
            request = request.header(*name, *value);
        }
        let sent = match body {
            Some(body) => self
                .agent
                .run(request.body(body).map_err(|_| self.unreachable())?),
            None => self
                .agent
                .run(request.body(()).map_err(|_| self.unreachable())?),
        };
        let mut response = sent.map_err(|_| self.unreachable())?;
        let status = response.status().as_u16();
        let modified = response
            .headers()
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| httpdate::parse_http_date(v).ok());
        let body = if method == "HEAD" {
            Vec::new()
        } else {
            response
                .body_mut()
                .with_config()
                .limit(MOST_BYTES)
                .read_to_vec()
                .map_err(|_| self.unreachable())?
        };
        Ok(Reply {
            status,
            body,
            modified,
        })
    }

    fn put(&self, key: &str, bytes: &[u8], only_if_new: bool) -> Result<Reply> {
        self.send("PUT", Some(key), &[], Some(bytes), only_if_new)
    }

    /// The file read back: the bytes there now decide, whatever the storage
    /// said about the write.
    fn settled(&self, relative: &str, bytes: &[u8]) -> Result<Created> {
        match self.read(relative)? {
            Some(there) if there == bytes => Ok(Created::Written),
            Some(there) => Ok(Created::Exists(there)),
            None => Err(Error(
                "The bucket did not keep a file just written to it".into(),
            )),
        }
    }
}

impl Storage for Bucket {
    fn list(&self, dir: &str) -> Result<Vec<String>> {
        let base = format!("{}/", self.key(dir));
        let mut names = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..MOST_PAGES {
            let mut query = vec![
                ("delimiter", "/".to_string()),
                ("list-type", "2".to_string()),
                ("prefix", base.clone()),
            ];
            if let Some(token) = &token {
                query.push(("continuation-token", token.clone()));
            }
            let reply = self.send("GET", None, &query, None, false)?;
            if reply.status != 200 {
                return Err(self.failed(&reply));
            }
            let (page, next) = parse_listing(&reply.body, &base)?;
            names.extend(page);
            match next {
                Some(next) => token = Some(next),
                None => {
                    names.retain(|name| !name.starts_with('.'));
                    names.sort();
                    return Ok(names);
                }
            }
        }
        Err(Error("The bucket's listing did not end".into()))
    }

    fn read(&self, relative: &str) -> Result<Option<Vec<u8>>> {
        let reply = self.send("GET", Some(&self.key(relative)), &[], None, false)?;
        match reply.status {
            200 => Ok(Some(reply.body)),
            404 if error_code(&reply.body).as_deref() != Some("NoSuchBucket") => Ok(None),
            _ => Err(self.failed(&reply)),
        }
    }

    /// `If-None-Match: *` so nothing is ever replaced, and for a storage that
    /// does not honour it the look beforehand and the read afterwards stand
    /// in: another machine's bytes under this name show up as `Exists`.
    fn create(&self, relative: &str, bytes: &[u8]) -> Result<Created> {
        if let Some(existing) = self.read(relative)? {
            return Ok(Created::Exists(existing));
        }
        let key = self.key(relative);
        let reply = self.put(&key, bytes, true)?;
        match (reply.status, error_code(&reply.body).as_deref()) {
            (200 | 201, _) => self.settled(relative, bytes),
            // Someone got there first, or is writing it now.
            (412 | 409, _) => self
                .read(relative)?
                .map(Created::Exists)
                .ok_or_else(|| self.failed(&reply)),
            (501, _) | (400, Some("NotImplemented")) => {
                let reply = self.put(&key, bytes, false)?;
                if !matches!(reply.status, 200 | 201) {
                    return Err(self.failed(&reply));
                }
                self.settled(relative, bytes)
            }
            _ => Err(self.failed(&reply)),
        }
    }

    fn modified(&self, relative: &str) -> Option<SystemTime> {
        let reply = self
            .send("HEAD", Some(&self.key(relative)), &[], None, false)
            .ok()?;
        (reply.status == 200).then_some(reply.modified).flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCESS: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const DATE: &str = "20130524T000000Z";

    /// The worked examples in AWS's Signature Version 4 documentation.
    #[test]
    fn signatures_match_the_published_examples() {
        let header = authorization(
            &Signing {
                method: "GET",
                path: "/test.txt",
                query: "",
                headers: &[
                    ("host", "examplebucket.s3.amazonaws.com"),
                    ("range", "bytes=0-9"),
                    ("x-amz-content-sha256", EMPTY),
                    ("x-amz-date", DATE),
                ],
                payload_hash: EMPTY,
                amz_date: DATE,
                region: "us-east-1",
            },
            ACCESS,
            SECRET,
        );
        assert!(
            header.ends_with(
                "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
            ),
            "{header}"
        );

        let query = query_string(&[("prefix", "J".into()), ("max-keys", "2".into())]);
        assert_eq!(query, "max-keys=2&prefix=J");
        let header = authorization(
            &Signing {
                method: "GET",
                path: "/",
                query: &query,
                headers: &[
                    ("host", "examplebucket.s3.amazonaws.com"),
                    ("x-amz-content-sha256", EMPTY),
                    ("x-amz-date", DATE),
                ],
                payload_hash: EMPTY,
                amz_date: DATE,
                region: "us-east-1",
            },
            ACCESS,
            SECRET,
        );
        assert!(
            header.ends_with(
                "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
            ),
            "{header}"
        );
    }

    #[test]
    fn dates_and_paths_are_written_as_signing_needs() {
        assert_eq!(amz_date(1_369_353_600), DATE);
        assert_eq!(encode("a/b c+d", false), "a/b%20c%2Bd");
        assert_eq!(encode("a/b", true), "a%2Fb");
    }

    #[test]
    fn listings_give_names_directly_under_the_prefix() {
        let xml = br#"<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <Name>b</Name><Prefix>r/d/</Prefix><IsTruncated>true</IsTruncated>
            <NextContinuationToken>tok</NextContinuationToken>
            <Contents><Key>r/d/one.vpc</Key><Size>1</Size></Contents>
            <Contents><Key>other/two.vpc</Key></Contents>
            <Contents><Key>r/d/deep/three.vpc</Key></Contents>
            <CommonPrefixes><Prefix>r/d/sub/</Prefix></CommonPrefixes>
            </ListBucketResult>"#;
        let (names, token) = parse_listing(xml, "r/d/").unwrap();
        assert_eq!(names, ["one.vpc", "sub"]);
        assert_eq!(token.as_deref(), Some("tok"));
    }

    #[test]
    fn only_a_plain_error_code_is_taken_from_a_response() {
        assert_eq!(
            error_code(b"<Error><Code>AccessDenied</Code><Message>x</Message></Error>").as_deref(),
            Some("AccessDenied")
        );
        assert_eq!(error_code(b"<Code>has a space</Code>"), None);
        assert_eq!(error_code(b"nothing"), None);
    }
}
