//! Where sync goes when it is an S3-compatible bucket (§11.1 of
//! `docs/crypto-design.md`). Nothing here is secret: the keys travel apart, as
//! [`BucketKeys`].

use crate::secret::Secret;
use serde::{Deserialize, Serialize};

/// An S3-compatible bucket: AWS, Cloudflare R2, Backblaze B2, MinIO.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketConfig {
    /// `https://host[:port]`, with no path.
    pub endpoint: String,
    pub bucket: String,
    /// Inside the bucket, without slashes at either end; may be empty.
    #[serde(default)]
    pub prefix: String,
    pub region: String,
}

/// The bucket's keys, typed in the VisiPass window and kept in the vault.
#[derive(Clone)]
pub struct BucketKeys {
    pub access_key: Secret,
    pub secret_key: Secret,
}

/// Where a device syncs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SyncPlace {
    Folder { path: String },
    Bucket { bucket: BucketConfig },
}

impl SyncPlace {
    /// As a person would write it.
    pub fn describe(&self) -> String {
        match self {
            SyncPlace::Folder { path } => path.clone(),
            SyncPlace::Bucket { bucket } => bucket.location(),
        }
    }
}

impl BucketConfig {
    /// From `s3://bucket[/prefix]` and the flags beside it. AWS needs only a
    /// region; every other provider needs its endpoint, and its region is
    /// read from that where the provider puts one there.
    pub fn parse(
        location: &str,
        endpoint: Option<&str>,
        region: Option<&str>,
    ) -> Result<Self, String> {
        let rest = location
            .strip_prefix("s3://")
            .ok_or_else(|| format!("{location} is not an s3://bucket address"))?;
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        let endpoint = match (endpoint, region) {
            (Some(endpoint), _) => endpoint.trim_end_matches('/').to_string(),
            (None, Some(region)) => format!("https://s3.{region}.amazonaws.com"),
            (None, None) => {
                return Err(
                    "Say where the bucket is: --endpoint https://... (R2, Backblaze, MinIO), or --region us-east-1 for AWS"
                        .into(),
                );
            }
        };
        let region = region
            .map(str::to_string)
            .unwrap_or_else(|| region_of(&endpoint));
        let config = BucketConfig {
            endpoint,
            bucket: bucket.to_string(),
            prefix: prefix.trim_matches('/').to_string(),
            region,
        };
        config.check()?;
        Ok(config)
    }

    /// Refuses anything that could reach somewhere other than the storage
    /// named, or send the files in the clear beyond this machine.
    pub fn check(&self) -> Result<(), String> {
        let url = url::Url::parse(&self.endpoint)
            .map_err(|_| format!("{} is not a usable endpoint URL", self.endpoint))?;
        let loopback = match url.host() {
            Some(url::Host::Domain(name)) => name == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback)) {
            return Err("The endpoint must be https:// (http:// only on this machine)".into());
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(
                "The endpoint is only https://host[:port]; the bucket goes in s3://bucket".into(),
            );
        }
        let name_ok = (3..=63).contains(&self.bucket.len())
            && self
                .bucket
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'));
        if !name_ok {
            return Err(format!("{} is not a bucket name", self.bucket));
        }
        // The prefix goes unescaped into listings the storage echoes back.
        let prefix_ok = self
            .prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '/'))
            && self
                .prefix
                .split('/')
                .all(|p| self.prefix.is_empty() || !(p.is_empty() || p == "." || p == ".."));
        if !prefix_ok {
            return Err(
                "The path inside the bucket may use only letters, digits and - . _ /".into(),
            );
        }
        let region_ok = !self.region.is_empty()
            && self
                .region
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !region_ok {
            return Err(format!("{} is not a region", self.region));
        }
        Ok(())
    }

    /// `s3://bucket/prefix`.
    pub fn location(&self) -> String {
        if self.prefix.is_empty() {
            format!("s3://{}", self.bucket)
        } else {
            format!("s3://{}/{}", self.bucket, self.prefix)
        }
    }
}

/// R2 signs as `auto`; AWS and Backblaze name the region in the host; S3
/// servers that do neither (MinIO, most others) expect `us-east-1`.
fn region_of(endpoint: &str) -> String {
    let host = url::Url::parse(endpoint)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    if host.ends_with(".r2.cloudflarestorage.com") {
        return "auto".into();
    }
    for provider in [".amazonaws.com", ".backblazeb2.com"] {
        if let Some(region) = host
            .strip_suffix(provider)
            .and_then(|h| h.strip_prefix("s3."))
        {
            return region.to_string();
        }
    }
    "us-east-1".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_get_their_region_from_the_endpoint() {
        let parse = |endpoint| BucketConfig::parse("s3://my-vault/a/b/", Some(endpoint), None);
        let r2 = parse("https://abc.r2.cloudflarestorage.com").unwrap();
        assert_eq!(r2.region, "auto");
        assert_eq!(r2.prefix, "a/b");
        assert_eq!(r2.location(), "s3://my-vault/a/b");
        assert_eq!(
            parse("https://s3.us-west-004.backblazeb2.com/")
                .unwrap()
                .region,
            "us-west-004"
        );
        assert_eq!(parse("http://127.0.0.1:9000").unwrap().region, "us-east-1");
    }

    #[test]
    fn aws_needs_only_a_region_and_nothing_means_asking() {
        let aws = BucketConfig::parse("s3://my-vault", None, Some("eu-west-1")).unwrap();
        assert_eq!(aws.endpoint, "https://s3.eu-west-1.amazonaws.com");
        assert!(
            BucketConfig::parse("s3://my-vault", None, None)
                .unwrap_err()
                .contains("--endpoint")
        );
    }

    #[test]
    fn unsafe_places_are_refused() {
        let parse = |location, endpoint| BucketConfig::parse(location, Some(endpoint), None);
        for endpoint in [
            "http://storage.example.com",
            "https://user:pw@storage.example.com",
            "https://storage.example.com/path",
            "https://storage.example.com?x=1",
            "file:///etc",
            "not a url",
        ] {
            assert!(parse("s3://my-vault", endpoint).is_err(), "{endpoint}");
        }
        for location in [
            "s3://a",
            "s3://bad bucket",
            "s3://my-vault/../up",
            "s3://my-vault/a//b",
            "s3://my-vault/a&b",
            "/home/me/folder",
        ] {
            assert!(
                parse(location, "https://storage.example.com").is_err(),
                "{location}"
            );
        }
    }
}
