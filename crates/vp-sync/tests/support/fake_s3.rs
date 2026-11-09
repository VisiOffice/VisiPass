//! A small S3 server on a loopback port, for tests: objects in memory, signed
//! requests required, listings two to a page so paging is always exercised.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub const ACCESS_KEY: &str = "AKIAFAKEACCESSKEY001";
pub const SECRET_KEY: &str = "sentinel-bucket-secret-7d1f";
pub const BUCKET: &str = "vault-sync";

#[derive(Default)]
pub struct Fake {
    pub objects: Mutex<BTreeMap<String, Vec<u8>>>,
    pub requests: AtomicUsize,
    /// Every request is refused, as with wrong keys.
    pub refuse: AtomicBool,
    /// `If-None-Match` is answered 501, as a storage without it might.
    pub no_conditional: AtomicBool,
    /// `If-None-Match` is ignored, and the write replaces what is there.
    pub ignore_conditional: AtomicBool,
}

impl Fake {
    pub fn start() -> (Arc<Fake>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let fake = Arc::new(Fake::default());
        let server = fake.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let server = server.clone();
                std::thread::spawn(move || server.serve(stream));
            }
        });
        (fake, endpoint)
    }

    pub fn count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    fn serve(&self, stream: TcpStream) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.is_empty() {
            return;
        }
        let mut words = line.split_whitespace();
        let method = words.next().unwrap_or_default().to_string();
        let target = words.next().unwrap_or_default().to_string();
        let mut headers = BTreeMap::new();
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            let header = header.trim();
            if header.is_empty() {
                break;
            }
            let (name, value) = header.split_once(':').unwrap();
            headers.insert(name.to_lowercase(), value.trim().to_string());
        }
        let length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        self.requests.fetch_add(1, Ordering::SeqCst);
        let (status, extra, reply) = self.answer(&method, &target, &headers, body);
        let mut out = stream;
        write!(
            out,
            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n",
            if method == "HEAD" { 0 } else { reply.len() }
        )
        .unwrap();
        if method != "HEAD" {
            out.write_all(&reply).unwrap();
        }
    }

    fn answer(
        &self,
        method: &str,
        target: &str,
        headers: &BTreeMap<String, String>,
        body: Vec<u8>,
    ) -> (u16, &'static str, Vec<u8>) {
        let code = |status, code: &str| {
            (
                status,
                "",
                format!("<Error><Code>{code}</Code><Message>m</Message></Error>").into_bytes(),
            )
        };
        let signed = headers.get("authorization").is_some_and(|a| {
            a.starts_with(&format!("AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/"))
                && a.contains("x-amz-date")
                && !a.contains(SECRET_KEY)
        });
        if !signed || self.refuse.load(Ordering::SeqCst) {
            return code(403, "AccessDenied");
        }
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let path = decode(path);
        let Some(rest) = path.strip_prefix(&format!("/{BUCKET}")) else {
            return code(404, "NoSuchBucket");
        };
        let key = rest.trim_start_matches('/').to_string();
        let mut objects = self.objects.lock().unwrap();
        match method {
            "GET" if key.is_empty() => (200, "", list(&objects, query).into_bytes()),
            "GET" => match objects.get(&key) {
                Some(bytes) => (200, "", bytes.clone()),
                None => code(404, "NoSuchKey"),
            },
            "HEAD" => match objects.get(&key) {
                Some(_) => (
                    200,
                    "last-modified: Wed, 21 Oct 2026 07:28:00 GMT\r\n",
                    Vec::new(),
                ),
                None => (404, "", Vec::new()),
            },
            "PUT" => {
                if headers.get("if-none-match").map(String::as_str) == Some("*") {
                    if self.no_conditional.load(Ordering::SeqCst) {
                        return code(501, "NotImplemented");
                    }
                    if objects.contains_key(&key) && !self.ignore_conditional.load(Ordering::SeqCst)
                    {
                        return code(412, "PreconditionFailed");
                    }
                }
                objects.insert(key, body);
                (200, "", Vec::new())
            }
            _ => code(400, "BadRequest"),
        }
    }
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn list(objects: &BTreeMap<String, Vec<u8>>, query: &str) -> String {
    let param = |name: &str| {
        query
            .split('&')
            .find_map(|p| p.strip_prefix(&format!("{name}=")))
            .map(decode)
    };
    let prefix = param("prefix").unwrap_or_default();
    let mut entries: Vec<(String, bool)> = Vec::new();
    for key in objects.keys().filter(|k| k.starts_with(&prefix)) {
        let rest = &key[prefix.len()..];
        let entry = match rest.split_once('/') {
            Some((dir, _)) => (format!("{prefix}{dir}/"), true),
            None => (key.clone(), false),
        };
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    }
    let start: usize = param("continuation-token")
        .and_then(|t| t.parse().ok())
        .unwrap_or(0);
    let page = &entries[start.min(entries.len())..(start + 2).min(entries.len())];
    let more = start + 2 < entries.len();
    let mut xml = format!(
        "<?xml version=\"1.0\"?><ListBucketResult><Prefix>{prefix}</Prefix><IsTruncated>{more}</IsTruncated>"
    );
    if more {
        xml.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            start + 2
        ));
    }
    for (name, is_dir) in page {
        if *is_dir {
            xml.push_str(&format!(
                "<CommonPrefixes><Prefix>{name}</Prefix></CommonPrefixes>"
            ));
        } else {
            xml.push_str(&format!("<Contents><Key>{name}</Key></Contents>"));
        }
    }
    xml.push_str("</ListBucketResult>");
    xml
}
