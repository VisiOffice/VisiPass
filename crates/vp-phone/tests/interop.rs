//! The two things the phone does with CryptoKit, checked against files
//! CryptoKit wrote: it opens a request sealed here (HPKE Auth mode), and
//! visipassd accepts its ECDSA signatures.
//!
//! `interop/rust.json` is written by `cargo test -p vp-phone --test interop --
//! --ignored write_rust_vectors`; `interop/cryptokit.json` by
//! `tools/phone-interop.swift` in the iOS app's repository, which opens the
//! request and signs with CryptoKit.

use hpke::{Kem as _, Serializable};
use serde_json::{Value, json};
use vp_phone::*;

type Kem = hpke::kem::DhP256HkdfSha256;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &Value) -> Vec<u8> {
    let s = s.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn read(name: &str) -> Value {
    let path = format!("{}/tests/interop/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
#[ignore = "writes tests/interop/rust.json"]
fn write_rust_vectors() {
    let daemon = DaemonKey::generate();
    let kem_p_private: [u8; 32] = vp_crypto::random();
    let (_, kem_p) = Kem::derive_keypair(&kem_p_private);
    // derive_keypair hashes its input; CryptoKit wants the scalar itself.
    let kem_p_private = Kem::derive_keypair(&kem_p_private).0.to_bytes();
    let kem_p: PublicKey = kem_p.to_bytes().as_slice().try_into().unwrap();
    let sign_p_private: [u8; 32] = vp_crypto::random();
    let sign_p = p256::ecdsa::SigningKey::from_slice(&sign_p_private).unwrap();

    let pairing_id: PairingId = vp_crypto::random();
    let request = Request::new(
        pairing_id,
        Kind::Approve,
        Prompt {
            who: "Claude Code".into(),
            action: "inject 1 secret into a command".into(),
            details: vec![("Project".into(), "~/Code/visipass".into())],
            secrets: vec!["vp://Dev/Stripe/secret key".into()],
            purpose: Some("Run the billing tests ✓".into()),
            paste: None,
        },
        vec![Choice::Deny, Choice::Once, Choice::Task, Choice::Hours],
        1_800_000_000,
    );
    let body = request.encode();
    let sealed = SealedRequest::seal(&daemon, &kem_p, &pairing_id, &body).unwrap();
    let answer = Answer {
        request_id: request.request_id,
        request_hash: Request::hash(&body),
        choice: Choice::Once,
        value: None,
    }
    .encode();

    let vectors = json!({
        "kem_d_public": hex(&daemon.public()),
        "kem_p_private": hex(&kem_p_private),
        "kem_p_public": hex(&kem_p),
        "sign_p_private": hex(&sign_p_private),
        "sign_p_public": hex(sign_p.verifying_key().to_encoded_point(false).as_bytes()),
        "pairing_id": hex(&pairing_id),
        "request_info": hex(&Request::info(&pairing_id)),
        "request_body": hex(&body),
        "request_enc": hex(&sealed.sealed.enc),
        "request_ciphertext": hex(&sealed.sealed.ciphertext),
        "answer": hex(&answer),
        "answer_signed_bytes": hex(&Answer::signed_bytes(&pairing_id, &answer)),
    });
    let path = format!("{}/tests/interop/rust.json", env!("CARGO_MANIFEST_DIR"));
    std::fs::write(path, serde_json::to_string_pretty(&vectors).unwrap() + "\n").unwrap();
}

/// CryptoKit opened the request this crate sealed, and got its exact bytes.
#[test]
fn cryptokit_opens_a_sealed_request() {
    let rust = read("rust.json");
    let cryptokit = read("cryptokit.json");
    assert_eq!(cryptokit["opened_request_body"], rust["request_body"]);
    assert!(cryptokit["impostor_refused"].as_bool().unwrap());
}

/// visipassd accepts answers CryptoKit signed, and only over the bytes it signed.
#[test]
fn cryptokit_signatures_verify() {
    let rust = read("rust.json");
    let cryptokit = read("cryptokit.json");
    let sign_p: PublicKey = unhex(&rust["sign_p_public"]).try_into().unwrap();
    let pairing_id: PairingId = unhex(&rust["pairing_id"]).try_into().unwrap();
    let signatures = cryptokit["answer_signatures"].as_array().unwrap();
    assert!(signatures.len() >= 16);
    for signature in signatures {
        let answer = SignedAnswer {
            pairing_id,
            answer: unhex(&rust["answer"]),
            signature: unhex(signature).try_into().unwrap(),
        };
        let decoded = answer.verify(&sign_p).unwrap();
        assert_eq!(decoded.choice, Choice::Once);

        let mut other = answer.clone();
        other.pairing_id[0] ^= 1;
        assert!(other.verify(&sign_p).is_err());
    }
}
