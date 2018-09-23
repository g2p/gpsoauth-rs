extern crate base64;
extern crate byteorder;
extern crate http;
extern crate hyper;
extern crate ring;
extern crate serde_urlencoded;
extern crate untrusted;

use byteorder::{BigEndian, ByteOrder};
use http::Request;

const GOOGLE_DEFAULT_PUBLIC_KEY : &'static str =
    "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==";

const AUTH_URL: &'static str = "https://android.clients.google.com/auth";
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub fn pubkey_components(bytes: &[u8]) -> (&[u8], &[u8]) {
    let i = BigEndian::read_u32(&bytes[..4]) as usize;
    let n = &bytes[4..4 + i];
    let j = BigEndian::read_u32(&bytes[4 + i..8 + i]) as usize;
    assert_eq!(bytes.len(), 8 + i + j);
    let e = &bytes[8 + i..];
    (n, e)
}

pub fn signature(email: &str, password: &str) -> Result<String, ring::error::Unspecified> {
    let rng = ring::rand::SystemRandom::new();
    let key_bytes = base64::decode(GOOGLE_DEFAULT_PUBLIC_KEY).unwrap();
    let key_hash = ring::digest::digest(&ring::digest::SHA1, key_bytes.as_slice());
    let (n, e) = pubkey_components(key_bytes.as_slice());
    let n = untrusted::Input::from(n);
    let e = untrusted::Input::from(e);
    let mut sig = vec![0u8];
    sig.extend(&key_hash.as_ref()[..4]);
    let mut msg = vec![];
    msg.extend(email.as_bytes());
    msg.push(0u8);
    msg.extend(password.as_bytes());
    let msg = untrusted::Input::from(msg.as_slice());
    sig.extend(ring::encryption::encrypt(&rng, n, e, msg)?);
    Ok(base64::encode_config(sig.as_slice(), base64::URL_SAFE))
}

pub fn master_login_request(email: &str, password: &str, device_id: &str) -> Request<hyper::Body> {
    let body = &[
        ("accountType", "HOSTED_OR_GOOGLE"),
        ("Email", email),
        ("has_permission", "1"),
        ("add_account", "1"),
        ("EncryptedPasswd", &signature(email, password).unwrap()),
        ("service", "ac2dm"),
        ("source", "android"),
        ("androidId", device_id),
        ("device_country", "us"),
        ("operatorCountry", "us"),
        ("lang", "en"),
        ("sdk_version", "17"),
    ];
    let body = serde_urlencoded::to_string(body).unwrap();
    println!("Body {}", body);
    Request::post(AUTH_URL)
        .header("User-Agent", "gpsoauth-rs/".to_owned() + VERSION)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(hyper::Body::from(body))
        .unwrap()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_signature() {
        let username = "someone@google.com";
        let password = "apassword";
        let sig = signature(username, password).unwrap();
        eprintln!("{}", sig);
        // This only tests the hash part
        assert!(sig.starts_with("AFcb4K"));
    }
}
