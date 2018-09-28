#[macro_use]
extern crate log;

extern crate base64;
extern crate byteorder;
extern crate futures;
extern crate http;
extern crate hyper;
extern crate ring;
extern crate serde_urlencoded;
extern crate untrusted;

use byteorder::{BigEndian, ByteOrder};
use futures::future::{err, ok};
use futures::prelude::*;
use http::Request;
use hyper::body::Payload;
use hyper::client::connect::Connect;
use std::io::BufRead;

// https://kov4l3nko.github.io/blog/2014-06-09-about-encryptedpasswd/
const GOOGLE_DEFAULT_PUBLIC_KEY : &'static str =
    "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==";

const AUTH_URL: &'static str = "https://android.clients.google.com/auth";
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub struct ServiceInfo<'a> {
    service: &'a str,
    app: &'a str,
    client_sig: &'a str,
}

pub struct AuthContext<'a> {
    username: &'a str,
    password: &'a str,
    device_id: &'a str,
    service_info: ServiceInfo<'a>,
    master_token: Option<String>,
    oauth_token: Option<String>,
}

pub trait AuthorizedRequestBuilder {
    fn authorization_header(&mut self, oauth_token: &str) -> &mut Self;
}

impl AuthorizedRequestBuilder for http::request::Builder {
    fn authorization_header(&mut self, oauth_token: &str) -> &mut Self {
        self.header(
            "Authorization",
            "GoogleLogin auth=".to_owned() + oauth_token,
        )
    }
}

pub trait Client<B = hyper::Body>
where
    B: Payload + Send + 'static,
    B::Data: Send,
{
    fn request(&self, req: Request<B>) -> hyper::client::ResponseFuture;
}

impl<C, B> Client<B> for hyper::Client<C, B>
where
    C: Connect + Sync + 'static,
    C::Transport: 'static,
    C::Future: 'static,
    B: Payload + Send + 'static,
    B::Data: Send,
{
    fn request(&self, req: Request<B>) -> hyper::client::ResponseFuture {
        hyper::Client::request(self, req)
    }
}

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
    debug!("Body {}", body);
    Request::post(AUTH_URL)
        .header("User-Agent", "gpsoauth-rs/".to_owned() + VERSION)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(hyper::Body::from(body))
        .unwrap()
}

pub fn oauth_request(
    email: &str,
    token: &str,
    device_id: &str,
    service: &str,
    app: &str,
    client_sig: &str,
) -> Request<hyper::Body> {
    let body = &[
        ("accountType", "HOSTED_OR_GOOGLE"),
        ("Email", email),
        ("has_permission", "1"),
        ("EncryptedPasswd", token),
        ("service", service),
        ("source", "android"),
        ("androidId", device_id),
        ("app", app),
        ("client_sig", client_sig),
        ("device_country", "us"),
        ("operatorCountry", "us"),
        ("lang", "en"),
        ("sdk_version", "17"),
    ];
    let body = serde_urlencoded::to_string(body).unwrap();
    debug!("Body {}", body);
    Request::post(AUTH_URL)
        .header("User-Agent", "gpsoauth-rs/".to_owned() + VERSION)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(hyper::Body::from(body))
        .unwrap()
}

pub fn master_auth_async(
    client: &Client<hyper::Body>,
    username: &str,
    password: &str,
    device_id: &str,
) -> impl Future<Item = String, Error = ()> {
    client
        .request(master_login_request(username, password, device_id))
        .and_then(move |res| {
            res.into_body().fold(None, |acc, chunk| {
                ok::<_, hyper::Error>(chunk.lines().fold(acc, |acc, line| {
                    let line = line.unwrap();
                    if line.starts_with("Token=") {
                        Some(line[6..].to_owned())
                    } else {
                        acc
                    }
                }))
            })
        }).map_err(|e| warn!("Login error {}", e))
        .then(|r| {
            if let Ok(Some(x)) = r {
                ok(x)
            } else if let Err(y) = r {
                err(y)
            } else {
                err(warn!("Login error (no token)"))
            }
        })
}

pub fn oauth_async(
    client: &Client<hyper::Body>,
    username: &str,
    master_token: &str,
    device_id: &str,
    service: &str,
    app: &str,
    client_sig: &str,
) -> impl Future<Item = String, Error = ()> {
    client
        .request(oauth_request(
            username,
            master_token,
            device_id,
            service,
            app,
            client_sig,
        )).and_then(move |res| {
            res.into_body().fold(None, |acc, chunk| {
                ok::<_, hyper::Error>(chunk.lines().fold(acc, |acc, line| {
                    let line = line.unwrap();
                    if line.starts_with("Auth=") {
                        Some(line[5..].to_owned())
                    } else {
                        acc
                    }
                }))
            })
        }).map_err(|e| warn!("Login error {}", e))
        .then(|r| {
            if let Ok(Some(x)) = r {
                ok(x)
            } else if let Err(y) = r {
                err(y)
            } else {
                err(warn!("Login error (no token)"))
            }
        })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_signature() {
        let username = "someone@google.com";
        let password = "apassword";
        let sig = signature(username, password).unwrap();
        debug!("{}", sig);
        // This only tests the hash part
        assert!(sig.starts_with("AFcb4K"));
    }
}
