//! The JPKI certificates, read from a real card.

#![cfg(feature = "verify")]

use myna_card::Certificate;
use myna_card::data::Date;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("reading {name}: {e}"))
}

#[test]
fn the_auth_certificate_parses() {
    let cert = Certificate::parse(&fixture("jpki-auth-cert.der")).unwrap();
    assert!(
        cert.subject().contains("CN=997794E9AGCIEG13221003A"),
        "{}",
        cert.subject()
    );
    assert!(
        cert.issuer().contains("JPKI for user authentication"),
        "{}",
        cert.issuer()
    );
    assert_eq!(cert.public_key().unwrap().bits(), 2048);
    assert_eq!(cert.public_key().unwrap().exponent, [0x01, 0x00, 0x01]);
    // sha256WithRSAEncryption
    assert_eq!(cert.signature_algorithm(), "1.2.840.113549.1.1.11");
}

#[test]
fn the_sign_certificate_carries_the_holders_locality() {
    let auth = Certificate::parse(&fixture("jpki-auth-cert.der")).unwrap();
    let sign = Certificate::parse(&fixture("jpki-sign-cert.der")).unwrap();
    // The designed difference between the two: only the signature certificate names where the
    // holder lives.
    assert!(sign.subject().contains("Kiyose-shi"), "{}", sign.subject());
    assert!(!auth.subject().contains("Kiyose-shi"), "{}", auth.subject());
    assert!(
        sign.issuer().contains("JPKI for digital signature"),
        "{}",
        sign.issuer()
    );
    // Different keys, despite the same holder.
    assert_ne!(sign.public_key().unwrap(), auth.public_key().unwrap());
}

#[test]
fn validity_decodes_to_dates() {
    let cert = Certificate::parse(&fixture("jpki-auth-cert.der")).unwrap();
    let (from, to) = cert.validity();
    assert_eq!(from.to_string(), "2025-10-27");
    assert_eq!(to.to_string(), "2030-02-17");

    assert!(cert.is_valid_on(Date {
        year: 2027,
        month: 6,
        day: 1
    }));
    assert!(cert.is_valid_on(from));
    assert!(cert.is_valid_on(to));
    assert!(!cert.is_valid_on(Date {
        year: 2025,
        month: 10,
        day: 26
    }));
    assert!(!cert.is_valid_on(Date {
        year: 2030,
        month: 2,
        day: 18
    }));
}

#[test]
fn the_ca_certificate_is_self_issued() {
    let ca = Certificate::parse(&fixture("jpki-auth-ca-cert.der")).unwrap();
    assert_eq!(ca.subject(), ca.issuer());
    // And it is the issuer of the end-entity certificate.
    let cert = Certificate::parse(&fixture("jpki-auth-cert.der")).unwrap();
    assert_eq!(cert.issuer(), ca.subject());
}

#[test]
fn the_der_round_trips() {
    let der = fixture("jpki-auth-cert.der");
    assert_eq!(Certificate::parse(&der).unwrap().der(), der.as_slice());
}

#[test]
fn rubbish_is_rejected() {
    assert!(Certificate::parse(b"not a certificate").is_err());
    let mut broken = fixture("jpki-auth-cert.der");
    broken.truncate(100);
    assert!(Certificate::parse(&broken).is_err());
}

#[test]
fn a_chain_checks_signatures_names_and_dates() {
    let auth = Certificate::parse(&fixture("jpki-auth-cert.der")).unwrap();
    let ca = Certificate::parse(&fixture("jpki-auth-ca-cert.der")).unwrap();
    let chain = [auth.clone(), ca.clone()];

    let (from, _) = auth.validity();
    Certificate::verify_chain(&chain, from).expect("the chain the card hands over");

    // Reversed, the names no longer meet.
    assert!(Certificate::verify_chain(&[ca.clone(), auth.clone()], from).is_err());
    assert!(Certificate::verify_chain(&[], from).is_err());

    // A date outside the leaf's validity is rejected even though every signature is fine.
    let (_, until) = auth.validity();
    let day_after = Date {
        year: until.year + 1,
        ..until
    };
    assert!(Certificate::verify_chain(&chain, day_after).is_err());

    // A single certificate is a chain: only its dates are checked, nothing is verified.
    Certificate::verify_chain(&[auth], from).unwrap();
}
