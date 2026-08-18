//! 券面入力補助AP's signature records, and the certificate chain, against real card data.

#![cfg(feature = "verify")]

use myna_card::Certificate;
use myna_card::ap::text::{ApBasicData, IntegrityRecord, SessionKeyPublicKey, SignedPublicKey};
use myna_card::data::CardVerifiableCertificate;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("reading {name}: {e}"))
}

fn issuer_key() -> myna_card::data::RsaPublicKey {
    CardVerifiableCertificate::parse(&fixture("text-0004.bin"))
        .unwrap()
        .public_key
}

#[test]
fn the_integrity_record_verifies() {
    let record = IntegrityRecord::parse(&fixture("text-0003.bin")).unwrap();
    record
        .verify(&issuer_key())
        .expect("integrity record signature");
}

#[test]
fn the_integrity_record_vouches_for_the_my_number_file() {
    let record = IntegrityRecord::parse(&fixture("text-0003.bin")).unwrap();
    let physical = fixture("text-0001-physical.bin");

    // The digest covers the file as stored: a 15 byte object plus two filler bytes.
    assert_eq!(physical.len(), 17);
    assert!(record.matches_my_number_file(&physical));

    // Trimming to the TLV, which is what `read_binary_all` returns, does not match — the reason
    // `Card::read_binary_physical` exists.
    assert!(!record.matches_my_number_file(&physical[..15]));
}

#[test]
fn the_integrity_record_vouches_for_the_attributes_file() {
    let record = IntegrityRecord::parse(&fixture("text-0003.bin")).unwrap();
    let attributes = fixture("text-0002.bin");

    assert!(record.matches_attributes_file(&attributes).unwrap());

    // This digest skips the offset table, so it is not a digest of the file — the two obvious
    // guesses both fail.
    use myna_card::data::sha256;
    assert_ne!(sha256(&attributes), record.attributes_digest);
    assert_ne!(sha256(&attributes[3..]), record.attributes_digest);

    // And it is not the rule the 個人番号 file follows either.
    let my_number = fixture("text-0001-physical.bin");
    assert!(record.matches_my_number_file(&my_number));
    assert!(!record.matches_attributes_file(&my_number).unwrap_or(false));
}

#[test]
fn a_changed_attribute_breaks_the_digest() {
    let record = IntegrityRecord::parse(&fixture("text-0003.bin")).unwrap();
    let mut attributes = fixture("text-0002.bin");
    let n = attributes.len() - 1; // 性別, the last field
    attributes[n] ^= 0x01;
    assert!(!record.matches_attributes_file(&attributes).unwrap());

    // Touching the offset table does not, because the digest starts after it.
    let mut attributes = fixture("text-0002.bin");
    attributes[7] ^= 0x01;
    assert!(record.matches_attributes_file(&attributes).unwrap());
}

#[test]
fn the_signing_key_record_verifies_and_is_a_different_key() {
    let signed = SignedPublicKey::parse(&fixture("text-0007.bin")).unwrap();
    signed
        .verify(&issuer_key())
        .expect("signed public key signature");
    assert_eq!(signed.public_key.bits(), 2048);

    // EF 0006 holds a third key, for encrypting a session key to the card. It signs nothing, so
    // it must be neither the card's signing key nor the issuer's.
    let session = SessionKeyPublicKey::parse(&fixture("text-0006.bin")).unwrap();
    assert_ne!(session.public_key, signed.public_key);
    assert_ne!(session.public_key, issuer_key());
}

#[test]
fn tampering_is_caught() {
    let issuer = issuer_key();

    let mut record = IntegrityRecord::parse(&fixture("text-0003.bin")).unwrap();
    record.signed_data[5] ^= 0x01;
    assert!(record.verify(&issuer).is_err());

    let mut signed = SignedPublicKey::parse(&fixture("text-0007.bin")).unwrap();
    signed.signature[0] ^= 0x01;
    assert!(signed.verify(&issuer).is_err());

    // A digest that does not cover the file it is checked against.
    let record = IntegrityRecord::parse(&fixture("text-0003.bin")).unwrap();
    let mut physical = fixture("text-0001-physical.bin");
    physical[16] ^= 0x01; // the filler, which the digest does cover
    assert!(!record.matches_my_number_file(&physical));
}

#[test]
fn the_certificate_chain_links() {
    let ee = Certificate::parse(&fixture("jpki-auth-cert.der")).unwrap();
    let ca = Certificate::parse(&fixture("jpki-auth-ca-cert.der")).unwrap();
    ee.verify_signature(&ca)
        .expect("end entity signed by its CA");
    ca.verify_signature(&ca).expect("CA is self-signed");

    // The wrong issuer is rejected, and so is a certificate checked against itself.
    assert!(ee.verify_signature(&ee).is_err());
    let sign = Certificate::parse(&fixture("jpki-sign-cert.der")).unwrap();
    assert!(sign.verify_signature(&ca).is_err());
}

#[test]
fn the_ap_basic_data_names_a_key_that_is_not_the_signing_key() {
    let basic = ApBasicData::parse(&fixture("text-0005.bin")).unwrap();
    assert_eq!(basic.identification, [0x01, 0x03, 0x0E, 0x01]);
    assert_eq!(basic.public_key_id.to_string(), "6000034/001");

    // Not the key EF 0004 certifies.
    let cert =
        myna_card::data::CardVerifiableCertificate::parse(&fixture("text-0004.bin")).unwrap();
    assert_ne!(basic.public_key_id, cert.subject_key_id);

    // 32 bytes then filler, on every card seen.
    assert_eq!(basic.trailing.len(), 128);
    assert_eq!(basic.digest().unwrap().len(), 32);
}
