//! Signature checks against files read from a real card.
//!
//! Everything here uses `tests/fixtures`, which came off a JPKI test card. Hand-built data would
//! only prove the parser agrees with itself; these prove it agrees with the card.

#![cfg(feature = "verify")]

use myna_card::ap::surface::{AgeRecord, CardFace, MyNumberImage};
use myna_card::data::{CardVerifiableCertificate, ImageFormat, RsaPublicKey, Sex};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("reading {name}: {e}"))
}

/// The key that signs this application's data: the subject of the certificate in EF `0004`.
///
/// Not the card's own key — that one lives inside each record and signs challenges instead.
fn issuer_key() -> RsaPublicKey {
    CardVerifiableCertificate::parse(&fixture("surface-0004.bin"))
        .unwrap()
        .public_key
}

#[test]
fn the_certificate_carries_a_2048_bit_key() {
    let cert = CardVerifiableCertificate::parse(&fixture("surface-0004.bin")).unwrap();
    assert_eq!(cert.issuer_key_id.to_string(), "6000023/001");
    assert_eq!(cert.subject_key_id.to_string(), "1322121/000");
    assert_eq!(cert.signed_data.len(), 297);
    assert_eq!(cert.public_key.bits(), 2048);
    assert_eq!(cert.public_key.exponent, [0x01, 0x00, 0x01]);
    assert_eq!(cert.signature.len(), 256);
}

#[test]
fn the_age_record_verifies() {
    let record = AgeRecord::parse(&fixture("surface-0001.bin")).unwrap();
    assert_eq!(record.birth_date.to_string(), "1980-02-17");
    record.verify(&issuer_key()).expect("age record signature");
}

#[test]
fn the_my_number_image_verifies() {
    let record = MyNumberImage::parse(&fixture("surface-0005.bin")).unwrap();
    assert_eq!(record.image.format, ImageFormat::Png);
    record
        .verify(&issuer_key())
        .expect("my number image signature");
}

#[test]
fn the_card_face_verifies_across_its_three_segments() {
    let face = CardFace::parse(&fixture("surface-0002.bin")).unwrap();
    assert_eq!(face.birth_date.to_string(), "1980-02-17");
    assert_eq!(face.expiry.to_string(), "2035-02-17");
    assert_eq!(face.sex, Sex::Male);
    assert_eq!(face.photo.format, ImageFormat::Jpeg2000);
    face.verify(&issuer_key()).expect("card face signature");
}

#[test]
fn all_three_records_carry_the_same_card_key() {
    let age = AgeRecord::parse(&fixture("surface-0001.bin")).unwrap();
    let face = CardFace::parse(&fixture("surface-0002.bin")).unwrap();
    let image = MyNumberImage::parse(&fixture("surface-0005.bin")).unwrap();
    assert_eq!(age.public_key, face.public_key);
    assert_eq!(face.public_key, image.public_key);
    // And it is not the key that signed them.
    assert_ne!(age.public_key, issuer_key());
}

#[test]
fn a_tampered_record_does_not_verify() {
    let issuer = issuer_key();

    // Flip a bit in the signature.
    let mut record = AgeRecord::parse(&fixture("surface-0001.bin")).unwrap();
    record.signature[200] ^= 0x01;
    assert!(record.verify(&issuer).is_err());

    // Flip a bit in the data instead.
    let mut record = AgeRecord::parse(&fixture("surface-0001.bin")).unwrap();
    record.signed_data[10] ^= 0x01;
    assert!(record.verify(&issuer).is_err());

    // Change the photograph, which lives in the third signed segment of the card face.
    let mut face = CardFace::parse(&fixture("surface-0002.bin")).unwrap();
    let last = face.signed_segments[2].len() - 1;
    face.signed_segments[2][last] ^= 0x01;
    assert!(face.verify(&issuer).is_err());

    // And the first segment, which holds the card's public key.
    let mut face = CardFace::parse(&fixture("surface-0002.bin")).unwrap();
    face.signed_segments[0][0] ^= 0x01;
    assert!(face.verify(&issuer).is_err());
}

#[test]
fn the_card_key_does_not_verify_the_data_signatures() {
    // A plausible mistake, since every record carries the card's key right next to the signature.
    let record = AgeRecord::parse(&fixture("surface-0001.bin")).unwrap();
    assert!(record.verify(&record.public_key).is_err());
}

/// Card-verifiable certificates are signed by a CA key that is deliberately *not* on the card. The
/// test hierarchy keys are now in [`myna_card::ca`], recovered from pairs of certificates, so the
/// real ones can be checked end to end; a synthetic certificate signed with a key generated here
/// covers the tampering cases, where a real signature cannot be produced.
mod card_verifiable_certificates {
    use super::fixture;
    use myna_card::data::{CardVerifiableCertificate, RsaPublicKey};

    fn synthetic() -> (CardVerifiableCertificate, RsaPublicKey) {
        let cert =
            CardVerifiableCertificate::parse(&fixture("cv-certificate-synthetic.bin")).unwrap();
        let ca = RsaPublicKey::parse(&fixture("cv-ca-key-synthetic.bin")).unwrap();
        (cert, ca)
    }

    #[test]
    fn a_certificate_verifies_under_its_ca_key() {
        let (cert, ca) = synthetic();
        assert_eq!(cert.issuer_key_id.to_string(), "5000023/001");
        assert_eq!(cert.signed_data.len(), CardVerifiableCertificate::BODY_LEN);
        cert.verify_with(&ca).expect("certificate signature");
    }

    #[test]
    fn a_certificate_parses_with_or_without_its_template() {
        // Read out of an EF it comes wrapped; GET DATA hands back the contents instead.
        let wrapped = CardVerifiableCertificate::parse(&fixture("surface-0004.bin")).unwrap();
        let body = &fixture("surface-0004.bin")[5..];
        assert_eq!(CardVerifiableCertificate::parse(body).unwrap(), wrapped);

        // And the MF level fixtures, which are stored bare, parse as they are.
        let bare = CardVerifiableCertificate::parse(&fixture("mf-do-F8.bin")).unwrap();
        assert_eq!(bare.issuer_key_id.number(), "6000020");
    }

    #[test]
    fn a_chain_needs_a_key_only_for_its_root() {
        let chain = [
            CardVerifiableCertificate::parse(&fixture("mf-do-F8.bin")).unwrap(),
            CardVerifiableCertificate::parse(&fixture("mf-do-7F21.bin")).unwrap(),
        ];
        // The second names an issuer that is in no table, and still verifies as part of the chain.
        assert!(chain[1].verify().is_err());
        CardVerifiableCertificate::verify_chain(&chain).unwrap();

        // Reversed, the links no longer meet.
        let flipped = [chain[1].clone(), chain[0].clone()];
        assert!(CardVerifiableCertificate::verify_chain(&flipped).is_err());
        assert!(CardVerifiableCertificate::verify_chain(&[]).is_err());
    }

    #[test]
    fn a_tampered_certificate_does_not() {
        let (mut cert, ca) = synthetic();
        // The signature covers the key identifiers as well as the key, so changing either breaks it.
        cert.signed_data[0] ^= 0x01;
        assert!(cert.verify_with(&ca).is_err());

        let (mut cert, ca) = synthetic();
        let n = cert.signed_data.len() - 1;
        cert.signed_data[n] ^= 0x01;
        assert!(cert.verify_with(&ca).is_err());

        let (mut cert, ca) = synthetic();
        cert.signature[100] ^= 0x01;
        assert!(cert.verify_with(&ca).is_err());
    }

    #[test]
    fn the_cards_own_certificates_verify_against_the_built_in_table() {
        let (_, ca) = synthetic();
        for name in ["surface-0004.bin", "text-0004.bin", "mf-do-F8.bin"] {
            let cert = CardVerifiableCertificate::parse(&fixture(name)).unwrap();
            // A test hierarchy: the production identifiers begin "5000".
            assert!(
                cert.issuer_key_id.number().starts_with("6000"),
                "{:?}",
                cert.issuer_key_id
            );

            cert.verify().unwrap();

            // An explicit check against the wrong key still fails as a signature.
            assert!(cert.verify_with(&ca).is_err());
            // Emphatically not against the key the certificate itself carries.
            assert!(cert.verify_with(&cert.public_key).is_err());
        }
    }

    #[test]
    fn an_unknown_authority_is_not_reported_as_a_bad_signature() {
        // The intermediate that signs the second MF level certificate is not in the table — its
        // key travels in the certificate above it instead. The lookup must say so, rather than
        // claiming the signature is wrong: nothing was checked, and the two are not the same
        // answer.
        let cert = CardVerifiableCertificate::parse(&fixture("mf-do-7F21.bin")).unwrap();
        let err = cert.verify().unwrap_err();
        assert!(
            matches!(err, myna_card::Error::UnknownCertificateAuthority(_)),
            "{err}"
        );

        // It does verify under the key carried by the certificate above it, closing the chain.
        let above = CardVerifiableCertificate::parse(&fixture("mf-do-F8.bin")).unwrap();
        assert_eq!(cert.issuer_key_id, above.subject_key_id);
        cert.verify_with(&above.public_key).unwrap();
    }

    #[test]
    fn a_production_certificate_resolves_its_ca() {
        // The synthetic certificate is issued under a production identifier, so the lookup finds
        // a key — and then rejects it, because it was signed with a key generated here instead.
        let (cert, _) = synthetic();
        let named = myna_card::ca::find(&cert.issuer_key_id).expect("5000023 is in the table");
        assert_eq!(named.name(), "5000023");
        let err = cert.verify().unwrap_err();
        assert!(
            matches!(err, myna_card::Error::SignatureInvalid(_)),
            "{err}"
        );
    }
}

#[test]
fn the_ap_basic_data_carries_the_municipality_and_an_encrypted_reference_number() {
    let basic = myna_card::ap::surface::ApBasicData::parse(&fixture("surface-0003.bin")).unwrap();
    assert_eq!(basic.municipality_code, "13221");
    assert_eq!(basic.version, 0x00);
    assert_eq!(basic.public_key_id.to_string(), "6000024/001");

    // The 照合番号 is here, encrypted to a key the issuer holds — the same one on every card seen,
    // production and test alike.
    assert_eq!(
        basic.encrypted_reference_number.key_id.to_string(),
        "5900025/001"
    );
    assert_eq!(basic.encrypted_reference_number.data.len(), 256);
}

#[test]
fn filler_past_the_end_of_a_file_does_not_move_the_offsets() {
    // A file read straight off the card carries filler; `read_binary_all` trims it, but a dump
    // does not. The offset table is absolute, so a parser that measures the header by subtracting
    // the value length from the file length gets every offset wrong by the amount of filler.
    let trimmed = fixture("surface-0002.bin");
    let padded = [trimmed.clone(), vec![0xFF; 512]].concat();
    assert_eq!(
        CardFace::parse(&padded).unwrap(),
        CardFace::parse(&trimmed).unwrap()
    );
    CardFace::parse(&padded)
        .unwrap()
        .verify(&issuer_key())
        .expect("still verifies");
}
