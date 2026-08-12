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

mod published_roots {
    use myna_card::Certificate;
    use myna_card::certificate::roots::{self, Accept, Hierarchy, Purpose};
    use myna_card::data::Date;

    #[test]
    fn every_root_parses_and_signs_itself() {
        assert_eq!(roots::KNOWN.len(), 10);
        for root in roots::KNOWN {
            let cert = root.certificate().expect("parses");
            // Self-signed, checked with this crate's verifier rather than assumed.
            assert_eq!(cert.subject(), cert.issuer());
            cert.verify_signature(&cert).expect("self-signature");
            assert_eq!(cert.public_key().unwrap().bits(), 2048);

            // The name says which certificate on the card it is for.
            let wanted = match root.purpose {
                Purpose::UserAuthentication => "JPKI for user authentication",
                Purpose::DigitalSignature => "JPKI for digital signature",
            };
            assert!(cert.subject().contains(wanted), "{}", cert.subject());
            let org = match root.hierarchy {
                Hierarchy::Production => "O=JPKI,",
                Hierarchy::Test => "O=JPKI-TEST,",
            };
            assert!(cert.subject().contains(org), "{}", cert.subject());
        }
    }

    #[test]
    fn the_generations_are_distinct_and_the_published_ones_are_in_order() {
        use myna_card::certificate::roots::Purpose;
        for purpose in [Purpose::UserAuthentication, Purpose::DigitalSignature] {
            // J-LIS numbers the production roots, so the list can be checked against that: the
            // numbers run 1, 2, 3 and the validity periods run the same way.
            let published: Vec<_> = roots::KNOWN
                .iter()
                .filter(|r| r.purpose == purpose && r.hierarchy == Hierarchy::Production)
                .collect();
            assert_eq!(
                published.iter().map(|r| r.generation).collect::<Vec<_>>(),
                vec![Some(1), Some(2), Some(3)]
            );
            let mut previous: Option<Date> = None;
            for root in &published {
                let (from, to) = root.certificate().unwrap().validity();
                assert!(from < to);
                if let Some(earlier) = previous {
                    assert!(earlier < from);
                }
                previous = Some(from);
            }

            // The test roots carry no number, because there is no published list to number them
            // against. Only that they are valid periods and distinct certificates is claimed.
            for root in roots::KNOWN
                .iter()
                .filter(|r| r.purpose == purpose && r.hierarchy == Hierarchy::Test)
            {
                assert_eq!(root.generation, None);
                let (from, to) = root.certificate().unwrap().validity();
                assert!(from < to);
            }
        }

        // Ten distinct keys, not one key repeated.
        let mut moduli: Vec<Vec<u8>> = roots::KNOWN
            .iter()
            .map(|r| r.certificate().unwrap().public_key().unwrap().modulus)
            .collect();
        moduli.sort();
        moduli.dedup();
        assert_eq!(moduli.len(), roots::KNOWN.len());
    }

    #[test]
    fn a_test_card_needs_the_test_hierarchy_to_be_asked_for() {
        // The card surveyed is a JPKI test card. Under the production-only setting the answer has
        // to be "no root signed this" — not a crash, and above all not an accept.
        let cert = Certificate::parse(&super::fixture("jpki-auth-cert.der")).unwrap();
        let (from, _) = cert.validity();
        assert!(roots::issuer_of(&cert, Accept::ProductionOnly).is_err());
        assert!(cert.verify_to_root(from, Accept::ProductionOnly).is_err());

        // Asked for explicitly, it resolves — to the test root, which is the one that signed it.
        let root = roots::issuer_of(&cert, Accept::ProductionAndTest).expect("test root");
        assert!(root.subject().contains("O=JPKI-TEST"));
        cert.verify_to_root(from, Accept::ProductionAndTest)
            .unwrap();
    }

    #[test]
    fn the_embedded_test_roots_are_the_bytes_the_card_returned() {
        // certs/test/ and tests/fixtures/ hold the same certificates; this stops them drifting.
        for (embedded, fixture) in [
            ("O=JPKI-TEST,C=JP", "jpki-auth-ca-cert.der"),
            ("O=JPKI-TEST,C=JP", "jpki-sign-ca-cert.der"),
            ("O=JPKI-TEST,C=JP", "jpki-auth-ca-cert-2019.der"),
            ("O=JPKI-TEST,C=JP", "jpki-sign-ca-cert-2019.der"),
        ] {
            let der = super::fixture(fixture);
            assert!(
                roots::KNOWN.iter().any(|r| r.der == der),
                "{fixture} is not among the embedded roots ({embedded})"
            );
        }
    }
}

mod the_cards_own_authority {
    use super::fixture;
    use myna_card::Certificate;
    use myna_card::certificate::roots::{self, Accept, Hierarchy};

    fn cas() -> (Certificate, Certificate) {
        (
            Certificate::parse(&fixture("jpki-auth-ca-cert.der")).unwrap(),
            Certificate::parse(&fixture("jpki-sign-ca-cert.der")).unwrap(),
        )
    }

    #[test]
    fn both_are_self_signed_roots_of_the_test_hierarchy() {
        for ca in [cas().0, cas().1] {
            assert_eq!(ca.subject(), ca.issuer());
            ca.verify_signature(&ca).expect("self-signature");
            assert!(ca.subject().contains("O=JPKI-TEST"), "{}", ca.subject());
            assert_eq!(ca.public_key().unwrap().bits(), 2048);
        }
    }

    #[test]
    fn each_leaf_verifies_under_its_own_authority_and_not_the_other() {
        let (auth_ca, sign_ca) = cas();
        let auth = Certificate::parse(&fixture("jpki-auth-cert.der")).unwrap();
        let sign = Certificate::parse(&fixture("jpki-sign-cert.der")).unwrap();

        auth.verify_signature(&auth_ca).expect("利用者証明用");
        sign.verify_signature(&sign_ca).expect("署名用");

        // The two hierarchies are separate all the way up; crossing them must fail.
        assert!(auth.verify_signature(&sign_ca).is_err());
        assert!(sign.verify_signature(&auth_ca).is_err());
    }

    #[test]
    fn two_generations_share_a_name_and_only_the_signature_tells_them_apart() {
        // A second test card, issued five years earlier, carries CA certificates with the *same*
        // distinguished name and different keys. Picking an issuer by name alone would pick the
        // wrong one half the time.
        let (auth_ca, sign_ca) = cas();
        let older_auth = Certificate::parse(&fixture("jpki-auth-ca-cert-2019.der")).unwrap();
        let older_sign = Certificate::parse(&fixture("jpki-sign-ca-cert-2019.der")).unwrap();

        for (newer, older) in [(&auth_ca, &older_auth), (&sign_ca, &older_sign)] {
            assert_eq!(newer.subject(), older.subject());
            assert_ne!(newer.der(), older.der());
            assert_ne!(
                newer.public_key().unwrap().modulus,
                older.public_key().unwrap().modulus
            );
            older.verify_signature(older).expect("self-signature");
        }

        // This card's leaf is issued by this card's CA, not by the same-named older one.
        let auth = Certificate::parse(&fixture("jpki-auth-cert.der")).unwrap();
        auth.verify_signature(&auth_ca).expect("its own CA");
        assert!(auth.verify_signature(&older_auth).is_err());
    }

    #[test]
    fn every_generation_of_a_root_shares_one_name() {
        // Which is why `issuer_of` narrows by name and then decides by signature. Four groups —
        // two purposes times two hierarchies — and one distinguished name each.
        use myna_card::certificate::roots::Purpose;
        let mut groups = 0;
        for purpose in [Purpose::UserAuthentication, Purpose::DigitalSignature] {
            for hierarchy in [Hierarchy::Production, Hierarchy::Test] {
                let mut names: Vec<String> = roots::KNOWN
                    .iter()
                    .filter(|r| r.purpose == purpose && r.hierarchy == hierarchy)
                    .map(|r| r.certificate().unwrap().subject())
                    .collect();
                assert!(names.len() >= 2, "expected several generations");
                names.dedup();
                assert_eq!(names.len(), 1, "{purpose:?} {hierarchy:?}");
                groups += 1;
            }
        }
        assert_eq!(groups, 4);
    }

    #[test]
    fn a_root_off_the_card_is_not_a_published_root() {
        // The whole reason `certs/` exists: these two verify their own leaves perfectly well and
        // still anchor nothing, because they came off the card being checked.
        let (auth_ca, sign_ca) = cas();
        for ca in [&auth_ca, &sign_ca] {
            assert!(
                !roots::KNOWN
                    .iter()
                    .any(|r| r.der == ca.der() && r.hierarchy == Hierarchy::Production)
            );
            assert!(roots::issuer_of(ca, Accept::ProductionOnly).is_err());
        }
    }
}
