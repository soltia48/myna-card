//! Read and decode everything the card will hand over for a given set of credentials.
//!
//! ```sh
//! cargo run --example read_card -- --pin 1234 --birth-date 550217 \
//!     --code-a 537686677188 --out /tmp
//! ```
//!
//! Options: `--pin`, `--birth-date` (和暦 `YYMMDD`), `--code-a`, `--code-b`, `--out`. Every
//! credential is optional; without one, the files it guards are skipped. Nothing here guesses: a
//! value is only ever presented to the key it belongs to, so no retry counter is spent on a wrong
//! attempt.
//!
//! Everything read is also checked, and the output distinguishes two things that look alike. The
//! 券面 applications each carry a card-verifiable certificate whose CA key is *not* on the card, so
//! it is resolved from the table in `myna_card::ca` and the records are then checked against the
//! key that certificate certifies. The 公的個人認証AP's certificates can be checked twice over:
//! against the CA certificate the card hands over, which only says the card is self-consistent,
//! and against a root the crate carries, which the card had no say in.

use std::collections::HashMap;

use myna_card::Certificate;
use myna_card::ap::jpki::SignatureScheme;
use myna_card::ap::{common::CommonAp, jpki::JpkiAp, surface::SurfaceAp, text::TextAp};
use myna_card::certificate::roots::Accept;
use myna_card::data::CardVerifiableCertificate;
use myna_card::mf::{self, MasterFile};
use myna_card::transport::pcsc::Sharing;
use myna_card::{Pin, Retries, transport::pcsc};

/// Render a check as a short tag, so a failure is visible without stopping the run.
fn outcome(result: Result<(), myna_card::Error>) -> String {
    match result {
        Ok(()) => "verified".to_owned(),
        Err(err) => format!("{err}"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: HashMap<String, String> = HashMap::new();
    let mut rest = std::env::args().skip(1);
    while let (Some(k), Some(v)) = (rest.next(), rest.next()) {
        args.insert(k.trim_start_matches("--").to_owned(), v);
    }
    let get = |k: &str| args.get(k).map(String::as_str);
    let out = std::path::PathBuf::from(get("out").unwrap_or("."));
    // Kept so the 券面事項確認AP can be checked against it: two files, one municipality code,
    // and nothing signs either of them.
    let municipality;

    let mut card = pcsc::connect_any(Sharing::Shared)?;

    // The master file level answers only while no application is selected, so it goes first — and
    // a power cycle is what puts the card back in that state.
    println!("== master file ==");
    {
        card.transport_mut().power_cycle()?;
        let mut mf = MasterFile::new(&mut card);
        println!(
            "  card number  {}",
            String::from_utf8_lossy(&mf.data_object(mf::tag::CARD_IDENTIFICATION)?)
                .trim_matches(|c: char| !c.is_ascii_graphic())
                .to_owned()
        );
        let chain = mf.certificate_chain()?;
        for (index, cert) in chain.iter().enumerate() {
            println!(
                "  chain[{index}]     {} -> {}",
                cert.issuer_key_id, cert.subject_key_id
            );
        }
        // Only the root needs a key from the table; the rest chain off it.
        println!(
            "  chain        [{}]",
            outcome(CardVerifiableCertificate::verify_chain(&chain))
        );
    }

    println!("\n== 共通カードAP ==");
    {
        let mut common = CommonAp::select(&mut card)?;
        // Answers here on some cards and at the master file level on others.
        let atr = common.card().contact_atr()?;
        println!(
            "  contact ATR  {}",
            atr.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let info = common.read_card_info()?;
        println!("  serial       {}", info.serial);
        println!(
            "  municipality {} (prefecture {})",
            info.municipality_code,
            info.prefecture_code()
        );
        println!("  expires      {}", info.expiry);
        municipality = info.municipality_code.clone();
    }

    println!("\n== 券面入力補助AP ==");
    {
        let mut text = TextAp::select(&mut card)?;
        let cert = text.read_certificate()?;
        println!(
            "  certificate  被証明者鍵ID {}, issued under {}  [{}]",
            cert.subject_key_id,
            cert.issuer_key_id,
            outcome(cert.verify())
        );

        // Free to read. The key it names is not the one the certificate above certifies, and
        // what it is for is not established.
        let basic = text.read_ap_basic_data()?;
        println!(
            "  AP basic     names key {}, {} B trailing",
            basic.public_key_id,
            basic.trailing.len()
        );

        if let Some(pin) = get("pin") {
            text.verify_pin(&Pin::numeric(pin)?)?;

            // Signed by the key the certificate certifies, and gated on the same credential.
            let signed_key = text.read_signed_public_key()?;
            println!(
                "  signed key   {} bit  [{}]",
                signed_key.public_key.bits(),
                outcome(signed_key.verify(&cert.public_key))
            );

            println!("  個人番号     {}", text.read_my_number()?.as_str());
            let a = text.read_attributes()?;
            println!("  氏名         {}", a.name);
            println!("  住所         {}", a.address);
            println!(
                "  生年月日     {}{}",
                a.birth_date,
                match a.birth_date.to_era() {
                    Some((era, year)) => format!(" ({}{}年)", era.name(), year),
                    None => String::new(),
                }
            );
            println!("  性別         {:?}", a.sex);

            // EF 0003 signs a digest of each of the two files above, so it ties them together.
            let integrity = text.read_integrity_record()?;
            let my_number_file = text.read_my_number_file()?;
            let attributes_file = text.read_ef(myna_card::ap::text::ef::ATTRIBUTES)?;
            println!(
                "  integrity    signature [{}], 個人番号 digest [{}], 基本4情報 digest [{}]",
                outcome(integrity.verify(&cert.public_key)),
                if integrity.matches_my_number_file(&my_number_file) {
                    "ok"
                } else {
                    "MISMATCH"
                },
                match integrity.matches_attributes_file(&attributes_file) {
                    Ok(true) => "ok",
                    Ok(false) => "MISMATCH",
                    Err(_) => "unreadable",
                }
            );
        } else {
            println!("  (pass --pin to read the 個人番号 and 基本4情報)");
        }
    }

    println!("\n== 券面事項確認AP ==");
    {
        let mut surface = SurfaceAp::select(&mut card)?;
        let cert = surface.read_certificate()?;
        println!(
            "  certificate  被証明者鍵ID {}, issued under {}  [{}]",
            cert.subject_key_id,
            cert.issuer_key_id,
            outcome(cert.verify())
        );
        let issuer = &cert.public_key;

        // Also free to read, and it repeats the municipality code. Neither copy is independently
        // authenticated here, so the agreement is only a consistency check.
        let basic = surface.read_ap_basic_data()?;
        println!(
            "  AP basic     municipality {}{}, DF35 key reference {}",
            basic.municipality_code,
            if municipality == basic.municipality_code {
                " (agrees with 共通カードAP)"
            } else {
                " (DISAGREES with 共通カードAP)"
            },
            basic.encrypted_reference_number.key_id
        );

        if let Some(dob) = get("birth-date") {
            surface.verify_birth_date(&Pin::numeric(dob)?)?;
            // The age verification record: the one field this credential is meant to reveal.
            let age = surface.read_age_record()?;
            println!(
                "  年齢確認     生年月日 {}  [{}]",
                age.birth_date,
                outcome(age.verify(issuer))
            );
        }
        if let Some(code) = get("code-a").or_else(|| get("code-b")) {
            let pin = Pin::numeric(code)?;
            if get("code-a").is_some() {
                surface.verify_code_a(&pin)?;
            } else {
                surface.verify_code_b(&pin)?;
            }
            let face = surface.read_card_face()?;
            println!(
                "  券面         生年月日 {}, 有効期限 {}, 性別 {:?}  [{}]",
                face.birth_date,
                face.expiry,
                face.sex,
                outcome(face.verify(issuer))
            );
            for (label, image) in [
                ("name", &face.name_image),
                ("address", &face.address_image),
                ("photo", &face.photo),
            ] {
                let path = out.join(format!("{label}.{}", image.format.extension()));
                std::fs::write(&path, &image.data)?;
                println!(
                    "  {label:<12} {:?}, {} bytes -> {}",
                    image.format,
                    image.data.len(),
                    path.display()
                );
            }
            // The record proves the data is authentic; a fresh signature proves the card that
            // holds the matching private key is the one in the reader right now.
            let challenge = surface.card().get_challenge(16)?;
            let signature = surface.sign(&challenge)?;
            println!(
                "  challenge    16 bytes signed by the card key  [{}]",
                outcome(SignatureScheme::Sha256DigestInfo.verify(
                    &face.public_key,
                    &challenge,
                    &signature
                ))
            );

            if get("code-a").is_some() {
                let n = surface.read_my_number_image()?;
                println!("  my-number    signature [{}]", outcome(n.verify(issuer)));
                let path = out.join(format!("my-number.{}", n.image.format.extension()));
                std::fs::write(&path, &n.image.data)?;
                println!(
                    "  my-number    {:?}, {} bytes -> {}",
                    n.image.format,
                    n.image.data.len(),
                    path.display()
                );
            }
        }
    }

    println!("\n== 公的個人認証AP ==");
    {
        let mut jpki = JpkiAp::select(&mut card)?;
        println!("  token        {:?}", jpki.read_token_type()?);
        for (label, der) in [
            ("auth", jpki.read_auth_certificate_der()?),
            ("auth-ca", jpki.read_auth_ca_certificate_der()?),
        ] {
            let path = out.join(format!("{label}.der"));
            std::fs::write(&path, &der)?;
            println!("  {label:<12} {} bytes -> {}", der.len(), path.display());
        }
        // Two checks that look alike and are not. The first ends at the CA certificate in EF
        // 000B — the same card, so it says only that the card is internally consistent. The
        // second ends at a root the crate carries, which the card had no say in.
        let chain = [
            jpki.read_auth_certificate()?,
            jpki.read_auth_ca_certificate()?,
        ];
        let (issued, _) = chain[0].validity();
        println!(
            "  card's CA    auth <- auth-ca  [{}]",
            outcome(Certificate::verify_chain(&chain, issued))
        );
        println!(
            "  to a root    production only  [{}]",
            outcome(chain[0].verify_to_root(issued, Accept::ProductionOnly))
        );
        // A test card reaches no published root; asking for the test hierarchy is how you say so
        // out loud. Never do this where the answer decides whether to believe a cardholder.
        println!(
            "               test accepted   [{}]",
            outcome(chain[0].verify_to_root(issued, Accept::ProductionAndTest))
        );

        // Reported, never guessed at: an empty VERIFY costs nothing.
        for (label, r) in [
            ("利用者証明用", jpki.auth_pin_retries()?),
            ("署名用", jpki.sign_pin_retries()?),
        ] {
            println!(
                "  {label} retries {}",
                match r {
                    Retries::Remaining(n) => n.to_string(),
                    Retries::Blocked => "blocked".into(),
                    Retries::Unlimited => "unlimited".into(),
                    Retries::NotReported => "not reported".into(),
                }
            );
        }
    }

    Ok(())
}
