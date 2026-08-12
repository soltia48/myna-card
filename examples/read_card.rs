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
//! Everything read is also checked. The 券面 applications each carry a card-verifiable certificate
//! whose CA key is *not* on the card, so it is resolved from the table in `myna_card::ca`; the
//! records are then checked against the key that certificate certifies. Both steps matter: the
//! first says the data came from an issuer, the second says it belongs to this data.

use std::collections::HashMap;

use myna_card::ap::{common::CommonAp, jpki::JpkiAp, surface::SurfaceAp, text::TextAp};
use myna_card::{Pin, Retries, transport::pcsc};

/// The printable part of a 16 byte key identifier: seven digits, then the three digit group.
fn key_id(id: &[u8]) -> String {
    format!(
        "{}/{}",
        String::from_utf8_lossy(&id[..7]),
        String::from_utf8_lossy(&id[9..12])
    )
}

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

    let mut card = pcsc::connect_any()?;

    println!("== 共通カードAP ==");
    {
        let mut common = CommonAp::select(&mut card)?;
        let info = common.read_card_info()?;
        println!("  serial       {}", info.serial);
        println!(
            "  municipality {} (prefecture {})",
            info.municipality_code,
            info.prefecture_code()
        );
        println!("  expires      {}", info.expiry);
    }

    println!("\n== 券面入力補助AP ==");
    {
        let mut text = TextAp::select(&mut card)?;
        let cert = text.read_certificate()?;
        println!(
            "  certificate  被証明者鍵ID {}, issued under {}  [{}]",
            key_id(&cert.subject_key_id),
            key_id(&cert.issuer_key_id),
            outcome(cert.verify())
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
            key_id(&cert.subject_key_id),
            key_id(&cert.issuer_key_id),
            outcome(cert.verify())
        );
        let issuer = &cert.public_key;

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
        // One link only, and both ends came off the same card, so this says the CA certificate in
        // EF 000B signed the one in EF 000A — not that either is genuine.
        let auth = jpki.read_auth_certificate()?;
        let ca = jpki.read_auth_ca_certificate()?;
        println!(
            "  chain        auth <- auth-ca [{}]",
            outcome(auth.verify_signature(&ca))
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
