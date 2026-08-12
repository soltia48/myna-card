//! Read and decode everything the card will hand over for a given set of credentials.
//!
//! ```sh
//! cargo run --example read_card -- --pin 1234 --code-a 537686677188 --out /tmp
//! ```
//!
//! Every credential is optional; without one, the files it guards are skipped. Nothing here
//! guesses: a value is only ever presented to the key it belongs to, so no retry counter is
//! spent on a wrong attempt.

use std::collections::HashMap;

use myna_card::ap::{common::CommonAp, jpki::JpkiAp, surface::SurfaceAp, text::TextAp};
use myna_card::{Pin, Retries, transport::pcsc};

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
            "  certificate  被証明者鍵ID {:?}, issued under {:?}",
            String::from_utf8_lossy(&cert.subject_key_id).trim_end_matches('\0'),
            String::from_utf8_lossy(&cert.issuer_key_id).trim_end_matches('\0')
        );

        if let Some(pin) = get("pin") {
            text.verify_pin(&Pin::numeric(pin)?)?;
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
        } else {
            println!("  (pass --pin to read the 個人番号 and 基本4情報)");
        }
    }

    println!("\n== 券面事項確認AP ==");
    {
        let mut surface = SurfaceAp::select(&mut card)?;
        if let Some(dob) = get("birth-date") {
            surface.verify_birth_date(&Pin::numeric(dob)?)?;
            // The age verification record: the one field this credential is meant to reveal.
            println!(
                "  年齢確認     生年月日 {}",
                surface.read_age_record()?.birth_date
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
                "  券面         生年月日 {}, 有効期限 {}, 性別 {:?}",
                face.birth_date, face.expiry, face.sex
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
        for (label, der) in [
            ("auth", jpki.read_auth_certificate_der()?),
            ("auth-ca", jpki.read_auth_ca_certificate_der()?),
        ] {
            let path = out.join(format!("{label}.der"));
            std::fs::write(&path, &der)?;
            println!("  {label:<12} {} bytes -> {}", der.len(), path.display());
        }
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
