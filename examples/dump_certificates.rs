//! Write the JPKI certificates that are readable without a password to DER files.
//!
//! Run with: `cargo run --example dump_certificates -- /tmp`

use std::path::PathBuf;

use myna_card::ap::jpki::JpkiAp;
use myna_card::transport::pcsc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| ".".to_owned()));

    let mut card = pcsc::connect_any()?;
    let mut jpki = JpkiAp::select(&mut card)?;

    // The signature certificate is deliberately not dumped here: reading it needs the signature
    // password, and a wrong guess costs one of five attempts.
    for (name, der) in [
        ("auth_certificate.der", jpki.read_auth_certificate_der()?),
        (
            "auth_ca_certificate.der",
            jpki.read_auth_ca_certificate_der()?,
        ),
    ] {
        let path = out_dir.join(name);
        std::fs::write(&path, &der)?;
        println!("{}: {} bytes", path.display(), der.len());
    }

    use myna_card::Retries;
    match jpki.auth_pin_retries()? {
        Retries::Remaining(n) => println!("authentication PIN: {n} attempt(s) remaining"),
        Retries::Blocked => println!("authentication PIN: blocked"),
        Retries::Unlimited => println!("authentication PIN: no retry limit"),
        Retries::NotReported => println!("authentication PIN: counter not reported"),
    }

    Ok(())
}
