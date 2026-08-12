//! Write the JPKI certificates that are readable without a password to DER files, and check the
//! one link that can be checked without one.
//!
//! Run with: `cargo run --example dump_certificates -- /tmp`

use std::path::PathBuf;

use myna_card::ap::jpki::JpkiAp;
use myna_card::certificate::roots::Accept;
use myna_card::{Retries, transport::pcsc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| ".".to_owned()));

    let mut card = pcsc::connect_any()?;
    let mut jpki = JpkiAp::select(&mut card)?;

    // Tells a card apart from the mobile certificate in a phone, which speaks the same protocol.
    println!("token: {:?}", jpki.read_token_type()?);

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

    let auth = jpki.read_auth_certificate()?;
    let ca = jpki.read_auth_ca_certificate()?;
    println!("\nsubject: {}", auth.subject());
    println!("issuer:  {}", auth.issuer());
    let (from, until) = auth.validity();
    println!("valid:   {from} to {until}");

    // Two checks that look alike. The first ends at a certificate that came off the same card, so
    // it establishes internal consistency and nothing else. The second ends at a root the crate
    // carries, which the card had no say in — that is the one that means something.
    let say = |result: Result<(), myna_card::Error>| match result {
        Ok(()) => "yes".to_owned(),
        Err(err) => format!("no ({err})"),
    };
    println!(
        "signed by the CA certificate on the card: {}",
        say(auth.verify_signature(&ca))
    );
    println!(
        "reaches a published root:                {}",
        say(auth.verify_to_root(from, Accept::ProductionOnly))
    );
    // A test card reaches none, and asking for the test hierarchy is how you say so out loud.
    // Never do this where the answer decides whether to believe a cardholder.
    println!(
        "reaches a root incl. the test hierarchy: {}",
        say(auth.verify_to_root(from, Accept::ProductionAndTest))
    );

    match jpki.auth_pin_retries()? {
        Retries::Remaining(n) => println!("authentication PIN: {n} attempt(s) remaining"),
        Retries::Blocked => println!("authentication PIN: blocked"),
        Retries::Unlimited => println!("authentication PIN: no retry limit"),
        Retries::NotReported => println!("authentication PIN: counter not reported"),
    }

    Ok(())
}
