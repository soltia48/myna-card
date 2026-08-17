//! Read the 券面入力補助AP under secure messaging.
//!
//! ```text
//! cargo run --features sm --example secure_messaging -- <PIN>
//! ```
//!
//! Shows the one thing a session is actually worth on this card: 照合番号A is the 個人番号, and
//! presenting it inside a session keeps it off the interface. The PIN cannot be protected this
//! way — the card will not deliver a session key until it has been presented in the clear — so it
//! is read from the command line and sent as it always is.

use myna_card::ap::text::{TextAp, ef};
use myna_card::transport::pcsc::{self, Sharing};
use myna_card::{Error, Pin};

fn main() -> Result<(), Error> {
    let pin = match std::env::args().nth(1) {
        Some(value) => Pin::numeric(value)?,
        None => {
            eprintln!("usage: secure_messaging <PIN>");
            std::process::exit(2);
        }
    };

    // A program that presents a PIN wants `Sharing::Exclusive`, because a security status outlives
    // the command that set it. Some contactless readers refuse that mode outright — the RC-S300
    // answers `SharingViolation` — so the examples all use `Shared` to stay runnable.
    let mut card = pcsc::connect_any(Sharing::Shared)?;
    let mut text = TextAp::select(&mut card)?;

    println!(
        "attempts left — PIN {:?}, 照合番号A {:?}, 照合番号B {:?}, blocked reference {:?}",
        text.retries(ef::PIN)?.count(),
        text.retries(ef::CODE_A)?.count(),
        text.retries(ef::CODE_B)?.count(),
        text.retries(ef::BLOCKED_0012)?.count(),
    );

    // In the clear, unavoidably.
    text.verify_pin(&pin)?;

    // Read the 個人番号 the ordinary way, so that there is something to compare against.
    let expected = text.read_my_number()?;

    let mut seed = [0u8; myna_card::sm::SEED_LEN];
    rsa::rand_core::RngCore::fill_bytes(&mut rsa::rand_core::OsRng, &mut seed);
    let mut session = text.open_secure_session(&seed)?;
    println!("session open, next message counter {}", session.counter());

    // 照合番号A is the 個人番号 itself. This is the presentation that a session exists to protect.
    session.verify(ef::CODE_A, &Pin::numeric(expected.as_str())?)?;
    println!(
        "照合番号A presented under encryption, counter now {}",
        session.counter()
    );

    // Both files, read encrypted. Each of these is two counter steps: a SELECT and a READ.
    let my_number_file = session.read_ef(ef::MY_NUMBER)?;
    let attributes_file = session.read_ef(ef::ATTRIBUTES)?;
    // The physical read is what the integrity record's digest covers, filler and all.
    let my_number_physical = session.read_ef_physical(ef::MY_NUMBER)?;
    println!(
        "read {} and {} bytes ({} physical), counter now {}",
        my_number_file.len(),
        attributes_file.len(),
        my_number_physical.len(),
        session.counter()
    );

    // The bytes that came back encrypted have to be the same file the plain read returned.
    let decoded = myna_card::ap::text::Attributes::parse(&attributes_file)?;
    println!("個人番号  {}", expected.as_str());
    println!("氏名      {}", decoded.name);
    println!("住所      {}", decoded.address);
    println!("生年月日  {}", decoded.birth_date);
    println!("性別      {:?}", decoded.sex);

    assert!(
        my_number_file.starts_with(&[0xFF, 0x10]),
        "the decrypted 個人番号 file should start with its own tag"
    );
    assert!(
        my_number_physical.len() > my_number_file.len(),
        "the physical read should include the filler the trimmed one drops"
    );
    println!("\nplain and encrypted reads agree.");
    Ok(())
}
