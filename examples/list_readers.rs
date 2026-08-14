//! Print the available PC/SC readers and, if a card is present, say what it is.
//!
//! Run with: `cargo run --example list_readers`

use myna_card::ap::common::CommonAp;
use myna_card::ap::jpki::JpkiAp;
use myna_card::transport::pcsc;

fn main() -> Result<(), myna_card::Error> {
    let readers = pcsc::list_readers()?;
    if readers.is_empty() {
        println!("no PC/SC reader found");
        return Ok(());
    }
    for (index, reader) in readers.iter().enumerate() {
        println!("[{index}] {reader}");
    }
    println!();

    // A reader with nothing on it, or with something that is not an Individual Number Card, is an
    // ordinary outcome here rather than an error — so say which it is instead of failing.
    let mut card = match pcsc::connect_any() {
        Ok(card) => card,
        Err(err) => {
            println!("no card to talk to: {err}");
            return Ok(());
        }
    };

    match JpkiAp::select(&mut card).and_then(|mut jpki| jpki.read_token_type()) {
        Ok(token) => println!("token        {token:?}"),
        Err(err) => {
            println!("this does not answer as an Individual Number Card: {err}");
            return Ok(());
        }
    }

    let mut common = CommonAp::select(&mut card)?;
    let info = common.read_card_info()?;
    println!("serial       {}", info.serial);
    println!(
        "municipality {} (prefecture {})",
        info.municipality_code,
        info.prefecture_code()
    );
    println!("expires      {}", info.expiry);

    Ok(())
}
