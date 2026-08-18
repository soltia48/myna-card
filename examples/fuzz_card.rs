//! Read-only probes for exploring a physical Individual Number Card.
//!
//! This example intentionally exposes no arbitrary-APDU mode. Its command set is limited to
//! SELECT FILE, GET DATA and an empty VERIFY, so running it cannot guess a PIN or invoke a
//! command that writes persistent state.
//!
//! ```text
//! cargo run --example fuzz_card -- baseline
//! cargo run --example fuzz_card -- default-df-state
//! cargo run --example fuzz_card -- scan-aid-roots
//! cargo run --example fuzz_card -- select-prefix D392
//! cargo run --example fuzz_card -- enumerate-aids D392 12
//! cargo run --example fuzz_card -- enumerate-occurrences D3
//! ```

use std::collections::VecDeque;

use myna_card::ap::{DEFAULT_DF, common, jpki, juki, surface, text};
use myna_card::transport::pcsc::{self, Sharing};
use myna_card::{Card, Command, Retries, StatusWord};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("baseline") => baseline()?,
        Some("default-df-state") => default_df_state()?,
        Some("scan-aid-roots") => scan_aid_roots()?,
        Some("select-prefix") => {
            let prefix = parse_hex(&args.next().ok_or("missing hexadecimal prefix")?)?;
            let mut card = pcsc::connect_any(Sharing::Shared)?;
            card.transport_mut().power_cycle()?;
            let (status, data) = select_prefix(&mut card, &prefix);
            println!("{}  {}  {}", hex(&prefix), status, hex(&data));
        }
        Some("enumerate-aids") => {
            let root = parse_hex(&args.next().ok_or("missing hexadecimal root prefix")?)?;
            let max_len = args
                .next()
                .ok_or("missing maximum AID length")?
                .parse::<usize>()?;
            enumerate_aids(root, max_len)?;
        }
        Some("enumerate-occurrences") => {
            let prefix = parse_hex(&args.next().ok_or("missing hexadecimal prefix")?)?;
            enumerate_occurrences(&prefix)?;
        }
        _ => {
            return Err(
                "usage: fuzz_card baseline | default-df-state | scan-aid-roots | select-prefix HEX | \
                 enumerate-aids HEX MAX_LEN | enumerate-occurrences HEX"
                    .into(),
            );
        }
    }
    Ok(())
}

fn enumerate_occurrences(prefix: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if prefix.is_empty() || prefix.len() > 16 {
        return Err("prefix must contain 1..=16 bytes".into());
    }

    let mut card = pcsc::connect_any(Sharing::Shared)?;
    card.transport_mut().power_cycle()?;
    for occurrence in 0..32 {
        let p2 = if occurrence == 0 { 0x00 } else { 0x02 };
        let command = Command::with_data_le(0x00, 0xA4, 0x04, p2, prefix, 256);
        let response = card.call(&command)?;
        println!(
            "{occurrence:02}  {}  {}",
            response.status,
            hex(&response.data)
        );
        if !response.status.is_success() {
            break;
        }
    }
    Ok(())
}

fn default_df_state() -> Result<(), Box<dyn std::error::Error>> {
    let mut card = pcsc::connect_any(Sharing::Shared)?;
    card.transport_mut().power_cycle()?;

    print_get_data_state(&mut card, "cold");

    let (jpki_status, jpki_data) = select_prefix(&mut card, &jpki::DF);
    println!("SELECT jpki        {jpki_status}  {}", hex(&jpki_data));
    print_get_data_state(&mut card, "jpki");

    let (default_status, default_data) = select_prefix(&mut card, &DEFAULT_DF);
    println!(
        "SELECT default DF  {default_status}  {}",
        hex(&default_data)
    );
    print_get_data_state(&mut card, "default-aid");

    card.select_df(&jpki::DF)?;
    card.select_df(&DEFAULT_DF)?;
    println!("SELECT default DF with P2=0C  SW=9000 (normal end)");
    print_get_data_state(&mut card, "default-0c");

    card.select_df(&jpki::DF)?;
    let response = card.call(&Command::with_le(0x00, 0xA4, 0x04, 0x00, 256))?;
    println!(
        "SELECT default DF without AID  {}  {}",
        response.status,
        hex(&response.data)
    );
    print_get_data_state(&mut card, "default-empty");
    Ok(())
}

fn print_get_data_state<T: myna_card::Transmit>(card: &mut Card<T>, state: &str) {
    for tag in [0x0042u16, 0x0066, 0x00F0] {
        let [p1, p2] = tag.to_be_bytes();
        let command = Command::with_le(0x00, 0xCA, p1, p2, 256);
        match card.call(&command) {
            Ok(response) => println!(
                "{state:<11} GET DATA {tag:04X}  {}  {}",
                response.status,
                hex(&response.data)
            ),
            Err(error) => println!("{state:<11} GET DATA {tag:04X}  transport error: {error}"),
        }
    }
}

fn scan_aid_roots() -> Result<(), Box<dyn std::error::Error>> {
    let mut card = pcsc::connect_any(Sharing::Shared)?;
    card.transport_mut().power_cycle()?;
    for byte in 0u8..=u8::MAX {
        let prefix = [byte];
        let (status, data) = select_prefix(&mut card, &prefix);
        if status.is_success() {
            println!("prefix {}  {}", hex(&prefix), hex(&data));
        }
    }
    Ok(())
}

fn baseline() -> Result<(), Box<dyn std::error::Error>> {
    let mut card = pcsc::connect_any(Sharing::Shared)?;
    card.transport_mut().power_cycle()?;

    for (application, aid, keys) in [
        ("common", common::DF.as_slice(), &[0x001C, 0x001E][..]),
        ("juki", juki::DF.as_slice(), &[0x001C][..]),
        (
            "surface",
            surface::DF.as_slice(),
            &[0x0011, 0x0012, 0x0013, 0x0014, 0x0015][..],
        ),
        (
            "text",
            text::DF.as_slice(),
            &[0x0011, 0x0012, 0x0014, 0x0015][..],
        ),
        ("jpki", jpki::DF.as_slice(), &[0x0010, 0x0018, 0x001B][..]),
    ] {
        card.select_df(aid)?;
        for &key in keys {
            card.select_ef(key)?;
            println!("{application:<7} {key:04X} {}", retries(&mut card));
        }
    }
    Ok(())
}

fn retries<T: myna_card::Transmit>(card: &mut Card<T>) -> String {
    match card.pin_retries() {
        Ok(Retries::Remaining(n)) => format!("{n} remaining"),
        Ok(Retries::Blocked) => "blocked".to_owned(),
        Ok(Retries::Unlimited) => "unlimited".to_owned(),
        Ok(Retries::NotReported) => "not reported".to_owned(),
        Err(error) => format!("{error}"),
    }
}

fn enumerate_aids(root: Vec<u8>, max_len: usize) -> Result<(), Box<dyn std::error::Error>> {
    if root.is_empty() || max_len > 16 || root.len() > max_len {
        return Err("root must contain 1..=MAX_LEN bytes and MAX_LEN must be at most 16".into());
    }

    let mut card = pcsc::connect_any(Sharing::Shared)?;
    card.transport_mut().power_cycle()?;
    let (root_status, root_data) = select_prefix(&mut card, &root);
    if !root_status.is_success() {
        return Err(format!("root {} was rejected with {root_status}", hex(&root)).into());
    }
    println!("prefix {}  {}", hex(&root), hex(&root_data));

    let mut queue = VecDeque::from([root]);
    while let Some(prefix) = queue.pop_front() {
        if prefix.len() == max_len {
            println!("limit  {}", hex(&prefix));
            continue;
        }

        let mut child_count = 0usize;
        for byte in 0u8..=u8::MAX {
            let mut candidate = prefix.clone();
            candidate.push(byte);
            let (status, data) = select_prefix(&mut card, &candidate);
            if status.is_success() {
                child_count += 1;
                println!("prefix {}  {}", hex(&candidate), hex(&data));
                queue.push_back(candidate);
            }
        }
        if child_count == 0 {
            println!("leaf   {}", hex(&prefix));
        }
    }
    Ok(())
}

fn select_prefix<T: myna_card::Transmit>(
    card: &mut Card<T>,
    prefix: &[u8],
) -> (StatusWord, Vec<u8>) {
    let command = Command::with_data_le(0x00, 0xA4, 0x04, 0x00, prefix, 256);
    match card.call(&command) {
        Ok(response) => (response.status, response.data),
        Err(error) => {
            eprintln!("SELECT {} failed at the transport: {error}", hex(prefix));
            (StatusWord::new(0x6F00), Vec::new())
        }
    }
}

fn parse_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let compact: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.is_empty() || compact.len() % 2 != 0 {
        return Err("hexadecimal input must contain a whole number of bytes".into());
    }
    (0..compact.len() / 2)
        .map(|i| Ok(u8::from_str_radix(&compact[i * 2..i * 2 + 2], 16)?))
        .collect()
}

fn hex(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join("")
}
