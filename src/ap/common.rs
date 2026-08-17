//! 共通カードAP — the common card application.
//!
//! Unlike the other applications, its EFs are record structured rather than transparent, so they
//! are read with [`CommonAp::read_record`] rather than by offset.
//!
//! Record 1 of EF 0001 carries the card's own identity: a serial number, the prefecture and
//! municipality codes of the issuer, and the expiry date. EF 0002 matches EF 0002 of the 住基
//! application, whose content is not yet understood.
//!
//! No secure messaging. SET SESSION KEY answers `66F1`, "the security environment itself is
//! faulty" — there is no key delivery configured here to satisfy, so presenting more credentials
//! does not change it. See [`crate::sm`].

use crate::card::{Card, Retries, ShortEfId};
use crate::data::{Date, malformed};
use crate::error::Result;
use crate::pin::Pin;
use crate::tlv::simple;
use crate::transport::Transmit;

/// AID of the common card application.
pub const DF: [u8; 10] = [0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x01, 0x00];

/// File identifiers within the common card application.
pub mod ef {
    /// Serial number, prefecture code, municipality code and expiry date.
    pub const CARD_INFO: u16 = 0x0001;
    /// One 16 byte key reference, byte-identical to EF `0002` of the 住基 application. Which key
    /// it names is not identified.
    pub const KEY_REFERENCE: u16 = 0x0002;
    /// Key that answers INTERNAL AUTHENTICATE, with no credential. Its public half is nowhere on
    /// the card.
    pub const INTERNAL_AUTHENTICATION_KEY: u16 = 0x0019;
    /// Key reference for the PIN, which appears to be shared with the 住基 and 券面入力補助
    /// applications.
    pub const PIN: u16 = 0x001C;
}

/// The common card application, selected on a card.
#[derive(Debug)]
pub struct CommonAp<'a, T> {
    card: &'a mut Card<T>,
}

impl<'a, T: Transmit> CommonAp<'a, T> {
    /// Select the application.
    pub fn select(card: &'a mut Card<T>) -> Result<Self> {
        card.select_df(&DF)?;
        Ok(CommonAp { card })
    }

    /// Borrow the underlying card, for operations this wrapper does not cover.
    pub fn card(&mut self) -> &mut Card<T> {
        self.card
    }

    /// Read one record of a record structured EF of this application. Records start at 1.
    pub fn read_record(&mut self, id: u16, record: u8) -> Result<Vec<u8>> {
        self.card.select_ef(id)?;
        self.card.read_record(record)
    }

    /// Read the card's serial number, issuing municipality and expiry date.
    pub fn read_card_info(&mut self) -> Result<CardInfo> {
        let raw = self.read_record(ef::CARD_INFO, 1)?;
        CardInfo::parse(&raw)
    }

    /// Have the card sign `challenge` with the key in EF `0019`, without presenting anything.
    ///
    /// The only key on the card that answers INTERNAL AUTHENTICATE. What it is for is not
    /// established: its public half is on no file of the card, so nothing readable here can check
    /// the result, and whether the key is per card or shared across a hierarchy is unknown.
    ///
    /// The signature is `sha256WithRSAEncryption` over the challenge — see
    /// [`Card::internal_authenticate`](crate::card::Card::internal_authenticate).
    pub fn internal_authenticate(&mut self, challenge: &[u8]) -> Result<Vec<u8>> {
        let sfi = ShortEfId::from_ef_id(ef::INTERNAL_AUTHENTICATION_KEY)?;
        self.card.internal_authenticate(sfi, challenge)
    }

    /// Present the PIN.
    pub fn verify_pin(&mut self, pin: &Pin) -> Result<()> {
        self.card.select_ef(ef::PIN)?;
        self.card.verify(pin)
    }

    /// Attempts remaining on the PIN, without spending one.
    pub fn pin_retries(&mut self) -> Result<Retries> {
        self.card.select_ef(ef::PIN)?;
        self.card.pin_retries()
    }
}

/// Record 1 of EF `0001`: what the card says about itself.
///
/// A simple encoded TLV record (JICSAP 4.4.1 (1)) — tag `01`, length `1C`, then 28 ASCII digits
/// laid out as `<serial:15><municipality:5><expiry:YYYYMMDD>`:
///
/// ```text
/// 01 1C  "400000012719843" "13221" "20350217"
/// ```
///
/// The split was confirmed against 券面事項確認AP `0003`, whose `DF34` holds the same municipality
/// code, and against the expiry year in 照合番号B.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardInfo {
    /// Serial number, 15 digits.
    pub serial: String,
    /// 全国地方公共団体コード of the issuing municipality, 5 digits.
    pub municipality_code: String,
    /// Expiry date.
    pub expiry: Date,
}

impl CardInfo {
    /// Tag of the record.
    pub const TAG: u8 = 0x01;
    /// Length of the value field.
    pub const LEN: usize = 28;

    /// Parse record 1 of EF `0001`.
    pub fn parse(record: &[u8]) -> Result<Self> {
        let tlv = simple::parse(record)?;
        if tlv.tag != Self::TAG {
            return Err(malformed(&format!("expected tag 01, got {:02X}", tlv.tag)));
        }
        if tlv.value.len() != Self::LEN {
            return Err(malformed(&format!(
                "card info must be {} digits, got {}",
                Self::LEN,
                tlv.value.len()
            )));
        }
        if !tlv.value.iter().all(u8::is_ascii_digit) {
            return Err(malformed("card info must be all digits"));
        }
        let text = std::str::from_utf8(tlv.value).expect("digits are ASCII");
        Ok(CardInfo {
            serial: text[..15].to_owned(),
            municipality_code: text[15..20].to_owned(),
            expiry: Date::parse(&tlv.value[20..])?,
        })
    }

    /// The prefecture code, the first two digits of the municipality code.
    pub fn prefecture_code(&self) -> &str {
        &self.municipality_code[..2]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Record 1 of EF 0001 on the test card, byte for byte.
    const RECORD: &[u8] = b"\x01\x1c4000000127198431322120350217";

    #[test]
    fn parses_the_card_info_record() {
        let info = CardInfo::parse(RECORD).unwrap();
        assert_eq!(info.serial, "400000012719843");
        assert_eq!(info.municipality_code, "13221");
        assert_eq!(info.prefecture_code(), "13");
        assert_eq!(
            info.expiry,
            Date {
                year: 2035,
                month: 2,
                day: 17
            }
        );
    }

    #[test]
    fn rejects_a_record_of_the_wrong_shape() {
        assert!(CardInfo::parse(b"\x02\x1c4000000127198431322120350217").is_err());
        assert!(CardInfo::parse(b"\x01\x1b400000012719843132212035021").is_err());
        assert!(CardInfo::parse(b"\x01\x1c40000001271984313221203502XX").is_err());
    }
}
