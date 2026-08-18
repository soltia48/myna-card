//! Files under the master file that JICSAP itself specifies.
//!
//! Unlike the application files, whose layouts had to be reverse engineered, these three are
//! fully described by the specification, so they can be parsed rather than handed back raw:
//!
//! | EF | Contents | Reference |
//! |---|---|---|
//! | `001E` | card identifier | Annex B |
//! | `2F10` | application folder list | Annex D |
//! | `2F11` | IC manufacturer ID | Annex F |
//!
//! All three are record structured, so their records are simple encoded TLV
//! ([`crate::tlv::simple`]), not BER.
//!
//! # None of this works on the Individual Number Card
//!
//! Annex D and Annex F say these files *should* exist, not that they must, and a sweep of a real
//! card found that none of them do:
//!
//! - `2F10` and `2F11` answer 6A82, "no file to be accessed".
//! - `001E` can be selected, but both READ BINARY and READ RECORD answer 6981, "command
//!   conflicting the file structure" — it is an internal EF, not the card identifier.
//! - Sweeping every identifier `0001`-`001E` immediately after a cold reset finds nothing at all,
//!   so the MF holds no elementary file with a short identifier.
//!
//! The ISO MF cannot be re-selected: `00 A4 00 00` answers 6A86 after a reset and 9000 — *without
//! changing the current DF* — once an application is selected, and 3F00 answers 6A82. The same
//! observable power-on state is nevertheless reachable through GlobalPlatform: selecting the
//! Issuer Security Domain at its default AID, `A0000001510000`, restores the MF-level GET DATA
//! objects. [`MasterFile::select`] performs that selection; [`MasterFile::new`] remains available
//! when the card is already freshly reset.
//!
//! The module is kept because it is what JICSAP specifies, and other cards built to the same
//! specification do carry these files.
//!
//! # What is there instead
//!
//! The MF level is not empty — it is just not reachable through files. GET DATA answers there,
//! and only there, for a set of objects that includes the card's contact-interface ATR, its
//! identification number, the issuing municipality and expiry date, and a chain of
//! card-verifiable certificates. See [`tag`] and [`MasterFile::data_object`].

use crate::card::Card;
use crate::data::CardVerifiableCertificate;
use crate::error::{Error, Result};
use crate::tlv::simple;
use crate::transport::Transmit;

/// Identifiers of the EFs under the master file.
pub mod ef {
    /// Card identifier (JICSAP 4.2 (2) reserves this identifier for it; see Annex B).
    pub const CARD_IDENTIFIER: u16 = 0x001E;
    /// Application folder list file (Annex D). Also present under each DF.
    pub const APPLICATION_FOLDER_LIST: u16 = 0x2F10;
    /// IC manufacturer ID file (Annex F).
    pub const IC_MANUFACTURER_ID: u16 = 0x2F11;
}

/// Tags of the data objects GET DATA answers for with the master file current.
///
/// Every one of these was found by sweeping P1-P2; the card publishes no index. Which are present
/// varies between cards, so treat a 6A88 as an ordinary answer rather than a fault.
pub mod tag {
    /// Issuer identification number, a 16 byte key reference.
    pub const ISSUER_IDENTIFICATION: u16 = 0x0042;
    /// Card identification number, ASCII.
    pub const CARD_IDENTIFICATION: u16 = 0x0045;
    /// Card recognition data: GlobalPlatform's, under the arc 1.2.840.114283.
    pub const CARD_RECOGNITION: u16 = 0x0066;
    /// 全国地方公共団体コード of the issuing municipality, five ASCII digits.
    pub const MUNICIPALITY_CODE: u16 = 0x00F0;
    /// Expiry date, eight ASCII digits.
    pub const EXPIRY: u16 = 0x00F2;
    /// 証明者鍵ID of the intermediate that signs [`CHAIN_LOWER`].
    pub const INTERMEDIATE_KEY_ID: u16 = 0x00F7;
    /// A card-verifiable certificate: the root certifying the intermediate.
    pub const CHAIN_UPPER: u16 = 0x00F8;
    /// A card-verifiable certificate: the intermediate certifying the key below it. Absent on
    /// some cards.
    pub const CHAIN_LOWER: u16 = 0x7F21;
    /// The contact interface ATR, without its initial `TS`. Answers with an application current
    /// too, and on some cards *only* then, so it lives on [`Card::contact_atr`](crate::card::Card::contact_atr).
    pub const CONTACT_ATR: u16 = 0x5F51;
}

/// The master file, selected on a card.
#[derive(Debug)]
pub struct MasterFile<'a, T> {
    card: &'a mut Card<T>,
}

impl<'a, T: Transmit> MasterFile<'a, T> {
    /// Select the GlobalPlatform Issuer Security Domain and work with the power-on card-manager
    /// state.
    ///
    /// The Individual Number Card does not implement a trustworthy ISO SELECT MF command, but its
    /// default Issuer Security Domain AID is selectable. On the surveyed card this restores the
    /// same GET DATA objects as a cold reset, even after an application DF was current.
    pub fn select(card: &'a mut Card<T>) -> Result<Self> {
        card.select_df(&crate::ap::DEFAULT_DF)?;
        Ok(MasterFile { card })
    }

    /// Work with the master file as the current DF.
    ///
    /// This issues no SELECT. A card reset makes the card-manager state current on every logical
    /// channel (JICSAP 4.5); [`MasterFile::select`] can restore it later through the
    /// GlobalPlatform Issuer Security Domain AID.
    ///
    /// The caller is responsible for ensuring that state: reset the card, select the Issuer
    /// Security Domain, or use this before selecting any application. If an application DF is
    /// current instead, every read here silently comes from that application.
    pub fn new(card: &'a mut Card<T>) -> Self {
        MasterFile { card }
    }

    /// Borrow the underlying card, for operations this wrapper does not cover.
    pub fn card(&mut self) -> &mut Card<T> {
        self.card
    }

    /// Retrieve one of the MF level data objects; see [`tag`].
    ///
    /// This is GET DATA, not a file read, so it works even though the MF holds no readable EF.
    pub fn data_object(&mut self, tag: u16) -> Result<Vec<u8>> {
        self.card.get_data(tag)
    }

    /// The card-verifiable certificates at the MF level, root first.
    ///
    /// One or two, depending on the card: [`tag::CHAIN_UPPER`] is always there, and
    /// [`tag::CHAIN_LOWER`] is missing on older cards. Consecutive entries chain — the second is
    /// signed by the key the first certifies — and only the first needs a CA key from
    /// [`crate::ca`], which is what makes the pair self-contained.
    pub fn certificate_chain(&mut self) -> Result<Vec<CardVerifiableCertificate>> {
        let mut chain = Vec::new();
        for tag in [tag::CHAIN_UPPER, tag::CHAIN_LOWER] {
            match self.data_object(tag) {
                Ok(raw) => chain.push(CardVerifiableCertificate::parse(&raw)?),
                // The card says it has no such object; that is an absence, not a failure.
                Err(Error::Status(sw)) if matches!(sw.value(), 0x6A88 | 0x6A82) => break,
                Err(err) => return Err(err),
            }
        }
        Ok(chain)
    }

    /// Read the card identifier (Annex B).
    pub fn card_identifier(&mut self) -> Result<CardIdentifier> {
        let raw = self.read_all_records(ef::CARD_IDENTIFIER)?;
        CardIdentifier::parse(&raw)
    }

    /// Read the application folder list of the master file (Annex D).
    pub fn application_folders(&mut self) -> Result<ApplicationFolders> {
        let raw = self.read_all_records(ef::APPLICATION_FOLDER_LIST)?;
        ApplicationFolders::parse(&raw)
    }

    /// Read the IC manufacturer ID file (Annex F).
    pub fn ic_manufacturer_id(&mut self) -> Result<IcManufacturerId> {
        let raw = self.read_all_records(ef::IC_MANUFACTURER_ID)?;
        IcManufacturerId::parse(&raw)
    }

    /// Read every record of a record structured EF, concatenated.
    ///
    /// Tries the multi-record form of READ RECORD(S) first and falls back to reading one record
    /// at a time, since JICSAP 6.4.4 lets a card answer 6A81 to the multi-record form.
    pub fn read_all_records(&mut self, id: u16) -> Result<Vec<u8>> {
        self.card.select_ef(id)?;
        match self.card.read_records_from(1) {
            Ok(data) => Ok(data),
            Err(Error::Status(sw)) if sw.value() == 0x6A81 => self.read_records_one_by_one(),
            Err(err) => Err(err),
        }
    }

    fn read_records_one_by_one(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for record in 1..=u8::MAX {
            match self.card.read_record(record) {
                Ok(data) if data.is_empty() => break,
                Ok(data) => out.extend_from_slice(&data),
                // 6A83: no such record — we have reached the end of the file.
                Err(Error::Status(sw)) if sw.value() == 0x6A83 => break,
                Err(err) => return Err(err),
            }
        }
        Ok(out)
    }
}

/// The card identifier of JICSAP Annex B.
///
/// Set by the card manufacturer before the card reaches the issuer, and not rewritable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardIdentifier {
    /// Which manufacturer's issuance library the card expects. Administered by JICSAP.
    pub manufacturer: u8,
    /// Which encryption algorithms the card implements.
    pub algorithms: Algorithms,
    /// Which JICSAP specification version the card implements.
    pub version: SpecVersion,
    /// Which optional functions the card implements. Absent if the record is missing, though
    /// Annex B calls it mandatory.
    pub optional_functions: Option<OptionalFunctions>,
    /// Manufacturer's proprietary information, 1 to 5 bytes. Optional.
    pub proprietary: Option<Vec<u8>>,
}

impl CardIdentifier {
    /// Tag of the manufacturer specific information record.
    pub const TAG_MANUFACTURER: u8 = 0x00;
    /// Tag of the optional function information record.
    pub const TAG_OPTIONAL_FUNCTIONS: u8 = 0x01;
    /// Tag of the manufacturer's proprietary information record.
    pub const TAG_PROPRIETARY: u8 = 0x02;

    /// Parse the concatenated records of EF `001E`.
    pub fn parse(records: &[u8]) -> Result<Self> {
        let manufacturer_record = simple::find(records, Self::TAG_MANUFACTURER)?
            .ok_or_else(|| malformed("card identifier has no manufacturer record (tag 00)"))?;
        let [manufacturer, algorithms, version] = <[u8; 3]>::try_from(manufacturer_record)
            .map_err(|_| {
                malformed(&format!(
                    "manufacturer record must be 3 bytes, got {}",
                    manufacturer_record.len()
                ))
            })?;

        let optional_functions = simple::find(records, Self::TAG_OPTIONAL_FUNCTIONS)?
            .and_then(|v| v.first().copied())
            .map(OptionalFunctions);

        Ok(CardIdentifier {
            manufacturer,
            algorithms: Algorithms(algorithms),
            version: SpecVersion(version),
            optional_functions,
            proprietary: simple::find(records, Self::TAG_PROPRIETARY)?.map(<[u8]>::to_vec),
        })
    }
}

/// The encryption algorithm identifier of JICSAP Table B-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Algorithms(pub u8);

impl Algorithms {
    /// b1 — DES.
    pub const fn des(self) -> bool {
        self.0 & 0x01 != 0
    }
    /// b2 — RSA.
    pub const fn rsa(self) -> bool {
        self.0 & 0x02 != 0
    }
    /// b3 — FEAL.
    pub const fn feal(self) -> bool {
        self.0 & 0x04 != 0
    }
    /// b4 — Triple DES.
    pub const fn triple_des(self) -> bool {
        self.0 & 0x08 != 0
    }
}

/// The optional function information of JICSAP Table B-3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionalFunctions(pub u8);

impl OptionalFunctions {
    /// b1 — DF deletion.
    pub const fn delete_df(self) -> bool {
        self.0 & 0x01 != 0
    }
    /// b2 — IEF creation checking.
    pub const fn check_ief_creation(self) -> bool {
        self.0 & 0x02 != 0
    }
    /// b3 — unused DF memory size check.
    pub const fn unused_df_memory_size_check(self) -> bool {
        self.0 & 0x04 != 0
    }
    /// b4 — secure messaging, confidentiality.
    pub const fn secure_messaging_confidentiality(self) -> bool {
        self.0 & 0x08 != 0
    }
    /// b5 — secure messaging, integrity.
    pub const fn secure_messaging_integrity(self) -> bool {
        self.0 & 0x10 != 0
    }
    /// b6 — secure messaging, confidentiality and integrity together.
    pub const fn secure_messaging_both(self) -> bool {
        self.0 & 0x20 != 0
    }
    /// b7 — ECB mode for secure messaging confidentiality.
    pub const fn ecb_mode(self) -> bool {
        self.0 & 0x40 != 0
    }
    /// b8 — CBC mode for secure messaging confidentiality.
    pub const fn cbc_mode(self) -> bool {
        self.0 & 0x80 != 0
    }
}

/// The specification version identifier of JICSAP Table B-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecVersion(pub u8);

impl SpecVersion {
    /// The version as a string, for the two values Table B-2 assigns.
    pub const fn name(self) -> Option<&'static str> {
        match self.0 {
            0x01 => Some("1.0"),
            0x02 => Some("1.1"),
            _ => None,
        }
    }
}

/// The application folder list file of JICSAP Annex D.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApplicationFolders {
    /// The name of the DF this file lives in. Empty under the MF, which has no DF name.
    pub own_name: Vec<u8>,
    /// The names of the DFs directly below it.
    pub children: Vec<Vec<u8>>,
}

impl ApplicationFolders {
    /// Tag of the record naming the DF this file lives in.
    pub const TAG_SELF: u8 = 0x01;
    /// Tag of a record naming a subordinate DF.
    pub const TAG_CHILD: u8 = 0x02;
    /// Tag marking a record as invalidated, reusable when a DF is issued later.
    pub const TAG_INVALID: u8 = 0xFE;

    /// Parse the concatenated records of an EF `2F10`.
    ///
    /// Records tagged `FE` are skipped: Annex D uses that tag for a slot that is reserved but
    /// carries no DF, and 4.2.3 of the issuance library specification has the issuer write one
    /// into every free record.
    pub fn parse(records: &[u8]) -> Result<Self> {
        let mut folders = ApplicationFolders::default();
        for tlv in simple::iter(records) {
            let tlv = tlv?;
            match tlv.tag {
                Self::TAG_SELF => folders.own_name = tlv.value.to_vec(),
                Self::TAG_CHILD => folders.children.push(tlv.value.to_vec()),
                Self::TAG_INVALID => {}
                // 4.4.1 (1): a record whose tag is '00' has no tag, so it holds nothing.
                simple::TAG_UNUSED => {}
                other => {
                    return Err(malformed(&format!(
                        "unexpected tag {other:02X} in an application folder list"
                    )));
                }
            }
        }
        Ok(folders)
    }
}

/// The IC manufacturer ID file of JICSAP Annex F.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcManufacturerId {
    /// Embedder / IC assembler identifier, five alphanumeric bytes in the form `CCEEA`: an
    /// ISO 3166 country code, the manufacturer identifier as two ASCII hex digits, and a field
    /// that is a space when unused.
    pub embedder: [u8; 5],
    /// IC manufacturer identifier.
    pub ic_manufacturer: u8,
    /// Manufacturer's IC type identifier.
    pub ic_type: u16,
}

impl IcManufacturerId {
    /// Tag of the embedder / IC assembler identifier record.
    pub const TAG_EMBEDDER: u8 = 0x45;
    /// Tag of the IC manufacturer and IC type record.
    pub const TAG_MANUFACTURER: u8 = 0x46;

    /// Parse the concatenated records of EF `2F11`.
    pub fn parse(records: &[u8]) -> Result<Self> {
        let embedder = simple::find(records, Self::TAG_EMBEDDER)?
            .ok_or_else(|| malformed("no embedder record (tag 45)"))?;
        let embedder = <[u8; 5]>::try_from(embedder).map_err(|_| {
            malformed(&format!(
                "embedder record must be 5 bytes, got {}",
                embedder.len()
            ))
        })?;

        let manufacturer = simple::find(records, Self::TAG_MANUFACTURER)?
            .ok_or_else(|| malformed("no IC manufacturer record (tag 46)"))?;
        let [ic_manufacturer, type_hi, type_lo] =
            <[u8; 3]>::try_from(manufacturer).map_err(|_| {
                malformed(&format!(
                    "IC manufacturer record must be 3 bytes, got {}",
                    manufacturer.len()
                ))
            })?;

        Ok(IcManufacturerId {
            embedder,
            ic_manufacturer,
            ic_type: u16::from_be_bytes([type_hi, type_lo]),
        })
    }

    /// The country code from the first two bytes of the embedder identifier.
    pub fn country(&self) -> Option<&str> {
        std::str::from_utf8(&self.embedder[..2]).ok()
    }
}

fn malformed(what: &str) -> Error {
    Error::Malformed(what.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    #[test]
    fn parses_a_card_identifier() {
        // Annex B: manufacturer record, optional function record, proprietary record.
        let records = [
            0x00, 0x03, 0x07, 0x0A, 0x02, // manufacturer 07, RSA + Triple DES, version 1.1
            0x01, 0x01, 0x05, // delete DF + unused DF memory size check
            0x02, 0x02, 0xDE, 0xAD,
        ];
        let id = CardIdentifier::parse(&records).unwrap();
        assert_eq!(id.manufacturer, 0x07);
        assert!(id.algorithms.rsa() && id.algorithms.triple_des());
        assert!(!id.algorithms.des() && !id.algorithms.feal());
        assert_eq!(id.version.name(), Some("1.1"));

        let options = id.optional_functions.unwrap();
        assert!(options.delete_df() && options.unused_df_memory_size_check());
        assert!(!options.check_ief_creation() && !options.secure_messaging_confidentiality());
        assert_eq!(id.proprietary.as_deref(), Some(&[0xDE, 0xAD][..]));
    }

    #[test]
    fn card_identifier_needs_the_mandatory_record() {
        assert!(CardIdentifier::parse(&[0x01, 0x01, 0x00]).is_err());
        assert!(CardIdentifier::parse(&[0x00, 0x02, 0x07, 0x0A]).is_err());
    }

    #[test]
    fn parses_an_application_folder_list() {
        // The MF's list: no name of its own, two child DFs, then invalidated free records.
        let records = [
            0x01, 0x00, //
            0x02, 0x02, 0x11, 0x22, //
            0x02, 0x03, 0x33, 0x44, 0x55, //
            0xFE, 0x02, 0x00, 0x00,
        ];
        let folders = ApplicationFolders::parse(&records).unwrap();
        assert!(folders.own_name.is_empty());
        assert_eq!(folders.children, [vec![0x11, 0x22], vec![0x33, 0x44, 0x55]]);
    }

    #[test]
    fn parses_an_ic_manufacturer_id() {
        // 'JP' + manufacturer "07" + unused field, then manufacturer 07 and IC type 1234.
        let records = [
            0x45, 0x05, b'J', b'P', b'0', b'7', b' ', //
            0x46, 0x03, 0x07, 0x12, 0x34,
        ];
        let id = IcManufacturerId::parse(&records).unwrap();
        assert_eq!(id.country(), Some("JP"));
        assert_eq!(id.ic_manufacturer, 0x07);
        assert_eq!(id.ic_type, 0x1234);
    }

    #[test]
    fn get_data_falls_back_to_an_extended_le() {
        // The card refuses a short Le for the large objects rather than reporting the length, so
        // the first attempt is spent finding that out.
        let big = vec![0xAA; 300];
        let mut card = Card::new(MockTransport::new([
            vec![0x67, 0x00],
            [big.clone(), vec![0x90, 0x00]].concat(),
        ]));
        let mut mf = MasterFile::new(&mut card);
        assert_eq!(mf.data_object(tag::CHAIN_UPPER).unwrap(), big);
        assert_eq!(
            mf.card().transport().sent,
            vec![
                vec![0x00, 0xCA, 0x00, 0xF8, 0x00],
                vec![0x00, 0xCA, 0x00, 0xF8, 0x00, 0x00, 0x00],
            ]
        );
    }

    #[test]
    fn selects_the_default_issuer_security_domain() {
        let mut card = Card::new(MockTransport::new([vec![0x90, 0x00]]));
        let mut mf = MasterFile::select(&mut card).unwrap();
        assert_eq!(
            mf.card().transport().sent,
            [vec![
                0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00,
            ]]
        );
    }

    #[test]
    fn get_data_uses_one_apdu_when_the_object_is_small() {
        let mut card = Card::new(MockTransport::new([vec![
            b'1', b'3', b'2', b'2', b'1', 0x90, 0x00,
        ]]));
        let mut mf = MasterFile::new(&mut card);
        assert_eq!(mf.data_object(tag::MUNICIPALITY_CODE).unwrap(), b"13221");
        assert_eq!(mf.card().transport().sent.len(), 1);
    }

    #[test]
    fn a_missing_second_certificate_ends_the_chain_rather_than_failing() {
        let cert = std::fs::read(format!(
            "{}/tests/fixtures/mf-do-F8.bin",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let mut card = Card::new(MockTransport::new([
            [cert.clone(), vec![0x90, 0x00]].concat(),
            vec![0x6A, 0x88],
        ]));
        let chain = MasterFile::new(&mut card).certificate_chain().unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].issuer_key_id.number(), "6000020");
    }

    #[test]
    fn reads_records_one_at_a_time_when_the_card_rejects_the_multi_record_form() {
        // No SELECT here: `MasterFile::new` assumes the card-manager state is already current.
        let mut card = Card::new(MockTransport::new([
            vec![0x90, 0x00],                               // SELECT EF 001E
            vec![0x6A, 0x81],                               // READ RECORD(S) 1..last: not provided
            vec![0x00, 0x03, 0x07, 0x0A, 0x02, 0x90, 0x00], // record 1
            vec![0x6A, 0x83],                               // record 2: none
        ]));
        let mut mf = MasterFile::new(&mut card);
        let id = mf.card_identifier().unwrap();
        assert_eq!(id.manufacturer, 0x07);

        assert_eq!(
            card.transport().sent[0],
            [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x1E]
        );
        assert_eq!(card.transport().sent[1], [0x00, 0xB2, 0x01, 0x05, 0x00]);
        assert_eq!(card.transport().sent[2], [0x00, 0xB2, 0x01, 0x04, 0x00]);
    }
}
