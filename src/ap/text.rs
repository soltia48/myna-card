//! 券面入力補助AP — the text input support application.
//!
//! Exists so that a reader can obtain the data printed on the card without the user typing it
//! in. It holds the individual number itself and the four basic attributes (name, address, date
//! of birth, sex), each behind its own access rule.
//!
//! Three key references guard this application: a four digit PIN, and the two 照合番号 values
//! derived from what is printed on the card. Which of them unlocks which EF differs per file;
//! see the notes on each accessor. A fourth reference exists but is blocked — see
//! [`ef::BLOCKED_0012`].
//!
//! # Secure messaging
//!
//! This is the only application on the card that offers it, and the only one that publishes a key
//! to deliver a session key to. See [`crate::sm`] for the mechanism and for what it does and does
//! not protect, and [`TextAp::open_secure_session`] to open a session.
//!
//! The other applications answer SET SESSION KEY without ever implementing what it asks for. None
//! answers `6D00`, so the instruction exists card-wide; they differ in why they refuse:
//!
//! ```text
//! 共通AP            66F1   no key delivery configured in the security environment
//! 券面事項確認AP      66F1   likewise
//! 公的個人認証AP      6982   configured, but no credential this crate can present satisfies it
//! 住基AP            6982   likewise
//! 券面入力補助AP      9000
//! ```
//!
//! `6982` there is about access, not about knowing the right key: with the correct public key but
//! no PIN presented this application answers `6982` too, and with the wrong key but the PIN
//! presented it answers `6A80`. The card checks the access condition before it decrypts anything.

use crate::card::{Card, Retries};
use crate::data::{
    CardVerifiableCertificate, Date, KeyId, MyNumber, RsaPublicKey, Sex, TlvFields, check_offsets,
    malformed,
};
use crate::error::Result;
use crate::pin::Pin;
use crate::tlv::ber;
use crate::transport::Transmit;

/// AID of the text input support application.
pub const DF: [u8; 10] = [0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x08];

/// File identifiers within the text input support application.
pub mod ef {
    /// The individual number (個人番号).
    pub const MY_NUMBER: u16 = 0x0001;
    /// The four basic attributes: name, address, date of birth, sex (基本4情報).
    pub const ATTRIBUTES: u16 = 0x0002;
    /// Digests of the data files, and a signature over them. Unlocked by the PIN or 照合番号A.
    pub const INTEGRITY: u16 = 0x0003;
    /// This application's own card-verifiable certificate.
    pub const CERTIFICATE: u16 = 0x0004;
    /// This application's basic information: an identifier and the key it names.
    pub const AP_BASIC_DATA: u16 = 0x0005;
    /// Public key a terminal encrypts a session key to. Unlocked by the PIN or either 照合番号.
    pub const SESSION_KEY_PUBLIC_KEY: u16 = 0x0006;
    /// The public half of this application's signing key, with a signature over it.
    pub const SIGNED_PUBLIC_KEY: u16 = 0x0007;
    /// Purpose not yet identified; observed as sixteen 0xFF bytes.
    pub const UNKNOWN_0008: u16 = 0x0008;
    /// Key reference for the four digit PIN (暗証番号).
    pub const PIN: u16 = 0x0011;
    /// A key reference that is blocked, with zero attempts left, on every card examined.
    ///
    /// It answers the non-consuming VERIFY query with `63C0`, and a VERIFY against it with `6984`,
    /// "the referenced IEF is blocked". Nothing here has ever presented a value to it, so this is
    /// how the cards are issued rather than the result of exhausted attempts. What it guards is
    /// not established; no EF of this application was found that it opens.
    pub const BLOCKED_0012: u16 = 0x0012;
    /// Key reference for 照合番号A.
    pub const CODE_A: u16 = 0x0014;
    /// Key reference for 照合番号B.
    pub const CODE_B: u16 = 0x0015;
}

/// The text input support application, selected on a card.
#[derive(Debug)]
pub struct TextAp<'a, T> {
    card: &'a mut Card<T>,
}

impl<'a, T: Transmit> TextAp<'a, T> {
    /// Select the application.
    pub fn select(card: &'a mut Card<T>) -> Result<Self> {
        card.select_df(&DF)?;
        Ok(TextAp { card })
    }

    /// Borrow the underlying card, for operations this wrapper does not cover.
    pub fn card(&mut self) -> &mut Card<T> {
        self.card
    }

    /// Read a transparent EF of this application in full.
    pub fn read_ef(&mut self, id: u16) -> Result<Vec<u8>> {
        self.card.select_ef(id)?;
        self.card.read_binary_all()
    }

    /// Read the 個人番号.
    ///
    /// Requires [`TextAp::verify_pin`] or [`TextAp::verify_code_a`] first.
    pub fn read_my_number(&mut self) -> Result<MyNumber> {
        let raw = self.read_ef(ef::MY_NUMBER)?;
        parse_my_number(&raw)
    }

    /// Read the 基本4情報: name, address, date of birth and sex.
    ///
    /// Requires [`TextAp::verify_pin`] or [`TextAp::verify_code_b`] first. 照合番号A does **not**
    /// open it: on a card, A opens EF `0001` and not `0002`, B opens `0002` and not `0001`. The
    /// two are complementary, and only the PIN opens both.
    pub fn read_attributes(&mut self) -> Result<Attributes> {
        let raw = self.read_ef(ef::ATTRIBUTES)?;
        Attributes::parse(&raw)
    }

    /// Read this application's own card-verifiable certificate, EF `0004`.
    ///
    /// Readable with nothing presented.
    pub fn read_certificate(&mut self) -> Result<CardVerifiableCertificate> {
        let raw = self.read_ef(ef::CERTIFICATE)?;
        CardVerifiableCertificate::parse(&raw)
    }

    /// Read this application's basic information from EF `0005`.
    ///
    /// Readable with nothing presented.
    pub fn read_ap_basic_data(&mut self) -> Result<ApBasicData> {
        let raw = self.read_ef(ef::AP_BASIC_DATA)?;
        ApBasicData::parse(&raw)
    }

    /// Read the integrity record of EF `0003`.
    ///
    /// Requires the PIN or either 照合番号.
    pub fn read_integrity_record(&mut self) -> Result<IntegrityRecord> {
        let raw = self.read_ef(ef::INTEGRITY)?;
        IntegrityRecord::parse(&raw)
    }

    /// Read the signed public key of EF `0007`.
    ///
    /// Requires the PIN or either 照合番号.
    pub fn read_signed_public_key(&mut self) -> Result<SignedPublicKey> {
        let raw = self.read_ef(ef::SIGNED_PUBLIC_KEY)?;
        SignedPublicKey::parse(&raw)
    }

    /// Read the session key encryption public key of EF `0006`.
    ///
    /// Requires the PIN or either 照合番号.
    pub fn read_session_key_public_key(&mut self) -> Result<SessionKeyPublicKey> {
        let raw = self.read_ef(ef::SESSION_KEY_PUBLIC_KEY)?;
        SessionKeyPublicKey::parse(&raw)
    }

    /// Read the whole physical content of EF `0001`, filler included.
    ///
    /// This is what [`IntegrityRecord::matches_my_number_file`] hashes.
    pub fn read_my_number_file(&mut self) -> Result<Vec<u8>> {
        self.card.select_ef(ef::MY_NUMBER)?;
        self.card.read_binary_physical()
    }

    /// Sign `data` with this application's own key — the one whose public half travels inside the
    /// signed records, and which needs no credential.
    ///
    /// Hashing happens here: the card is handed a SHA-256 `DigestInfo`, and P2 is `00`, which
    /// selects the application's default key.
    ///
    /// Signing a challenge and checking the result against the public key in a record is what
    /// proves the card is present, as opposed to a copy of its files. The record has to be
    /// verified too, or the key being challenged is one the attacker chose.
    #[cfg(feature = "verify")]
    pub fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let digest_info = crate::data::sha256_digest_info(&crate::data::sha256(data));
        self.card.call_ok(&crate::apdu::Command::with_data_le(
            0x80,
            crate::card::ins::COMPUTE_SIGNATURE,
            0x00,
            0x00,
            digest_info,
            256,
        ))
    }

    /// Open a secure messaging session, delivering `seed` under the key in EF `0006`.
    ///
    /// The PIN must already have been presented with [`TextAp::verify_pin`], in the clear — this
    /// application will not deliver a session key on the strength of 照合番号A, and there is no way
    /// around that ordering. `seed` must be freshly generated by a cryptographically secure random
    /// number generator for every session.
    ///
    /// What a session is worth: 照合番号A is the 個人番号, and presenting it inside a session keeps
    /// it off the interface. See [`crate::sm`] for the rest.
    ///
    /// ```no_run
    /// # #[cfg(all(feature = "pcsc", feature = "sm"))]
    /// # fn main() -> Result<(), myna_card::Error> {
    /// # use myna_card::{Pin, ap::text::{TextAp, ef}, transport::pcsc::{self, Sharing}};
    /// # let mut card = pcsc::connect_any(Sharing::Exclusive)?;
    /// let mut text = TextAp::select(&mut card)?;
    /// text.verify_pin(&Pin::numeric("1234")?)?;
    ///
    /// let seed = [0u8; 32]; // from a CSPRNG, not this
    /// let mut session = text.open_secure_session(&seed)?;
    /// session.verify(ef::CODE_A, &Pin::numeric("537686677188")?)?;
    /// let my_number = session.read_ef(ef::MY_NUMBER)?;
    /// # let _ = my_number;
    /// # Ok(())
    /// # }
    /// # #[cfg(not(all(feature = "pcsc", feature = "sm")))]
    /// # fn main() {}
    /// ```
    #[cfg(feature = "sm")]
    pub fn open_secure_session(
        &mut self,
        seed: &[u8; crate::sm::SEED_LEN],
    ) -> Result<crate::sm::SecureSession<'_, T>> {
        let key = self.read_session_key_public_key()?.public_key;
        crate::sm::SecureSession::establish(self.card, &key, seed)
    }

    /// Present the four digit PIN.
    ///
    /// This travels in the clear, and cannot do otherwise: a session to encrypt it under cannot be
    /// opened until it has been presented. Treat it as exposed to anything listening.
    pub fn verify_pin(&mut self, pin: &Pin) -> Result<()> {
        self.verify_key(ef::PIN, pin)
    }

    /// Present 照合番号A.
    pub fn verify_code_a(&mut self, code: &Pin) -> Result<()> {
        self.verify_key(ef::CODE_A, code)
    }

    /// Present 照合番号B.
    pub fn verify_code_b(&mut self, code: &Pin) -> Result<()> {
        self.verify_key(ef::CODE_B, code)
    }

    /// Attempts remaining on one of this application's key references, without spending one.
    ///
    /// Pass one of [`ef::PIN`], [`ef::CODE_A`], [`ef::CODE_B`] or [`ef::BLOCKED_0012`].
    pub fn retries(&mut self, key: u16) -> Result<Retries> {
        self.card.select_ef(key)?;
        self.card.pin_retries()
    }

    fn verify_key(&mut self, key: u16, value: &Pin) -> Result<()> {
        self.card.select_ef(key)?;
        self.card.verify(value)
    }
}

/// Tag of the file holding the 個人番号.
const TAG_MY_NUMBER: u32 = 0xFF10;

fn parse_my_number(raw: &[u8]) -> Result<MyNumber> {
    let tlv = ber::parse(raw)?;
    if tlv.tag != TAG_MY_NUMBER {
        return Err(malformed(&format!(
            "expected tag FF10, got {:04X}",
            tlv.tag
        )));
    }
    MyNumber::parse(tlv.value)
}

/// The 基本4情報 of EF `0002`.
///
/// ```text
/// FF 20 65
///   DF 21 08   000E 0020 0059 0064   offset table
///   DF 22 <n>  氏名        UTF-8
///   DF 23 <n>  住所        UTF-8
///   DF 24 08   YYYYMMDD    生年月日
///   DF 25 01   "1"         性別
/// ```
///
/// `DF21` gives the byte offset of each of the four fields from the start of the file. The two
/// text fields are variable length, so the table is what lets a reader jump straight to one.
/// [`Attributes::parse`] checks it rather than trusting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attributes {
    /// 氏名. Family and given name are separated by an ideographic space, `U+3000`.
    pub name: String,
    /// 住所. Block numbers use full-width digits.
    pub address: String,
    /// 生年月日, Gregorian.
    pub birth_date: Date,
    /// 性別.
    pub sex: Sex,
}

impl Attributes {
    /// Tag of the whole file.
    pub const TAG: u32 = 0xFF20;
    /// Tag of the offset table.
    pub const TAG_OFFSETS: u32 = 0xDF21;
    /// Tag of 氏名.
    pub const TAG_NAME: u32 = 0xDF22;
    /// Tag of 住所.
    pub const TAG_ADDRESS: u32 = 0xDF23;
    /// Tag of 生年月日.
    pub const TAG_BIRTH_DATE: u32 = 0xDF24;
    /// Tag of 性別.
    pub const TAG_SEX: u32 = 0xDF25;

    /// Parse EF `0002`.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let outer = ber::parse(raw)?;
        if outer.tag != Self::TAG {
            return Err(malformed(&format!(
                "expected tag FF20, got {:04X}",
                outer.tag
            )));
        }
        // The table quotes offsets from the start of the file, so count from there — the outer
        // header sits before every object it names.
        let mut pos = raw.len() - outer.value.len();
        let mut rest = outer.value;
        let mut offsets = None;
        let mut fields: Vec<(u32, &[u8], usize)> = Vec::new();
        while let Some(&first) = rest.first() {
            if first == 0x00 || first == 0xFF {
                break; // filler past the end of the objects
            }
            let header = ber::parse_header(rest)?;
            let end = header.total_len();
            let value = rest
                .get(header.header_len..end)
                .ok_or_else(|| malformed("a field runs past the end of the file"))?;
            if header.tag == Self::TAG_OFFSETS {
                offsets = Some(value);
            } else {
                fields.push((header.tag, value, pos));
            }
            pos += end;
            rest = &rest[end..];
        }

        let find = |tag: u32| {
            fields
                .iter()
                .find(|(t, _, _)| *t == tag)
                .map(|(_, v, _)| *v)
                .ok_or_else(|| malformed(&format!("no field with tag {tag:04X}")))
        };
        let name = find(Self::TAG_NAME)?;
        let address = find(Self::TAG_ADDRESS)?;
        let birth_date = find(Self::TAG_BIRTH_DATE)?;
        let sex = find(Self::TAG_SEX)?;

        if let Some(table) = offsets {
            let starts: Vec<usize> = fields.iter().map(|(_, _, s)| *s).collect();
            check_offsets(raw, table, &starts)?;
        }

        Ok(Attributes {
            name: decode_text(name, "氏名")?,
            address: decode_text(address, "住所")?,
            birth_date: Date::parse(birth_date)?,
            sex: Sex::from_byte(*sex.first().ok_or_else(|| malformed("性別 is empty"))?),
        })
    }

    /// The SHA-256 that 券面入力補助AP `0003` holds for this file.
    ///
    /// Not a digest of the file, nor of its trimmed TLV: it covers the outer value **with the
    /// offset table skipped**, so `DF22` to the end and nothing before. The 個人番号 file next to
    /// it is hashed differently again — whole, filler included — so neither rule generalises.
    ///
    /// Pass the file as [`TextAp::read_attributes`] reads it, trimmed to the TLV.
    pub fn digest_source(raw: &[u8]) -> Result<&[u8]> {
        let outer = ber::parse(raw)?;
        if outer.tag != Self::TAG {
            return Err(malformed(&format!(
                "expected tag FF20, got {:04X}",
                outer.tag
            )));
        }
        let table = ber::parse_header(outer.value)?;
        if table.tag != Self::TAG_OFFSETS {
            return Err(malformed("the offset table is not the first object"));
        }
        outer
            .value
            .get(table.total_len()..)
            .ok_or_else(|| malformed("nothing follows the offset table"))
    }

    /// 氏名 split on the ideographic space the card uses between the two parts.
    ///
    /// `None` if there is no separator, which happens for a mononym.
    pub fn split_name(&self) -> Option<(&str, &str)> {
        self.name.split_once('\u{3000}')
    }
}

fn decode_text(bytes: &[u8], what: &str) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| malformed(&format!("{what} is not valid UTF-8")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    /// EF 0001 of the test card, byte for byte.
    const MY_NUMBER_FILE: &[u8] = &[
        0xFF, 0x10, 0x0C, b'5', b'3', b'7', b'6', b'8', b'6', b'6', b'7', b'7', b'1', b'8', b'8',
    ];

    /// EF 0002 of the test card, byte for byte.
    fn attributes_file() -> Vec<u8> {
        let hex = "ff2065df2108000e002000590064df22\
                   0fe9bb92e6a190e38080e5b9b9e4b99f\
                   df2336e69db1e4baace983bde6b885e7\
                   80ace5b882e8a6b3e5b883e5ad90e58d\
                   97efbc91efbc92efbc8defbc97efbc8d\
                   efbc92efbc90efbc92df240831393830\
                   30323137df250131";
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn parses_the_my_number_file() {
        let n = parse_my_number(MY_NUMBER_FILE).unwrap();
        assert_eq!(n.as_str(), "537686677188");
    }

    #[test]
    fn rejects_a_my_number_file_with_the_wrong_tag() {
        let mut bad = MY_NUMBER_FILE.to_vec();
        bad[1] = 0x11;
        assert!(parse_my_number(&bad).is_err());
    }

    #[test]
    fn parses_the_basic_four_attributes() {
        let a = Attributes::parse(&attributes_file()).unwrap();
        assert_eq!(a.name, "黒桐　幹也");
        assert_eq!(a.address, "東京都清瀬市観布子南１２－７－２０２");
        assert_eq!(
            a.birth_date,
            Date {
                year: 1980,
                month: 2,
                day: 17
            }
        );
        assert_eq!(a.sex, Sex::Male);
        assert_eq!(a.split_name(), Some(("黒桐", "幹也")));
    }

    #[test]
    fn checks_the_offset_table_rather_than_trusting_it() {
        let mut file = attributes_file();
        // FF 20 65 DF 21 08 | 00 0E ... — the first offset is at bytes 6-7. Make it disagree
        // with where 氏名 actually starts.
        assert_eq!(&file[6..8], &[0x00, 0x0E]);
        file[7] = 0x0F;
        let err = Attributes::parse(&file).unwrap_err();
        assert!(format!("{err}").contains("offset 0"), "{err}");
    }

    #[test]
    fn reads_and_parses_over_a_transport() {
        let mut ok = attributes_file();
        ok.extend_from_slice(&[0x90, 0x00]);
        let mut card = Card::new(MockTransport::new([
            vec![0x90, 0x00], // SELECT DF
            vec![0x90, 0x00], // SELECT EF 0002
            ok,               // READ BINARY
        ]));
        let mut text = TextAp::select(&mut card).unwrap();
        assert_eq!(text.read_attributes().unwrap().sex, Sex::Male);
    }
}

/// This application's basic information, EF `0005`.
///
/// ```text
/// FF 40
///   DF 41 04     four bytes that identify the layout
///   DF 42 10     a key identifier, but not the one that signs this application's records
///   DF 43 80     128 bytes, purpose unknown
/// ```
///
/// Readable with nothing presented, and nothing here is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApBasicData {
    /// `DF41`, four bytes. `01 03 0E 01` on the cards seen.
    pub identification: Vec<u8>,
    /// `DF42` — a key identifier.
    ///
    /// It is **not** the key EF `0004` certifies: on the cards seen this is `x000034` while the
    /// certificate's 被証明者鍵ID is the municipality's own. What it names is not established.
    pub public_key_id: KeyId,
    /// `DF43`, 128 bytes, purpose unknown.
    ///
    /// On every card examined it is 32 bytes followed by 96 `FF`, which is the shape of a digest in
    /// a padded field — see [`digest`](Self::digest) — but nothing was found that it is a digest
    /// *of*.
    pub trailing: Vec<u8>,
}

impl ApBasicData {
    /// Tag of the file.
    pub const TAG: u32 = 0xFF40;

    /// The first 32 bytes of [`trailing`](Self::trailing), if the rest is `FF` filler.
    ///
    /// `None` when the field is shaped differently, rather than a guess about what it holds.
    pub fn digest(&self) -> Option<&[u8]> {
        let (head, filler) = self.trailing.split_at_checked(32)?;
        filler.iter().all(|b| *b == 0xFF).then_some(head)
    }

    /// Parse EF `0005`.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let f = TlvFields::parse(raw, Self::TAG, None)?;
        Ok(ApBasicData {
            identification: f.get(0xDF41)?.to_vec(),
            public_key_id: KeyId::parse(f.get(0xDF42)?)?,
            trailing: f.get(0xDF43)?.to_vec(),
        })
    }
}

/// The integrity record of EF `0003`.
///
/// ```text
/// FF 30 82 01 4B
///   DF 31 20 <32 B>    SHA-256 of the 個人番号 file
///   DF 32 20 <32 B>    SHA-256 of the 基本4情報 file
///   DF 33 8201 00      RSA-2048 signature
/// ```
///
/// The two digests are taken over different things, which is easy to get wrong: `DF31` covers the
/// 個人番号 file exactly as stored, filler included, while `DF32` covers the 基本4情報 file's outer
/// value with the offset table skipped.
///
/// The signature is made by the key certified in EF `0004` — the same issuer key that signs the
/// 券面事項確認AP records, not the card's own key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityRecord {
    /// SHA-256 of the 個人番号 file, over its **physical** content including the filler bytes.
    /// See [`IntegrityRecord::matches_my_number_file`].
    pub my_number_digest: [u8; 32],
    /// SHA-256 of the 基本4情報 file, over its outer value **with the offset table skipped**.
    /// See [`IntegrityRecord::matches_attributes_file`].
    pub attributes_digest: [u8; 32],
    /// Signature over everything before it.
    pub signature: Vec<u8>,
    /// Exactly the bytes the signature covers.
    pub signed_data: Vec<u8>,
}

impl IntegrityRecord {
    /// Tag of the file.
    pub const TAG: u32 = 0xFF30;

    /// Parse EF `0003`.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let f = TlvFields::parse(raw, Self::TAG, None)?;
        let digest = |tag: u32| -> Result<[u8; 32]> {
            <[u8; 32]>::try_from(f.get(tag)?)
                .map_err(|_| malformed(&format!("{tag:04X} is not a 32 byte digest")))
        };
        Ok(IntegrityRecord {
            my_number_digest: digest(0xDF31)?,
            attributes_digest: digest(0xDF32)?,
            signature: f.get(0xDF33)?.to_vec(),
            signed_data: f.bytes_before(0xDF33)?.to_vec(),
        })
    }

    /// Whether `attributes` is the 基本4情報 file this record vouches for.
    ///
    /// Pass the file as [`TextAp::read_attributes`] reads it. Unlike the 個人番号 digest, this one
    /// covers neither the filler nor the offset table — see [`Attributes::digest_source`].
    #[cfg(feature = "verify")]
    pub fn matches_attributes_file(&self, attributes: &[u8]) -> Result<bool> {
        let source = Attributes::digest_source(attributes)?;
        Ok(crate::data::sha256(source) == self.attributes_digest)
    }

    /// Whether `physical` is the 個人番号 file this record vouches for.
    ///
    /// Pass what [`Card::read_binary_physical`](crate::Card::read_binary_physical) returns for
    /// EF `0001`, not what [`TextAp::read_my_number`] parsed — the digest covers the file as
    /// stored, filler and all.
    #[cfg(feature = "verify")]
    pub fn matches_my_number_file(&self, physical: &[u8]) -> bool {
        crate::data::sha256(physical) == self.my_number_digest
    }
}

/// The session key encryption public key of EF `0006`.
///
/// A bare RSA-2048 key under tag `A1`, with no signature beside it — a terminal encrypts a session
/// key to it. It is not the key that signs this application's records, which is certified in EF
/// `0004`, and not the card's own signing key either, which lives in EF `0007`; nothing on the
/// card verifies under it, and nothing should.
///
/// Nothing here is secret. The modulus is readable by anyone who can present the PIN or either
/// 照合番号, which is also why the card's habit of answering `6F00` for a ciphertext at or above
/// the modulus and `6A80` for one below it costs nothing: it distinguishes what the reader can
/// already compute. Pass this to [`TextAp::open_secure_session`] rather than using it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeyPublicKey {
    /// The key.
    pub public_key: RsaPublicKey,
}

impl SessionKeyPublicKey {
    /// Tag of the file.
    pub const TAG: u32 = 0xA1;

    /// Parse EF `0006`.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let outer = ber::parse(raw)?;
        if outer.tag != Self::TAG {
            return Err(malformed(&format!(
                "expected tag A1, got {:04X}",
                outer.tag
            )));
        }
        Ok(SessionKeyPublicKey {
            public_key: RsaPublicKey::parse(outer.value)?,
        })
    }
}

/// The signed public key of EF `0007`.
///
/// ```text
/// FF 50 82 02 13
///   DF 51 8201 09   RSA-2048 public key
///   DF 52 8201 00   RSA-2048 signature
/// ```
///
/// `DF51` is the public half of `0013`, the key this application signs challenges with. `DF52` is
/// the issuer's signature over it, so verifying this record ties the card's signing key to the
/// certificate in EF `0004`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPublicKey {
    /// The public half of the key EF `0013` signs with.
    pub public_key: RsaPublicKey,
    /// Signature over it.
    pub signature: Vec<u8>,
    /// Exactly the bytes the signature covers.
    pub signed_data: Vec<u8>,
}

impl SignedPublicKey {
    /// Tag of the file.
    pub const TAG: u32 = 0xFF50;

    /// Parse EF `0007`.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let f = TlvFields::parse(raw, Self::TAG, None)?;
        Ok(SignedPublicKey {
            public_key: RsaPublicKey::parse(f.get(0xDF51)?)?,
            signature: f.get(0xDF52)?.to_vec(),
            signed_data: f.bytes_before(0xDF52)?.to_vec(),
        })
    }
}

#[cfg(feature = "verify")]
mod verify {
    use super::{IntegrityRecord, SignedPublicKey};
    use crate::data::RsaPublicKey;
    use crate::error::Result;

    impl IntegrityRecord {
        /// Check the signature against the key certified in EF `0004`.
        pub fn verify(&self, issuer: &RsaPublicKey) -> Result<()> {
            issuer.verify_pkcs1_sha256(&self.signed_data, &self.signature)
        }
    }

    impl SignedPublicKey {
        /// Check the signature against the key certified in EF `0004`.
        pub fn verify(&self, issuer: &RsaPublicKey) -> Result<()> {
            issuer.verify_pkcs1_sha256(&self.signed_data, &self.signature)
        }
    }
}
