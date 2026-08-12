//! 券面事項確認AP — the card surface verification application.
//!
//! Holds the data printed on the face of the card, so that a relying party can check that the
//! physical card matches its chip. Access is gated on 照合番号A and 照合番号B, both derived from
//! what is printed on the card, which is what makes possession of the card itself the credential.
//!
//! Three keys open three different amounts, and the amount tracks how much the terminal already
//! knows: the 生年月日 alone opens the age verification record, 照合番号B opens the card face, and
//! 照合番号A opens the card face plus the rendered 個人番号.

use crate::card::{Card, Retries};
use crate::data::{
    CardVerifiableCertificate, Date, Image, KeyId, RsaPublicKey, Sex, TlvFields, malformed,
};
use crate::error::{Error, Result};
use crate::pin::Pin;
use crate::transport::Transmit;

/// AID of the card surface verification application.
pub const DF: [u8; 10] = [0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x02];

/// File identifiers within the card surface verification application.
pub mod ef {
    /// Date of birth, its public key and a signature. Unlocked by the 生年月日 key.
    pub const AGE_RECORD: u16 = 0x0001;
    /// The card face: date of birth, sex, expiry, the rendered fields and the photograph.
    /// Unlocked by either 照合番号.
    pub const CARD_FACE: u16 = 0x0002;
    /// This application's basic information: an identifier, the key it names, the municipality
    /// code, and the 照合番号 in encrypted form.
    pub const AP_BASIC_DATA: u16 = 0x0003;
    /// This application's own card-verifiable certificate.
    pub const CERTIFICATE: u16 = 0x0004;
    /// The rendered 個人番号, with its public key and a signature. Unlocked by 照合番号A only.
    pub const MY_NUMBER_IMAGE: u16 = 0x0005;
    /// Purpose not yet identified.
    pub const UNKNOWN_0006: u16 = 0x0006;
    /// Key reference for the 生年月日, 和暦 `YYMMDD`.
    pub const BIRTH_DATE: u16 = 0x0011;
    /// Key reference for 照合番号B.
    pub const CODE_B: u16 = 0x0012;
    /// Key reference for 照合番号A.
    pub const CODE_A: u16 = 0x0013;
}

/// The card surface verification application, selected on a card.
#[derive(Debug)]
pub struct SurfaceAp<'a, T> {
    card: &'a mut Card<T>,
}

impl<'a, T: Transmit> SurfaceAp<'a, T> {
    /// Select the application.
    pub fn select(card: &'a mut Card<T>) -> Result<Self> {
        card.select_df(&DF)?;
        Ok(SurfaceAp { card })
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

    /// Read this application's basic information from EF `0003`.
    ///
    /// Readable with nothing presented.
    pub fn read_ap_basic_data(&mut self) -> Result<ApBasicData> {
        let raw = self.read_ef(ef::AP_BASIC_DATA)?;
        ApBasicData::parse(&raw)
    }

    /// Read the age verification record of EF `0001`.
    ///
    /// Requires a VERIFY of the 生年月日 key, [`SurfaceAp::verify_birth_date`]. Check it against
    /// [`SurfaceAp::read_certificate`]'s key with `AgeRecord::verify`.
    pub fn read_age_record(&mut self) -> Result<AgeRecord> {
        let raw = self.read_ef(ef::AGE_RECORD)?;
        AgeRecord::parse(&raw)
    }

    /// Read the card face data of EF `0002`.
    ///
    /// Requires a VERIFY of either 照合番号.
    pub fn read_card_face(&mut self) -> Result<CardFace> {
        let raw = self.read_ef(ef::CARD_FACE)?;
        CardFace::parse(&raw)
    }

    /// Read the rendered 個人番号 of EF `0005`.
    ///
    /// Requires [`SurfaceAp::verify_code_a`]; 照合番号B does not open this one.
    pub fn read_my_number_image(&mut self) -> Result<MyNumberImage> {
        let raw = self.read_ef(ef::MY_NUMBER_IMAGE)?;
        MyNumberImage::parse(&raw)
    }

    /// Read this application's own card-verifiable certificate, EF `0004`.
    ///
    /// Readable with nothing presented.
    pub fn read_certificate(&mut self) -> Result<CardVerifiableCertificate> {
        let raw = self.read_ef(ef::CERTIFICATE)?;
        CardVerifiableCertificate::parse(&raw)
    }

    /// Sign `data` with this application's own key — the one whose public half travels inside the
    /// signed records, and which needs no credential.
    ///
    /// Hashing happens here: the card is handed a SHA-256 `DigestInfo`, and P2 is `00`, which
    /// selects the application's default key. That is exactly what the issuer's own SDK sends.
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

    /// Present the 生年月日, six digits `YYMMDD` in the Japanese era year.
    ///
    /// This is the first six digits of 照合番号B on its own, and opens only the age verification
    /// record — the least a terminal can be told.
    pub fn verify_birth_date(&mut self, code: &Pin) -> Result<()> {
        self.card.select_ef(ef::BIRTH_DATE)?;
        self.card.verify(code)
    }

    /// Present 照合番号A.
    pub fn verify_code_a(&mut self, code: &Pin) -> Result<()> {
        self.card.select_ef(ef::CODE_A)?;
        self.card.verify(code)
    }

    /// Present 照合番号B.
    pub fn verify_code_b(&mut self, code: &Pin) -> Result<()> {
        self.card.select_ef(ef::CODE_B)?;
        self.card.verify(code)
    }

    /// Attempts remaining on one of this application's key references, without spending one.
    ///
    /// Pass [`ef::BIRTH_DATE`], [`ef::CODE_A`] or [`ef::CODE_B`].
    pub fn retries(&mut self, key: u16) -> Result<Retries> {
        self.card.select_ef(key)?;
        self.card.pin_retries()
    }
}

/// This application's basic information, EF `0003`.
///
/// ```text
/// FF 30
///   DF 31 04     four bytes that identify the layout
///   DF 32 10     a key identifier, but not the one that signs this application's records
///   DF 33 01     version
///   DF 34 05     全国地方公共団体コード of the issuing municipality
///   DF 35 8201 10  a key identifier, then 256 bytes: the 照合番号 encrypted under that key
/// ```
///
/// Nothing here is secret — the file opens with no credential — and nothing here is signed. The
/// municipality code repeats what 共通カードAP `0001` says, which is a cheap consistency check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApBasicData {
    /// `DF31`, four bytes. Identifies the layout; `06 03 0E 01` on the cards seen.
    pub identification: Vec<u8>,
    /// `DF32` — a key identifier, which the issuer's SDK calls simply the public key.
    ///
    /// It is **not** the key EF `0004` certifies: on the cards seen this is `x000024` while the
    /// certificate's 被証明者鍵ID is the municipality's own. What it names is not established.
    pub public_key_id: KeyId,
    /// `DF33`, one byte.
    pub version: u8,
    /// `DF34` — five digits, the 全国地方公共団体コード.
    pub municipality_code: String,
    /// `DF35` — the 照合番号 in encrypted form, and the key it is encrypted under.
    ///
    /// The private half is held by the issuer, so this is of no use to a reader; it is here
    /// because leaving a field out of a parser hides it.
    pub encrypted_reference_number: EncryptedReferenceNumber,
}

/// The 照合番号 as EF `0003` carries it: which key it is encrypted under, and the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedReferenceNumber {
    /// The key the issuer encrypted it to.
    pub key_id: KeyId,
    /// 256 bytes — one RSA-2048 block.
    pub data: Vec<u8>,
}

impl ApBasicData {
    /// Tag of the file.
    pub const TAG: u32 = 0xFF30;

    /// Parse EF `0003`.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let f = TlvFields::parse(raw, Self::TAG, None)?;
        let version = f.get(0xDF33)?;
        let encrypted = f.get(0xDF35)?;
        let (key_id, data) = encrypted.split_at_checked(KeyId::LEN).ok_or_else(|| {
            Error::Malformed(format!(
                "encrypted 照合番号 is {} bytes, too short to name a key",
                encrypted.len()
            ))
        })?;
        Ok(ApBasicData {
            identification: f.get(0xDF31)?.to_vec(),
            public_key_id: KeyId::parse(f.get(0xDF32)?)?,
            version: *version
                .first()
                .ok_or_else(|| Error::Malformed("version field is empty".into()))?,
            municipality_code: String::from_utf8_lossy(f.get(0xDF34)?).into_owned(),
            encrypted_reference_number: EncryptedReferenceNumber {
                key_id: KeyId::parse(key_id)?,
                data: data.to_vec(),
            },
        })
    }
}

/// The age verification record of EF `0001`.
///
/// ```text
/// FF 10 82 02 1E
///   DF 11 08      YYYYMMDD                    生年月日
///   DF 12 8201 09 90 03 010001 / 91 8201 00   RSA-2048 public key
///   DF 13 8201 00 <256 B>                     signature
/// ```
///
/// Minimal by design: one field, the key needed to check it, and a signature. A terminal that only
/// needs to confirm an age is given the six digit 生年月日 key and gets this and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgeRecord {
    /// 生年月日, Gregorian.
    pub birth_date: Date,
    /// The card's public key, the same one carried by [`CardFace`] and [`MyNumberImage`].
    pub public_key: RsaPublicKey,
    /// Signature over the record, made by the key certified in `0004`.
    pub signature: Vec<u8>,
    /// Exactly the bytes [`AgeRecord::signature`] covers: every object before it, as written.
    pub signed_data: Vec<u8>,
}

impl AgeRecord {
    /// Tag of the file.
    pub const TAG: u32 = 0xFF10;

    /// Parse EF `0001`.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        // No offset table: DF11 is the date of birth, and the fields are fixed size anyway.
        let f = TlvFields::parse(raw, Self::TAG, None)?;
        Ok(AgeRecord {
            birth_date: Date::parse(f.get(0xDF11)?)?,
            public_key: RsaPublicKey::parse(f.get(0xDF12)?)?,
            signature: f.get(0xDF13)?.to_vec(),
            signed_data: f.bytes_before(0xDF13)?.to_vec(),
        })
    }
}

/// The card face data of EF `0002`.
///
/// Nine objects behind an offset table: the two text fields as text, the same two rendered as
/// images, the photograph, and a signature over the lot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardFace {
    /// 生年月日, Gregorian.
    pub birth_date: Date,
    /// 性別.
    pub sex: Sex,
    /// The card's public key.
    pub public_key: RsaPublicKey,
    /// 氏名 as printed, a 1-bit image.
    pub name_image: Image,
    /// 住所 as printed, a 1-bit image.
    pub address_image: Image,
    /// 顔写真. JPEG 2000, greyscale — not JPEG.
    pub photo: Image,
    /// Signature over the record, made by the key certified in `0004`.
    pub signature: Vec<u8>,
    /// Expiry date. Note that this sits *after* the signature and is not covered by it.
    pub expiry: Date,
    /// The security code printed on the card face, rendered. 24×12 on the card surveyed. Also
    /// after the signature, and also not covered by it.
    pub security_code_image: Image,
    /// The three groups the signature covers, each hashed separately. See [`CardFace::verify`].
    pub signed_segments: [Vec<u8>; 3],
}

impl CardFace {
    /// Tag of the file.
    pub const TAG: u32 = 0xFF20;
    /// Tag of the offset table, the only one of these files to carry one.
    pub const TAG_OFFSETS: u32 = 0xDF21;

    /// Parse EF `0002`.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let f = TlvFields::parse(raw, Self::TAG, Some(Self::TAG_OFFSETS))?;
        Ok(CardFace {
            birth_date: Date::parse(f.get(0xDF22)?)?,
            sex: Sex::from_byte(
                *f.get(0xDF23)?
                    .first()
                    .ok_or_else(|| malformed("性別 is empty"))?,
            ),
            public_key: RsaPublicKey::parse(f.get(0xDF24)?)?,
            name_image: Image::new(f.get(0xDF25)?.to_vec()),
            address_image: Image::new(f.get(0xDF26)?.to_vec()),
            photo: Image::new(f.get(0xDF27)?.to_vec()),
            signature: f.get(0xDF28)?.to_vec(),
            expiry: Date::parse(f.get(0xDF29)?)?,
            security_code_image: Image::new(f.get(0xDF2A)?.to_vec()),
            signed_segments: [
                f.bytes_of(&[0xDF22, 0xDF23, 0xDF24])?,
                f.bytes_of(&[0xDF25, 0xDF26])?,
                f.bytes_of(&[0xDF27])?,
            ],
        })
    }
}

/// The rendered 個人番号 of EF `0005`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyNumberImage {
    /// The 個人番号 as printed, a 1-bit image. 72×12 on the card surveyed.
    pub image: Image,
    /// The card's public key.
    pub public_key: RsaPublicKey,
    /// Signature over the record, made by the key certified in `0004`.
    pub signature: Vec<u8>,
    /// Exactly the bytes [`MyNumberImage::signature`] covers.
    pub signed_data: Vec<u8>,
}

impl MyNumberImage {
    /// Tag of the file.
    pub const TAG: u32 = 0xFF40;

    /// Parse EF `0005`.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        // No offset table: DF41 is the image itself.
        let f = TlvFields::parse(raw, Self::TAG, None)?;
        Ok(MyNumberImage {
            image: Image::new(f.get(0xDF41)?.to_vec()),
            public_key: RsaPublicKey::parse(f.get(0xDF42)?)?,
            signature: f.get(0xDF43)?.to_vec(),
            signed_data: f.bytes_before(0xDF43)?.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::ImageFormat;

    /// Build a BER object with a two byte tag and a definite length.
    fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        if value.len() < 0x80 {
            out.push(value.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(value);
        out
    }

    fn public_key() -> Vec<u8> {
        let mut k = vec![0x90, 0x03, 0x01, 0x00, 0x01, 0x91, 0x82, 0x01, 0x00, 0xC9];
        k.extend(std::iter::repeat_n(0xAA, 255));
        k
    }

    fn png() -> Vec<u8> {
        let mut p = b"\x89PNG\r\n\x1a\n".to_vec();
        p.extend_from_slice(b"\x00\x00\x00\x0DIHDR\x00\x00\x00\x48\x00\x00\x00\x0C\x01\x00");
        p
    }

    /// Assemble a file with a correct offset table, the way the card writes one.
    fn with_offsets(outer_tag: u16, table_tag: u16, fields: &[Vec<u8>]) -> Vec<u8> {
        let table_len = fields.len() * 2;
        let table = tlv(table_tag, &vec![0u8; table_len]);
        let body_len = table.len() + fields.iter().map(Vec::len).sum::<usize>();
        let header_len = if body_len < 0x80 { 3 } else { 5 };

        let mut offsets = Vec::new();
        let mut pos = header_len + table.len();
        for f in fields {
            offsets.extend_from_slice(&(pos as u16).to_be_bytes());
            pos += f.len();
        }
        let mut body = tlv(table_tag, &offsets);
        for f in fields {
            body.extend_from_slice(f);
        }
        tlv(outer_tag, &body)
    }

    #[test]
    fn parses_the_age_record() {
        // EF 0001 has no offset table, so build it field by field.
        let mut body = tlv(0xDF11, b"19800217");
        body.extend_from_slice(&tlv(0xDF12, &public_key()));
        body.extend_from_slice(&tlv(0xDF13, &[0xBC; 256]));
        let raw = tlv(0xFF10, &body);

        let rec = AgeRecord::parse(&raw).unwrap();
        assert_eq!(
            rec.birth_date,
            Date {
                year: 1980,
                month: 2,
                day: 17
            }
        );
        assert_eq!(rec.public_key.bits(), 2048);
        assert_eq!(rec.signature.len(), 256);
    }

    #[test]
    fn parses_the_card_face() {
        let raw = with_offsets(
            0xFF20,
            0xDF21,
            &[
                tlv(0xDF22, b"19800217"),
                tlv(0xDF23, b"1"),
                tlv(0xDF24, &public_key()),
                tlv(0xDF25, &png()),
                tlv(0xDF26, &png()),
                tlv(0xDF27, b"\x00\x00\x00\x0CjP  \r\n\x87\n"),
                tlv(0xDF28, &[0xBC; 256]),
                tlv(0xDF29, b"20350217"),
                tlv(0xDF2A, &png()),
            ],
        );
        let face = CardFace::parse(&raw).unwrap();
        assert_eq!(
            face.birth_date,
            Date {
                year: 1980,
                month: 2,
                day: 17
            }
        );
        assert_eq!(face.sex, Sex::Male);
        assert_eq!(
            face.expiry,
            Date {
                year: 2035,
                month: 2,
                day: 17
            }
        );
        assert_eq!(face.name_image.format, ImageFormat::Png);
        assert_eq!(face.photo.format, ImageFormat::Jpeg2000);
        assert_eq!(face.signature.len(), 256);
    }

    #[test]
    fn parses_the_my_number_image() {
        // EF 0005 has no offset table either; DF41 is the image.
        let mut body = tlv(0xDF41, &png());
        body.extend_from_slice(&tlv(0xDF42, &public_key()));
        body.extend_from_slice(&tlv(0xDF43, &[0xBC; 256]));
        let raw = tlv(0xFF40, &body);

        let img = MyNumberImage::parse(&raw).unwrap();
        assert_eq!(img.image.format, ImageFormat::Png);
        assert_eq!(img.public_key.bits(), 2048);
    }

    #[test]
    fn a_wrong_offset_table_is_rejected() {
        let mut raw = with_offsets(
            0xFF20,
            0xDF21,
            &[
                tlv(0xDF22, b"19800217"),
                tlv(0xDF23, b"1"),
                tlv(0xDF24, &public_key()),
                tlv(0xDF25, &png()),
                tlv(0xDF26, &png()),
                tlv(0xDF27, b"\x00\x00\x00\x0CjP  \r\n\x87\n"),
                tlv(0xDF28, &[0xBC; 256]),
                tlv(0xDF29, b"20350217"),
                tlv(0xDF2A, &png()),
            ],
        );
        // Corrupt the last byte of the first offset in DF21.
        let i = raw.iter().position(|&b| b == 0xDF).unwrap() + 3 + 1;
        raw[i] = raw[i].wrapping_add(1);
        assert!(CardFace::parse(&raw).is_err());
    }
}

/// Signature checking for this application's records.
///
/// The three data files are each signed by a key that is **not** the card's own. The card's key —
/// the one in `DF12`, `DF24` and `DF42`, and the one `001A` signs challenges with — proves the
/// card is present. The data is signed by the key certified in EF `0004`, which is what
/// [`SurfaceAp::read_certificate`] returns.
///
/// So a full check is two steps, and both matter:
///
/// 1. Verify the record against the certified key, proving the data is authentic.
/// 2. Challenge the card with `80 2A` and check the result against the public key *inside* the
///    record, proving the card holding that data is the one in front of you.
///
/// Step 1 is what these methods do.
#[cfg(feature = "verify")]
mod verify {
    use super::{AgeRecord, CardFace, MyNumberImage};
    use crate::data::{RsaPublicKey, sha256, sha256_digest_info};
    use crate::error::Result;

    impl AgeRecord {
        /// Check the signature against the key certified in EF `0004`.
        pub fn verify(&self, issuer: &RsaPublicKey) -> Result<()> {
            issuer.verify_pkcs1_sha256(&self.signed_data, &self.signature)
        }
    }

    impl MyNumberImage {
        /// Check the signature against the key certified in EF `0004`.
        pub fn verify(&self, issuer: &RsaPublicKey) -> Result<()> {
            issuer.verify_pkcs1_sha256(&self.signed_data, &self.signature)
        }
    }

    impl CardFace {
        /// Check the signature against the key certified in EF `0004`.
        ///
        /// This record is signed differently from the other two. Rather than one digest over the
        /// whole thing, the fields are grouped and each group hashed separately, and the three
        /// digests are concatenated into a single `DigestInfo`:
        ///
        /// | Group | Fields |
        /// |---|---|
        /// | 1 | `DF22` 生年月日, `DF23` 性別, `DF24` public key |
        /// | 2 | `DF25` name image, `DF26` address image |
        /// | 3 | `DF27` photograph |
        ///
        /// The shape follows from what the card is for: a terminal can be handed group 1 and the
        /// digests of groups 2 and 3, and still check the signature without ever receiving the
        /// photograph. Note also that `DF29` 有効期限 and `DF2A` come after the signature and are
        /// not covered by it.
        pub fn verify(&self, issuer: &RsaPublicKey) -> Result<()> {
            let mut digests = Vec::with_capacity(96);
            for segment in &self.signed_segments {
                digests.extend_from_slice(&sha256(segment));
            }
            issuer.verify_pkcs1(&sha256_digest_info(&digests), &self.signature)
        }
    }
}
