//! The values the card stores, and the credentials derived from them.
//!
//! JICSAP specifies the containers — transparent and record structured files, and the two TLV
//! encodings — but says nothing about what any application puts inside them, so every layout here
//! was established by reading a physical card and is described on the type that parses it.

use std::fmt;

use crate::error::{Error, Result};
use crate::pin::Pin;
use crate::tlv::ber;

/// The four-byte identification field in an application's basic-data file.
///
/// The bytes are stored in this order:
///
/// ```text
/// 00  specification version
/// 01  extended Lc/Le support status
/// 02  vendor identifier
/// 03  vendor-specific value
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApIdentification {
    /// Byte 0: specification version.
    pub specification_version: u8,
    /// Byte 1: extended Lc/Le support status.
    pub extended_lc_le_support: u8,
    /// Byte 2: vendor identifier.
    pub vendor_id: u8,
    /// Byte 3: vendor-specific value.
    pub vendor_specific: u8,
}

impl ApIdentification {
    /// Encoded length of the field.
    pub const LEN: usize = 4;

    /// Parse the four bytes of an application-identification field.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `bytes` is not exactly four bytes long.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let [
            specification_version,
            extended_lc_le_support,
            vendor_id,
            vendor_specific,
        ] = <[u8; Self::LEN]>::try_from(bytes).map_err(|_| {
            malformed(&format!(
                "AP identification must be 4 bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self {
            specification_version,
            extended_lc_le_support,
            vendor_id,
            vendor_specific,
        })
    }

    /// Encode the field in its original byte order.
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        [
            self.specification_version,
            self.extended_lc_le_support,
            self.vendor_id,
            self.vendor_specific,
        ]
    }
}

/// A calendar date, as the card writes it: eight ASCII digits, `YYYYMMDD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    /// Gregorian year.
    pub year: u16,
    /// Month, 1 to 12.
    pub month: u8,
    /// Day, 1 to 31.
    pub day: u8,
}

impl Date {
    /// Parse eight ASCII digits, `YYYYMMDD`.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)
            .ok()
            .filter(|s| s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| malformed(&format!("expected 8 digits, got {}", hex(bytes))))?;
        let date = Date {
            year: text[0..4].parse().unwrap(),
            month: text[4..6].parse().unwrap(),
            day: text[6..8].parse().unwrap(),
        };
        if !(1..=12).contains(&date.month) || !(1..=31).contains(&date.day) {
            return Err(malformed(&format!("not a calendar date: {date}")));
        }
        Ok(date)
    }

    /// The date a Unix timestamp falls on, in UTC.
    ///
    /// Used for certificate validity, which the card records to the second; the time of day is
    /// dropped.
    pub fn from_unix_seconds(seconds: i64) -> Self {
        // Howard Hinnant's civil_from_days, with the era shifted so March starts the year and
        // the leap day lands at the end of it.
        let days = seconds.div_euclid(86_400) + 719_468;
        let era = days.div_euclid(146_097);
        let doe = days.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
        let year = (yoe + era * 400 + i64::from(month <= 2)) as u16;
        Date { year, month, day }
    }

    /// The Japanese era this date falls in, and the year within it.
    ///
    /// `None` before the Meiji era began on 1868-01-25.
    pub fn to_era(self) -> Option<(Era, u16)> {
        let key = (self.year, self.month, self.day);
        let era = match key {
            k if k >= (2019, 5, 1) => Era::Reiwa,
            k if k >= (1989, 1, 8) => Era::Heisei,
            k if k >= (1926, 12, 25) => Era::Showa,
            k if k >= (1912, 7, 30) => Era::Taisho,
            k if k >= (1868, 1, 25) => Era::Meiji,
            _ => return None,
        };
        Some((era, self.year - era.first_gregorian_year() + 1))
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// A Japanese era.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(missing_docs)]
pub enum Era {
    Meiji,
    Taisho,
    Showa,
    Heisei,
    Reiwa,
}

impl Era {
    /// The Gregorian year in which era year 1 falls.
    pub const fn first_gregorian_year(self) -> u16 {
        match self {
            Era::Meiji => 1868,
            Era::Taisho => 1912,
            Era::Showa => 1926,
            Era::Heisei => 1989,
            Era::Reiwa => 2019,
        }
    }

    /// The era's name in Japanese.
    pub const fn name(self) -> &'static str {
        match self {
            Era::Meiji => "明治",
            Era::Taisho => "大正",
            Era::Showa => "昭和",
            Era::Heisei => "平成",
            Era::Reiwa => "令和",
        }
    }
}

/// Sex, as one ASCII digit.
///
/// The card follows JIS X 0303. Only `1` has been seen on a real card; the rest are decoded from
/// the standard, and anything else is preserved rather than rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sex {
    /// `1`.
    Male,
    /// `2`.
    Female,
    /// `0` — not known.
    Unknown,
    /// `9` — not applicable.
    NotApplicable,
    /// Anything else, kept as written.
    Other(u8),
}

impl Sex {
    /// Decode the single byte the card stores.
    pub const fn from_byte(b: u8) -> Self {
        match b {
            b'0' => Sex::Unknown,
            b'1' => Sex::Male,
            b'2' => Sex::Female,
            b'9' => Sex::NotApplicable,
            other => Sex::Other(other),
        }
    }
}

/// An 個人番号 — twelve decimal digits.
///
/// Also the value of 照合番号A; see [`MyNumber::as_verification_code_a`].
#[derive(Clone, PartialEq, Eq)]
pub struct MyNumber([u8; 12]);

impl MyNumber {
    /// Parse twelve ASCII digits.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let digits: [u8; 12] = bytes
            .try_into()
            .ok()
            .filter(|d: &[u8; 12]| d.iter().all(u8::is_ascii_digit))
            .ok_or_else(|| malformed(&format!("個人番号 must be 12 digits, got {}", hex(bytes))))?;
        Ok(MyNumber(digits))
    }

    /// The twelve digits, as ASCII.
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// The twelve digits, as a string.
    pub fn as_str(&self) -> &str {
        // Every byte was checked to be an ASCII digit when this was built.
        std::str::from_utf8(&self.0).expect("digits are ASCII")
    }

    /// 照合番号A, which is the 個人番号 itself.
    ///
    /// Confirmed on a card: this value unlocks 券面入力補助AP `0001`, and that file returns the
    /// same twelve digits.
    pub fn as_verification_code_a(&self) -> Result<Pin> {
        Pin::numeric(self.0)
    }
}

/// Redacted; an 個人番号 should not reach a log by accident.
impl fmt::Debug for MyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MyNumber(<12 digits redacted>)")
    }
}

/// Build 照合番号B from the three things printed on the card.
///
/// Fourteen digits: the date of birth as `YYMMDD` in the **Japanese era year**, the Gregorian year
/// the card expires, and the four digit security code. Confirmed on a card — a date of birth of
/// 1980-02-17 (昭和55) with an expiry in 2035 and security code `2285` gives `55021720352285`.
///
/// # Only four of the fourteen digits are off the chip
///
/// 照合番号A opens 券面事項確認AP `0002`, and that file carries both the date of birth and the
/// expiry — the first ten digits of this value, confirmed by reading `2035` out of it on the card
/// the example above comes from. A party holding 照合番号A, which is the 個人番号, therefore has
/// everything here but the security code, and that is four digits against a counter of ten
/// attempts.
///
/// The consequence is smaller than it first sounds, because 照合番号A already opens the rendered
/// card face: what 照合番号B adds is the 基本4情報 as UTF-8 rather than as an image of the same
/// fields. It is worth knowing all the same that the two 照合番号 are not independent secrets.
///
/// # Errors
///
/// Returns [`Error::Malformed`] if the date of birth predates the Meiji era or its era year
/// exceeds two digits, and [`Error::InvalidPin`] if the security code is not four digits.
pub fn verification_code_b(
    birth_date: Date,
    expiry_year: u16,
    security_code: &[u8],
) -> Result<Pin> {
    let (_, era_year) = birth_date
        .to_era()
        .ok_or_else(|| malformed(&format!("{birth_date} predates the Meiji era")))?;
    if era_year > 99 {
        return Err(malformed(&format!(
            "era year {era_year} does not fit in two digits"
        )));
    }
    if security_code.len() != 4 || !security_code.iter().all(u8::is_ascii_digit) {
        return Err(Error::InvalidPin("security code must be 4 digits"));
    }
    let text = format!(
        "{:02}{:02}{:02}{:04}{}",
        era_year,
        birth_date.month,
        birth_date.day,
        expiry_year,
        std::str::from_utf8(security_code).expect("digits are ASCII"),
    );
    Pin::numeric(text)
}

/// An RSA public key, as the card stores it: tag `90` for the exponent, `91` for the modulus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    /// Public exponent, big-endian.
    pub exponent: Vec<u8>,
    /// Modulus, big-endian.
    pub modulus: Vec<u8>,
}

impl RsaPublicKey {
    /// Tag of the public exponent.
    pub const TAG_EXPONENT: u32 = 0x90;
    /// Tag of the modulus.
    pub const TAG_MODULUS: u32 = 0x91;

    /// Parse the concatenated `90` and `91` objects.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut exponent = None;
        let mut modulus = None;
        for tlv in ber::iter(data) {
            let tlv = tlv?;
            match tlv.tag {
                Self::TAG_EXPONENT => exponent = Some(tlv.value.to_vec()),
                Self::TAG_MODULUS => modulus = Some(tlv.value.to_vec()),
                _ => {}
            }
        }
        Ok(RsaPublicKey {
            exponent: exponent.ok_or_else(|| malformed("no public exponent (tag 90)"))?,
            modulus: modulus.ok_or_else(|| malformed("no modulus (tag 91)"))?,
        })
    }

    /// Modulus size in bits, which is the key size.
    pub fn bits(&self) -> usize {
        match self.modulus.iter().position(|&b| b != 0) {
            Some(first) => {
                (self.modulus.len() - first) * 8 - self.modulus[first].leading_zeros() as usize
            }
            None => 0,
        }
    }
}

/// A 16 byte key identifier — 証明者鍵ID, 被証明者鍵ID, and the references the 券面 applications'
/// basic information files carry.
///
/// ```text
/// "6000024" 08 05 "001" 00 00 00 00
///  ^^^^^^^ number      ^^^ group    ^^^^^^^^^^^ padding, whose last byte is not always zero
/// ```
///
/// It names a *key*, not an issuer: the same organisation appears under several of these. The
/// leading digit separates hierarchies — production identifiers begin `5`, the JPKI test
/// hierarchy's begin `6`.
///
/// Comparison and lookup use all 16 bytes, so a certificate from one hierarchy never resolves to
/// the other's key by accident.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId([u8; Self::LEN]);

impl KeyId {
    /// Length of the identifier.
    pub const LEN: usize = 16;

    /// Take the identifier from exactly 16 bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the slice is not 16 bytes long, or if the two digit groups are not
    /// ASCII digits.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; Self::LEN] = bytes.try_into().map_err(|_| {
            malformed(&format!(
                "key identifier must be 16 bytes, got {}",
                bytes.len()
            ))
        })?;
        if !bytes[..7].iter().all(u8::is_ascii_digit)
            || !bytes[9..12].iter().all(u8::is_ascii_digit)
        {
            return Err(malformed("key identifier is not digits where it should be"));
        }
        Ok(KeyId(bytes))
    }

    /// The seven digit number that names the key.
    pub fn number(&self) -> &str {
        std::str::from_utf8(&self.0[..7]).unwrap_or("???????")
    }

    /// The three digit group that follows it.
    pub fn group(&self) -> &str {
        std::str::from_utf8(&self.0[9..12]).unwrap_or("???")
    }

    /// All 16 bytes.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Display for KeyId {
    /// `6000024/001` — the two digit groups, which is what identifies the key to a reader.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.number(), self.group())
    }
}

impl fmt::Debug for KeyId {
    /// The printable form plus the padding, since that is where two identifiers can differ
    /// invisibly.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({self}")?;
        for byte in &self.0[12..] {
            write!(f, " {byte:02X}")?;
        }
        write!(f, ")")
    }
}

/// A card-verifiable certificate, tag `7F21`.
///
/// Both 券面 applications keep the card's own certificate in EF `0004` in this format. The
/// proprietary `80 A2` command takes a terminal's certificate in the same shape, checks it against
/// the terminal CA key, and keeps the public key inside it. The command's formal name is unknown.
///
/// ```text
/// 7F 21 82 02 33
///   5F 4E 82 01 29   297 bytes:
///                      16  証明者鍵ID
///                      16  被証明者鍵ID
///                     265  RSA-2048 public key (90 exponent, 91 modulus)
///   5F 37 82 01 00   256 byte signature over those 297 bytes
/// ```
///
/// The signing key is named by [`issuer_key_id`](Self::issuer_key_id) and is **not on the card**:
/// a verifier is expected to hold the CA keys and look one up by that identifier. Production
/// certificates name `"5000023"` (券面事項確認AP) and `"5000033"` (券面入力補助AP), and a JPKI test
/// card names `"6000023"` and `"6000033"` instead. See [`crate::ca`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardVerifiableCertificate {
    /// 証明者鍵ID — which key signed this certificate.
    pub issuer_key_id: KeyId,
    /// 被証明者鍵ID — which key is being certified.
    pub subject_key_id: KeyId,
    /// The certified public key.
    pub public_key: RsaPublicKey,
    /// Signature over the body, tag `5F37`.
    pub signature: Vec<u8>,
    /// Exactly the bytes the signature covers: the `5F4E` value, without its own header.
    pub signed_data: Vec<u8>,
}

impl CardVerifiableCertificate {
    /// Tag of the whole certificate.
    pub const TAG: u32 = 0x7F21;
    /// Tag of the certificate body.
    pub const TAG_BODY: u32 = 0x5F4E;
    /// Tag of the signature.
    pub const TAG_SIGNATURE: u32 = 0x5F37;
    /// Length of each of the two key identifiers.
    pub const KEY_ID_LEN: usize = 16;
    /// Length of the body: two key identifiers and an RSA-2048 public key.
    pub const BODY_LEN: usize = 297;

    /// Parse a certificate, with or without its `7F21` template.
    ///
    /// A certificate read out of an EF carries the template. GET DATA hands back the template's
    /// contents instead, so both forms turn up on the same card and both are accepted here.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let contents = if data.starts_with(&[0x7F, 0x21]) {
            let outer = ber::parse(data)?;
            if outer.tag != Self::TAG {
                return Err(malformed(&format!(
                    "expected tag 7F21, got {:04X}",
                    outer.tag
                )));
            }
            outer.value
        } else {
            data
        };
        let mut body = None;
        let mut signature = None;
        for tlv in ber::iter(contents) {
            let tlv = tlv?;
            match tlv.tag {
                Self::TAG_BODY => body = Some(tlv.value),
                Self::TAG_SIGNATURE => signature = Some(tlv.value.to_vec()),
                _ => {}
            }
        }
        let body = body.ok_or_else(|| malformed("certificate has no body (tag 5F4E)"))?;
        // Fixed size, because the key is: 16 + 16 + 265. Being strict here means a certificate
        // that is not shaped like this card's is rejected rather than silently mis-split.
        if body.len() != Self::BODY_LEN {
            return Err(malformed(&format!(
                "certificate body must be {} bytes, got {}",
                Self::BODY_LEN,
                body.len()
            )));
        }
        let ids = 2 * Self::KEY_ID_LEN;
        Ok(CardVerifiableCertificate {
            issuer_key_id: KeyId::parse(&body[..Self::KEY_ID_LEN])?,
            subject_key_id: KeyId::parse(&body[Self::KEY_ID_LEN..ids])?,
            public_key: RsaPublicKey::parse(&body[ids..])?,
            signature: signature
                .ok_or_else(|| malformed("certificate has no signature (tag 5F37)"))?,
            signed_data: body.to_vec(),
        })
    }
}

/// The format of an image the card stores.
///
/// Recognised from the magic bytes, because the card gives no other indication and the two are
/// mixed within one file: the rendered text fields are PNG and the photograph is JPEG 2000.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// PNG. The rendered card-face fields are 1-bit greyscale.
    Png,
    /// JPEG 2000, in the JP2 container. The photograph.
    Jpeg2000,
    /// Not recognised.
    Unknown,
}

impl ImageFormat {
    /// Identify an image by its leading bytes.
    pub fn detect(data: &[u8]) -> Self {
        if data.starts_with(b"\x89PNG\r\n\x1a\n") {
            ImageFormat::Png
        } else if data.len() >= 8 && &data[4..8] == b"jP  " {
            ImageFormat::Jpeg2000
        } else {
            ImageFormat::Unknown
        }
    }

    /// The usual file extension.
    pub const fn extension(self) -> &'static str {
        match self {
            ImageFormat::Png => "png",
            ImageFormat::Jpeg2000 => "jp2",
            ImageFormat::Unknown => "bin",
        }
    }
}

/// An image read from the card, with its format already identified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// Encoded image data, exactly as the card stores it.
    pub data: Vec<u8>,
    /// Which encoding that is.
    pub format: ImageFormat,
}

impl Image {
    /// Wrap image bytes, identifying the format.
    pub fn new(data: Vec<u8>) -> Self {
        let format = ImageFormat::detect(&data);
        Image { data, format }
    }
}

/// Read a `u16` offset table, and check it against where the objects actually start.
///
/// Both 券面 applications open their data files with one: a list of big-endian `u16` offsets from
/// the first byte of the file to each following object. Verifying it is a cheap integrity check on
/// a parse that is otherwise all reverse engineering.
pub(crate) fn check_offsets(file: &[u8], table: &[u8], starts: &[usize]) -> Result<()> {
    if table.len() != starts.len() * 2 {
        return Err(malformed(&format!(
            "offset table is {} bytes for {} objects",
            table.len(),
            starts.len()
        )));
    }
    for (i, (chunk, &start)) in table.chunks_exact(2).zip(starts).enumerate() {
        let declared = usize::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        if declared != start {
            return Err(malformed(&format!(
                "offset {i} says {declared:#06X} but the object starts at {start:#06X}"
            )));
        }
    }
    let _ = file;
    Ok(())
}

/// The objects inside one of the 券面 applications' data files, with any offset table checked.
///
/// Those files share a shape — an outer tag then a run of fields — but only some carry a table of
/// `u16` offsets from the start of the file, so which tag is the table (if any) has to be stated
/// rather than guessed: 券面事項確認AP `0001` and `0005` open with `DF11` and `DF41`, which are
/// ordinary fields despite the matching low nibble.
pub(crate) struct TlvFields<'a> {
    /// Tag, value, and the object's own bytes including its header.
    items: Vec<(u32, &'a [u8], &'a [u8])>,
}

impl<'a> TlvFields<'a> {
    pub(crate) fn parse(
        raw: &'a [u8],
        expected_tag: u32,
        offset_table: Option<u32>,
    ) -> Result<Self> {
        let outer = ber::parse(raw)?;
        if outer.tag != expected_tag {
            return Err(malformed(&format!(
                "expected tag {expected_tag:04X}, got {:04X}",
                outer.tag
            )));
        }
        // The header's own length, not `raw.len() - value.len()`: a file read straight off the
        // card carries filler past the end of the object, and taking the difference would push
        // every offset out by however much filler there is.
        let mut pos = ber::parse_header(raw)?.header_len;
        let mut rest = outer.value;
        let mut offsets = None;
        let mut items = Vec::new();
        let mut starts = Vec::new();
        while let Some(&first) = rest.first() {
            if first == 0x00 || first == 0xFF {
                break;
            }
            let header = ber::parse_header(rest)?;
            let end = header.total_len();
            let value = rest
                .get(header.header_len..end)
                .ok_or_else(|| malformed("a field runs past the end of the file"))?;
            if Some(header.tag) == offset_table {
                offsets = Some(value);
            } else {
                items.push((header.tag, value, &rest[..end]));
                starts.push(pos);
            }
            pos += end;
            rest = &rest[end..];
        }
        if let Some(table) = offsets {
            check_offsets(raw, table, &starts)?;
        }
        Ok(TlvFields { items })
    }

    pub(crate) fn get(&self, tag: u32) -> Result<&'a [u8]> {
        self.items
            .iter()
            .find(|(t, _, _)| *t == tag)
            .map(|(_, v, _)| *v)
            .ok_or_else(|| malformed(&format!("no field with tag {tag:04X}")))
    }

    /// Every object before `tag`, as written — what these files' signatures cover.
    pub(crate) fn bytes_before(&self, tag: u32) -> Result<Vec<u8>> {
        let end = self
            .items
            .iter()
            .position(|(t, _, _)| *t == tag)
            .ok_or_else(|| malformed(&format!("no field with tag {tag:04X}")))?;
        Ok(self.items[..end]
            .iter()
            .flat_map(|(_, _, raw)| *raw)
            .copied()
            .collect())
    }

    /// The named objects concatenated, as written.
    pub(crate) fn bytes_of(&self, tags: &[u32]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for tag in tags {
            let raw = self
                .items
                .iter()
                .find(|(t, _, _)| t == tag)
                .map(|(_, _, raw)| *raw)
                .ok_or_else(|| malformed(&format!("no field with tag {tag:04X}")))?;
            out.extend_from_slice(raw);
        }
        Ok(out)
    }
}

pub(crate) fn malformed(what: &str) -> Error {
    Error::Malformed(what.to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Build the PKCS #1 v1.5 `DigestInfo` for a SHA-256 digest.
///
/// ```text
/// 30 <len> 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 <n> <digest>
/// ```
///
/// `digest` is normally 32 bytes, but the card face record of 券面事項確認AP `0002` puts three
/// concatenated SHA-256 digests in one `DigestInfo` and declares the length accordingly — so the
/// length is taken from what is passed rather than fixed.
pub fn sha256_digest_info(digest: &[u8]) -> Vec<u8> {
    const ALGORITHM: [u8; 15] = [
        0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    ];
    let inner = ALGORITHM.len() + 2 + digest.len();
    let mut out = vec![0x30];
    if inner < 0x80 {
        out.push(inner as u8);
    } else {
        out.push(0x81);
        out.push(inner as u8);
    }
    out.extend_from_slice(&ALGORITHM);
    out.push(0x04);
    out.push(digest.len() as u8);
    out.extend_from_slice(digest);
    out
}

#[cfg(feature = "verify")]
impl RsaPublicKey {
    fn to_rsa(&self) -> Result<rsa::RsaPublicKey> {
        rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&self.modulus),
            rsa::BigUint::from_bytes_be(&self.exponent),
        )
        .map_err(|_| Error::SignatureInvalid("the public key is not usable"))
    }

    /// Verify a PKCS #1 v1.5 signature whose payload is `digest_info`, byte for byte.
    ///
    /// The padding is checked in full — this is not a search for the payload inside the block —
    /// so a signature with anything appended is rejected.
    pub fn verify_pkcs1(&self, digest_info: &[u8], signature: &[u8]) -> Result<()> {
        self.to_rsa()?
            .verify(rsa::Pkcs1v15Sign::new_unprefixed(), digest_info, signature)
            .map_err(|_| Error::SignatureInvalid("PKCS #1 v1.5 signature does not verify"))
    }

    /// Verify a PKCS #1 v1.5 signature over the SHA-256 of `message`.
    pub fn verify_pkcs1_sha256(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use rsa::sha2::Digest as _;
        let digest = rsa::sha2::Sha256::digest(message);
        self.verify_pkcs1(&sha256_digest_info(&digest), signature)
    }

    /// Verify an RSASSA-PSS signature over the SHA-256 of `message`.
    pub fn verify_pss_sha256(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use rsa::sha2::Digest as _;
        self.verify_pss_prehashed(&rsa::sha2::Sha256::digest(message), signature)
    }

    /// Encrypt `message` with RSAES-OAEP and SHA-256, both as the digest and in MGF1.
    ///
    /// Used to hand a session key to the 券面入力補助AP. The card's own answer distinguishes a
    /// ciphertext at or above the modulus (`6F00`) from one below it (`6A80` when the plaintext is
    /// not what it wanted), which is a property of its input range check rather than a leak: the
    /// modulus is in EF `0006` for anyone to read.
    #[cfg(feature = "sm")]
    pub fn encrypt_oaep_sha256(&self, message: &[u8]) -> Result<Vec<u8>> {
        use rsa::rand_core::OsRng;
        self.to_rsa()?
            .encrypt(&mut OsRng, rsa::Oaep::new::<rsa::sha2::Sha256>(), message)
            .map_err(|_| Error::SignatureInvalid("OAEP encryption failed"))
    }

    /// Verify an RSASSA-PSS signature over a SHA-256 digest you already have.
    pub fn verify_pss_prehashed(&self, digest: &[u8], signature: &[u8]) -> Result<()> {
        self.to_rsa()?
            .verify(rsa::Pss::new::<rsa::sha2::Sha256>(), digest, signature)
            .map_err(|_| Error::SignatureInvalid("PSS signature does not verify"))
    }
}

/// SHA-256 of `data`.
#[cfg(feature = "verify")]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use rsa::sha2::Digest as _;
    rsa::sha2::Sha256::digest(data).into()
}

#[cfg(all(test, feature = "verify"))]
mod verify_tests {
    use super::*;

    #[test]
    fn builds_digest_infos_of_both_lengths() {
        // The ordinary one: 32 byte digest, 49 byte structure.
        let one = sha256_digest_info(&[0xAA; 32]);
        assert_eq!(&one[..2], &[0x30, 0x31]);
        assert_eq!(&one[17..19], &[0x04, 0x20]);
        assert_eq!(one.len(), 51);

        // The card face record declares three concatenated digests in one DigestInfo.
        let three = sha256_digest_info(&[0xAA; 96]);
        assert_eq!(&three[..2], &[0x30, 0x71]);
        assert_eq!(&three[17..19], &[0x04, 0x60]);
        assert_eq!(three.len(), 115);
    }
}

#[cfg(feature = "verify")]
impl CardVerifiableCertificate {
    /// Check the certificate against the CA key its [`issuer_key_id`](Self::issuer_key_id) names.
    ///
    /// The key is looked up in [`crate::ca`], which carries the two production keys. To supply one
    /// yourself instead, use [`verify_with`](Self::verify_with).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownCertificateAuthority`] if no key is known for that identifier — which is
    /// what a test card gets, since its certificates are issued under `"6000023"`/`"6000033"`.
    /// Nothing is checked in that case; it is not a signature failure.
    pub fn verify(&self) -> Result<()> {
        let ca = crate::ca::find(&self.issuer_key_id)
            .ok_or(Error::UnknownCertificateAuthority(self.issuer_key_id))?;
        self.verify_with(&ca.to_public_key())
    }

    /// Check a chain: the first certificate against [`crate::ca`], each later one against the key
    /// the certificate before it certifies.
    ///
    /// This is what makes the master file chain self-contained — only its root needs a key that
    /// did not come off the card. The links are checked in order and the first failure is
    /// returned, so a chain that verifies here verifies as a whole.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the chain is empty or two consecutive certificates do not link,
    /// and whatever [`verify`](Self::verify) or [`verify_with`](Self::verify_with) reports
    /// otherwise.
    pub fn verify_chain(chain: &[Self]) -> Result<()> {
        let (first, rest) = chain
            .split_first()
            .ok_or_else(|| malformed("an empty chain verifies nothing"))?;
        first.verify()?;
        let mut issuer = first;
        for cert in rest {
            if cert.issuer_key_id != issuer.subject_key_id {
                return Err(malformed(
                    "chain is broken: a certificate names an issuer the one above does not certify",
                ));
            }
            cert.verify_with(&issuer.public_key)?;
            issuer = cert;
        }
        Ok(())
    }

    /// Check the certificate against a CA key you supply.
    ///
    /// The signature is PKCS #1 v1.5 with SHA-256 over the body — the two key identifiers followed
    /// by the certified public key, exactly the 297 bytes of [`signed_data`](Self::signed_data).
    ///
    /// The CA key does not come from the card, and the whole security of the 券面 protocol rests
    /// on where it does come from: a certificate checked against a key taken off the same card
    /// proves nothing at all.
    pub fn verify_with(&self, ca_key: &RsaPublicKey) -> Result<()> {
        ca_key.verify_pkcs1_sha256(&self.signed_data, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_ap_identification_field() {
        let identification = ApIdentification::parse(&[0x06, 0x03, 0x0E, 0x01]).unwrap();
        assert_eq!(identification.specification_version, 0x06);
        assert_eq!(identification.extended_lc_le_support, 0x03);
        assert_eq!(identification.vendor_id, 0x0E);
        assert_eq!(identification.vendor_specific, 0x01);
        assert_eq!(identification.to_bytes(), [0x06, 0x03, 0x0E, 0x01]);
        assert!(ApIdentification::parse(&[0x06, 0x03, 0x0E]).is_err());
        assert!(ApIdentification::parse(&[0x06, 0x03, 0x0E, 0x01, 0x00]).is_err());
    }

    #[test]
    fn parses_a_date() {
        assert_eq!(
            Date::parse(b"19800217").unwrap(),
            Date {
                year: 1980,
                month: 2,
                day: 17
            }
        );
        assert_eq!(Date::parse(b"19800217").unwrap().to_string(), "1980-02-17");
        assert!(Date::parse(b"1980021").is_err());
        assert!(Date::parse(b"19801317").is_err());
        assert!(Date::parse(b"1980-2-17").is_err());
    }

    #[test]
    fn converts_to_japanese_eras() {
        // The test card: 1980-02-17 is 昭和55, which is what 照合番号B encodes.
        assert_eq!(
            Date::parse(b"19800217").unwrap().to_era(),
            Some((Era::Showa, 55))
        );
        // Era boundaries are mid-year, so the day matters.
        assert_eq!(
            Date::parse(b"19890107").unwrap().to_era(),
            Some((Era::Showa, 64))
        );
        assert_eq!(
            Date::parse(b"19890108").unwrap().to_era(),
            Some((Era::Heisei, 1))
        );
        assert_eq!(
            Date::parse(b"20190430").unwrap().to_era(),
            Some((Era::Heisei, 31))
        );
        assert_eq!(
            Date::parse(b"20190501").unwrap().to_era(),
            Some((Era::Reiwa, 1))
        );
        assert_eq!(Date::parse(b"18670101").unwrap().to_era(), None);
        assert_eq!(Era::Showa.name(), "昭和");
    }

    #[test]
    fn builds_verification_code_b() {
        // The exact value that unlocks 券面入力補助AP 0002 on the test card.
        let dob = Date::parse(b"19800217").unwrap();
        let code = verification_code_b(dob, 2035, b"2285").unwrap();
        assert_eq!(code.as_bytes(), b"55021720352285");
        assert_eq!(code.len(), 14);
    }

    #[test]
    fn rejects_a_code_b_it_cannot_build() {
        let dob = Date::parse(b"19800217").unwrap();
        assert!(verification_code_b(dob, 2035, b"228").is_err());
        assert!(verification_code_b(dob, 2035, b"22X5").is_err());
        assert!(verification_code_b(Date::parse(b"18000101").unwrap(), 2035, b"2285").is_err());
    }

    #[test]
    fn my_number_is_also_verification_code_a() {
        let n = MyNumber::parse(b"537686677188").unwrap();
        assert_eq!(n.as_str(), "537686677188");
        assert_eq!(
            n.as_verification_code_a().unwrap().as_bytes(),
            b"537686677188"
        );
        assert!(!format!("{n:?}").contains("5376"));
        assert!(MyNumber::parse(b"53768667718").is_err());
        assert!(MyNumber::parse(b"53768667718X").is_err());
    }

    #[test]
    fn parses_a_public_key() {
        let mut data = vec![0x90, 0x03, 0x01, 0x00, 0x01, 0x91, 0x82, 0x01, 0x00];
        data.push(0xC9);
        data.extend(std::iter::repeat_n(0xAA, 255));
        let key = RsaPublicKey::parse(&data).unwrap();
        assert_eq!(key.exponent, [0x01, 0x00, 0x01]);
        assert_eq!(key.modulus.len(), 256);
        assert_eq!(key.bits(), 2048);
    }

    #[test]
    fn detects_image_formats() {
        assert_eq!(
            ImageFormat::detect(b"\x89PNG\r\n\x1a\n\x00"),
            ImageFormat::Png
        );
        assert_eq!(
            ImageFormat::detect(b"\x00\x00\x00\x0CjP  \r\n"),
            ImageFormat::Jpeg2000
        );
        assert_eq!(ImageFormat::detect(b"nope"), ImageFormat::Unknown);
        assert_eq!(ImageFormat::Png.extension(), "png");
    }

    /// A certificate shaped exactly like the card's: 16 + 16 + a 265 byte RSA-2048 key.
    fn cv_certificate() -> Vec<u8> {
        let mut body = b"9200073\x08\x050010000".to_vec();
        body.extend_from_slice(b"9299774\x08\x050010000");
        body.extend_from_slice(&[0x90, 0x03, 0x01, 0x00, 0x01, 0x91, 0x82, 0x01, 0x00]);
        body.push(0xC9);
        body.extend(std::iter::repeat_n(0xAA, 255));
        assert_eq!(body.len(), CardVerifiableCertificate::BODY_LEN);

        let mut inner = vec![0x5F, 0x4E, 0x82];
        inner.extend_from_slice(&(body.len() as u16).to_be_bytes());
        inner.extend_from_slice(&body);
        inner.extend_from_slice(&[0x5F, 0x37, 0x82, 0x01, 0x00]);
        inner.extend(std::iter::repeat_n(0xBC, 256));

        let mut cert = vec![0x7F, 0x21, 0x82];
        cert.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        cert.extend_from_slice(&inner);
        cert
    }

    #[test]
    fn parses_a_card_verifiable_certificate() {
        let parsed = CardVerifiableCertificate::parse(&cv_certificate()).unwrap();
        assert_eq!(parsed.issuer_key_id.to_string(), "9200073/001");
        assert_eq!(parsed.subject_key_id.to_string(), "9299774/001");
        assert_eq!(parsed.public_key.bits(), 2048);
        assert_eq!(parsed.signature.len(), 256);
        // The signature covers the body, and only the body.
        assert_eq!(
            parsed.signed_data.len(),
            CardVerifiableCertificate::BODY_LEN
        );
        assert!(parsed.signed_data.starts_with(b"9200073"));
    }

    #[test]
    fn rejects_a_body_of_the_wrong_size() {
        let mut cert = cv_certificate();
        // Shrink the body by one byte, keeping every length field consistent.
        let body_len = CardVerifiableCertificate::BODY_LEN - 1;
        cert[8] = (body_len >> 8) as u8;
        cert[9] = body_len as u8;
        cert.remove(10 + body_len);
        cert[3] = ((cert.len() - 5) >> 8) as u8;
        cert[4] = (cert.len() - 5) as u8;
        let err = CardVerifiableCertificate::parse(&cert).unwrap_err();
        assert!(format!("{err}").contains("297"), "{err}");
    }

    #[test]
    fn offset_table_mismatch_is_an_error() {
        assert!(check_offsets(&[], &[0x00, 0x0E, 0x00, 0x20], &[14, 32]).is_ok());
        assert!(check_offsets(&[], &[0x00, 0x0E, 0x00, 0x20], &[14, 33]).is_err());
        assert!(check_offsets(&[], &[0x00, 0x0E], &[14, 32]).is_err());
    }
}
