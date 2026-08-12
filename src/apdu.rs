//! Building ISO/IEC 7816-4 APDUs and interpreting responses.
//!
//! Nothing here talks to a card; it only produces and consumes byte strings.
//!
//! Section numbers in this module refer to the JICSAP specification of IC cards with contacts
//! complying with Japanese Industrial Standard, version 1.1 (July 1998).

use std::fmt;

use crate::error::{Error, Result};

/// CLA byte construction, per JICSAP Table 3.
pub mod cla {
    /// Commands complying with ISO/IEC 7816-4 — the JICSAP "user commands".
    pub const USER: u8 = 0x00;
    /// Commands not complying with ISO/IEC 7816-4 — the JICSAP "extended system commands".
    pub const SYSTEM: u8 = 0x80;
    /// Secure messaging applied, integrity check of the data field not required (b4=1, b3=0).
    pub const SM_WITHOUT_INTEGRITY: u8 = 0x08;
    /// Secure messaging applied, integrity check of the data field required (b4=1, b3=1).
    pub const SM_WITH_INTEGRITY: u8 = 0x0C;

    /// Put a logical channel number into bits b2-b1 of a CLA byte.
    ///
    /// JICSAP 4.5 requires a conforming card to support at least channels 0 and 1, and the ATR
    /// advertises two. The Individual Number Card does not: anything other than channel 0 answers
    /// 6881, "access with the specified logical channel number not provided". Use channel 0.
    pub const fn with_channel(cla: u8, channel: u8) -> u8 {
        (cla & 0xFC) | (channel & 0x03)
    }
}

/// A command APDU.
///
/// The short encoding is used whenever the data field fits in 255 bytes, which covers everything
/// this crate does on its own — files larger than 256 bytes are read in chunks via the offset in
/// [`Card::read_binary`](crate::Card::read_binary) rather than with an extended `Le`.
///
/// A longer data field switches to the extended encoding of JICSAP 6.1: `00` followed by a two
/// byte `Lc`. The card needs this for at least one command — VERIFY CERTIFICATE, `80 A2`, whose
/// first block carries a 307 byte certificate body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// Class byte.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// Parameter 1.
    pub p1: u8,
    /// Parameter 2.
    pub p2: u8,
    /// Command data field. `Lc` is derived from its length when encoding.
    pub data: Vec<u8>,
    /// Expected response length. In the short encoding `Some(0)` means 256 bytes.
    pub le: Option<u8>,
}

impl Command {
    /// Case 1: neither a data field nor `Le`.
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Command {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
        }
    }

    /// Case 2: `Le` only. Passing 0 requests 256 bytes.
    pub fn with_le(cla: u8, ins: u8, p1: u8, p2: u8, le: u8) -> Self {
        Command {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: Some(le),
        }
    }

    /// Case 3: a data field only.
    pub fn with_data(cla: u8, ins: u8, p1: u8, p2: u8, data: impl Into<Vec<u8>>) -> Self {
        Command {
            cla,
            ins,
            p1,
            p2,
            data: data.into(),
            le: None,
        }
    }

    /// Case 4: both a data field and `Le`.
    pub fn with_data_le(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: impl Into<Vec<u8>>,
        le: u8,
    ) -> Self {
        Command {
            cla,
            ins,
            p1,
            p2,
            data: data.into(),
            le: Some(le),
        }
    }

    /// Encode the command for transmission.
    ///
    /// Uses the short form while the data field fits in 255 bytes, and the extended form beyond
    /// that. In the extended form `Le` is widened to two bytes, as the encoding requires.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DataTooLong`] if the data field exceeds 65535 bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.data.len() > 0xFFFF {
            return Err(Error::DataTooLong(self.data.len()));
        }
        let extended = self.data.len() > 255;
        let mut out = Vec::with_capacity(7 + self.data.len() + 2);
        out.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2]);
        if !self.data.is_empty() {
            if extended {
                out.push(0x00);
                out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
            } else {
                out.push(self.data.len() as u8);
            }
            out.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            if extended {
                // The two forms cannot be mixed: an extended Lc forces an extended Le, where 0
                // means 65536 just as a short 0 means 256.
                out.extend_from_slice(&u16::from(le).to_be_bytes());
            } else {
                out.push(le);
            }
        }
        Ok(out)
    }
}

/// A response APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Response data field, without the trailing status word.
    pub data: Vec<u8>,
    /// Status word.
    pub status: StatusWord,
}

impl Response {
    /// Split a raw response from the card into its data field and status word.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ShortResponse`] if fewer than two bytes were received.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 2 {
            return Err(Error::ShortResponse(raw.len()));
        }
        let (data, sw) = raw.split_at(raw.len() - 2);
        Ok(Response {
            data: data.to_vec(),
            status: StatusWord::new(u16::from_be_bytes([sw[0], sw[1]])),
        })
    }

    /// Return the data field if the status word indicates success, otherwise fail.
    pub fn into_data(self) -> Result<Vec<u8>> {
        if self.status.is_success() {
            Ok(self.data)
        } else {
            Err(Error::from_status(self.status))
        }
    }
}

/// A status word (SW1-SW2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusWord(u16);

impl StatusWord {
    /// Normal end of processing.
    pub const SUCCESS: StatusWord = StatusWord(0x9000);

    /// Wrap a raw 16-bit value.
    pub const fn new(value: u16) -> Self {
        StatusWord(value)
    }

    /// The raw 16-bit value.
    pub const fn value(self) -> u16 {
        self.0
    }

    /// SW1.
    pub const fn sw1(self) -> u8 {
        (self.0 >> 8) as u8
    }

    /// SW2.
    pub const fn sw2(self) -> u8 {
        self.0 as u8
    }

    /// Whether this is 9000.
    pub const fn is_success(self) -> bool {
        self.0 == 0x9000
    }

    /// Whether this is an "end with warning" status: 62xx (non-volatile memory unchanged) or
    /// 63xx (non-volatile memory changed).
    ///
    /// JICSAP 6.1 puts these alongside a normal end, so a case 2 or case 4 response that carries
    /// one may still have a data field.
    pub const fn is_warning(self) -> bool {
        matches!(self.sw1(), 0x62 | 0x63)
    }

    /// 61xx — xx more bytes are available via GET RESPONSE.
    pub const fn more_data_available(self) -> Option<u8> {
        if self.sw1() == 0x61 {
            Some(self.sw2())
        } else {
            None
        }
    }

    /// 6Cxx — wrong `Le`; xx is the correct length.
    pub const fn correct_le(self) -> Option<u8> {
        if self.sw1() == 0x6C {
            Some(self.sw2())
        } else {
            None
        }
    }

    /// 63Cx — verification failed and x attempts remain (JICSAP 5.2.2).
    ///
    /// `Some(0)` means the key just became blocked. A card whose retry counter is unlimited
    /// answers 6300 instead, for which this returns `None`; use [`StatusWord::is_unlimited_retry`]
    /// to tell that apart from an unrelated status.
    pub const fn retries_remaining(self) -> Option<u8> {
        if self.0 & 0xFFF0 == 0x63C0 {
            Some(self.sw2() & 0x0F)
        } else {
            None
        }
    }

    /// 6300 — verification failed on a key whose number of retries is not limited (JICSAP 5.2.2).
    pub const fn is_unlimited_retry(self) -> bool {
        self.0 == 0x6300
    }

    /// A description of this status word, if it is one we recognise.
    ///
    /// The wording follows JICSAP Table 25, which is more specific than the ISO/IEC 7816-4
    /// wording for several of these.
    pub const fn description(self) -> Option<&'static str> {
        Some(match self.0 {
            0x9000 => "normal end",
            0x6281 => "output data failure",
            0x6283 => "DF locked",
            0x6300 => "verification unmatching (retries not limited)",
            0x6381 => "file full due to last writing",
            0x6400 => "file control information failure",
            0x6581 => "writing to the memory failed",
            0x6700 => "incorrect Lc/Le field",
            0x6881 => "access with the specified logical channel number not provided",
            0x6882 => "secure messaging feature not provided",
            0x6981 => "command conflicting the file structure",
            0x6982 => "security status not fulfilled",
            0x6984 => "referenced IEF locked",
            0x6985 => "command use condition not fulfilled",
            0x6986 => "no current EF",
            0x6987 => "no data object for secure messaging",
            0x6988 => "secure messaging CCS illegal",
            0x6A80 => "incorrect data field tag",
            0x6A81 => "feature not provided",
            0x6A82 => "no file to be accessed",
            0x6A83 => "no record to be accessed",
            0x6A84 => "insufficient memory space in the file",
            0x6A85 => "Lc value conflicting the TLV structure",
            0x6A86 => "incorrect P1-P2 value",
            0x6A87 => "Lc value conflicting P1-P2",
            0x6A88 => "referenced key not correctly set",
            0x6B00 => "offset specified out of the EF range",
            0x6D00 => "INS not provided",
            0x6E00 => "class not provided",
            0x6F00 => "self-diagnosis failure",
            _ => return None,
        })
    }
}

impl fmt::Display for StatusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SW={:04X}", self.0)?;
        if let Some(retries) = self.retries_remaining() {
            return write!(f, " (verification failed, {retries} attempt(s) remaining)");
        }
        if let Some(description) = self.description() {
            write!(f, " ({description})")?;
        }
        Ok(())
    }
}

impl From<u16> for StatusWord {
    fn from(value: u16) -> Self {
        StatusWord(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_each_apdu_case() {
        assert_eq!(
            Command::new(0x00, 0xA4, 0x04, 0x0C).to_bytes().unwrap(),
            [0x00, 0xA4, 0x04, 0x0C]
        );
        assert_eq!(
            Command::with_le(0x00, 0xB0, 0x00, 0x00, 0x00)
                .to_bytes()
                .unwrap(),
            [0x00, 0xB0, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            Command::with_data(0x00, 0xA4, 0x02, 0x0C, [0x00, 0x01])
                .to_bytes()
                .unwrap(),
            [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x01]
        );
        assert_eq!(
            Command::with_data_le(0x80, 0x2A, 0x00, 0x80, [0xAA], 0x00)
                .to_bytes()
                .unwrap(),
            [0x80, 0x2A, 0x00, 0x80, 0x01, 0xAA, 0x00]
        );
    }

    #[test]
    fn switches_to_the_extended_encoding_past_255_bytes() {
        // Short form right up to the boundary.
        let short = Command::with_data(0x80, 0xA2, 0x06, 0xC1, vec![0xAA; 255])
            .to_bytes()
            .unwrap();
        assert_eq!(short[..5], [0x80, 0xA2, 0x06, 0xC1, 0xFF]);
        assert_eq!(short.len(), 5 + 255);

        // Extended beyond it: 00 then a two byte Lc. This is what VERIFY CERTIFICATE needs — its
        // first block carries a 307 byte certificate body.
        let long = Command::with_data(0x80, 0xA2, 0x06, 0xC1, vec![0xAA; 307])
            .to_bytes()
            .unwrap();
        assert_eq!(long[..7], [0x80, 0xA2, 0x06, 0xC1, 0x00, 0x01, 0x33]);
        assert_eq!(long.len(), 7 + 307);

        // An extended Lc widens Le too.
        let both = Command::with_data_le(0x80, 0xA2, 0x00, 0xC1, vec![0xAA; 300], 0x00)
            .to_bytes()
            .unwrap();
        assert_eq!(both[..7], [0x80, 0xA2, 0x00, 0xC1, 0x00, 0x01, 0x2C]);
        assert_eq!(both[both.len() - 2..], [0x00, 0x00]);
    }

    #[test]
    fn rejects_data_no_encoding_can_carry() {
        let cmd = Command::with_data(0x00, 0x20, 0x00, 0x80, vec![0u8; 0x10000]);
        assert!(matches!(cmd.to_bytes(), Err(Error::DataTooLong(0x10000))));
    }

    #[test]
    fn splits_response_into_data_and_status() {
        let resp = Response::parse(&[0xDE, 0xAD, 0x90, 0x00]).unwrap();
        assert_eq!(resp.data, [0xDE, 0xAD]);
        assert_eq!(resp.status, StatusWord::SUCCESS);

        let resp = Response::parse(&[0x90, 0x00]).unwrap();
        assert!(resp.data.is_empty());
        assert!(resp.status.is_success());

        assert!(matches!(
            Response::parse(&[0x90]),
            Err(Error::ShortResponse(1))
        ));
    }

    #[test]
    fn decodes_retry_counter() {
        assert_eq!(StatusWord::new(0x63C3).retries_remaining(), Some(3));
        assert_eq!(StatusWord::new(0x63C0).retries_remaining(), Some(0));
        assert_eq!(StatusWord::new(0x6982).retries_remaining(), None);
    }

    #[test]
    fn maps_status_to_pin_errors() {
        assert!(matches!(
            Error::from_status(StatusWord::new(0x63C2)),
            Error::PinIncorrect { retries: Some(2) }
        ));
        assert!(matches!(
            Error::from_status(StatusWord::new(0x6300)),
            Error::PinIncorrect { retries: None }
        ));
        // 63C0 is the attempt that exhausts the counter; 6984 is every attempt after it.
        assert!(matches!(
            Error::from_status(StatusWord::new(0x63C0)),
            Error::PinBlocked
        ));
        assert!(matches!(
            Error::from_status(StatusWord::new(0x6984)),
            Error::PinBlocked
        ));
        assert!(matches!(
            Error::from_status(StatusWord::new(0x6A82)),
            Error::Status(_)
        ));
    }

    #[test]
    fn separates_warnings_from_success_and_failure() {
        assert!(StatusWord::new(0x6281).is_warning());
        assert!(StatusWord::new(0x63C1).is_warning());
        assert!(!StatusWord::SUCCESS.is_warning());
        assert!(!StatusWord::new(0x6A82).is_warning());
    }

    #[test]
    fn builds_cla_bytes() {
        assert_eq!(cla::with_channel(cla::USER, 1), 0x01);
        assert_eq!(cla::with_channel(cla::SYSTEM, 1), 0x81);
        assert_eq!(
            cla::with_channel(cla::SYSTEM | cla::SM_WITH_INTEGRITY, 0),
            0x8C
        );
    }
}
