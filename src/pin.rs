//! PIN handling.
//!
//! The card uses several different secrets, and this crate deliberately models them all with one
//! type. Which values a given key accepts is enforced by the card, not here; the checks below
//! only reject values that could not be transmitted at all.
//!
//! The secrets in use are, in the terminology of the card's specification:
//!
//! - 暗証番号 (PIN) — the four digit numbers protecting the 共通カード, 住基 and 券面入力補助
//!   applications, and the JPKI user authentication key.
//! - 署名用パスワード — the alphanumeric password protecting the JPKI signature key.
//! - 照合番号A / 照合番号B — the values derived from the data printed on the card, used by the
//!   券面事項確認 and 券面入力補助 applications.

use std::fmt;

use crate::error::{Error, Result};

/// A secret to present to the card with VERIFY.
///
/// The buffer is zeroed on drop. That is a best effort: the compiler is free to leave copies
/// behind, and this crate does not lock the memory into RAM.
#[derive(Clone, PartialEq, Eq)]
pub struct Pin(Vec<u8>);

impl Pin {
    /// The longest value a VERIFY can carry.
    ///
    /// JICSAP 6.4.9 (3) gives the VERIFY data field as 1 to 16 bytes, and CHANGE KEY the same, so
    /// no key on a conforming card is longer than this. The JPKI signature password (6 to 16
    /// alphanumeric characters) sits right at the limit.
    pub const MAX_LEN: usize = 16;

    /// Build a PIN from a string of printable ASCII.
    ///
    /// Lowercase letters are *not* folded to uppercase; the card compares bytes, and the
    /// signature password is registered in uppercase.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPin`] if the value is empty, longer than [`Pin::MAX_LEN`] bytes,
    /// or contains anything other than printable ASCII.
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(Error::InvalidPin("must not be empty"));
        }
        if value.len() > Self::MAX_LEN {
            return Err(Error::InvalidPin("must not exceed 16 bytes"));
        }
        if !value.iter().all(|b| (0x20..0x7F).contains(b)) {
            return Err(Error::InvalidPin("must consist of printable ASCII"));
        }
        Ok(Pin(value.to_vec()))
    }

    /// Build a PIN that must consist only of decimal digits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPin`] if the value contains a non-digit, in addition to the
    /// conditions checked by [`Pin::new`].
    pub fn numeric(value: impl AsRef<[u8]>) -> Result<Self> {
        let pin = Pin::new(value)?;
        if !pin.0.iter().all(u8::is_ascii_digit) {
            return Err(Error::InvalidPin("must consist of decimal digits"));
        }
        Ok(pin)
    }

    /// The bytes to send in the VERIFY data field.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false; a [`Pin`] cannot be constructed empty.
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Redacted, so that a PIN cannot reach a log by accident.
impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pin(<{} bytes redacted>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_digits_and_alphanumerics() {
        assert_eq!(Pin::new("1234").unwrap().as_bytes(), b"1234");
        assert_eq!(Pin::new("PASSWORD1234").unwrap().len(), 12);
        assert_eq!(Pin::numeric("0000").unwrap().as_bytes(), b"0000");
    }

    #[test]
    fn rejects_unusable_values() {
        assert!(Pin::new("").is_err());
        assert!(Pin::new("1234\n").is_err());
        assert!(Pin::new("１２３４").is_err());
        assert!(Pin::numeric("PASSWORD").is_err());
        // JICSAP 6.4.9: the VERIFY data field is 1 to 16 bytes.
        assert!(Pin::new(vec![b'0'; 16]).is_ok());
        assert!(Pin::new(vec![b'0'; 17]).is_err());
    }

    #[test]
    fn debug_does_not_leak_the_secret() {
        let rendered = format!("{:?}", Pin::new("1234").unwrap());
        assert!(!rendered.contains("1234"), "{rendered}");
    }
}
