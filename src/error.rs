//! Error types.

use crate::apdu::StatusWord;

/// Alias for [`std::result::Result`] with this crate's error type.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Anything that can go wrong while talking to an Individual Number Card.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An error reported by the PC/SC layer.
    #[cfg(feature = "pcsc")]
    #[error("PC/SC error: {0}")]
    Pcsc(#[from] pcsc::Error),

    /// No PC/SC reader is available.
    #[error("no PC/SC reader is available")]
    NoReader,

    /// The named PC/SC reader does not exist.
    #[error("no such PC/SC reader: {0}")]
    ReaderNotFound(String),

    /// The card returned a status word other than success.
    #[error("card returned {0}")]
    Status(StatusWord),

    /// The response was too short to even contain a status word.
    #[error("response is too short to contain a status word ({0} byte(s))")]
    ShortResponse(usize),

    /// The command data field exceeds what even an extended APDU can encode.
    #[error("APDU data field is too long ({0} byte(s), maximum 65535)")]
    DataTooLong(usize),

    /// `Le` is outside the 1 to 65536 an APDU can ask for.
    #[error("expected response length {0} is out of range (1 to 65536)")]
    ExpectedLengthOutOfRange(u32),

    /// The PIN was rejected.
    ///
    /// `retries` is the number of attempts left before the key is blocked, or `None` if the key
    /// has no retry limit (JICSAP 5.2.2: the card answers 6300 rather than 63Cx).
    #[error("incorrect PIN{}", match retries {
        Some(n) => format!(", {n} attempt(s) remaining"),
        None => String::from(" (retries are not limited)"),
    })]
    PinIncorrect {
        /// Attempts left on the card's retry counter, or `None` if it is unlimited.
        retries: Option<u8>,
    },

    /// The key is blocked because its retry counter reached zero.
    #[error("PIN is blocked")]
    PinBlocked,

    /// The supplied PIN is not well formed.
    #[error("invalid PIN: {0}")]
    InvalidPin(&'static str),

    /// The requested offset cannot be encoded in a short READ BINARY.
    #[error("offset {0} is out of range for READ BINARY (maximum 32767)")]
    OffsetOutOfRange(usize),

    /// A DF name must be 1 to 16 bytes (JICSAP 4.2 (1)).
    #[error("DF name must be 1 to 16 bytes, got {0}")]
    InvalidDfName(usize),

    /// The EF identifier has no short form; only `0001`-`001E` do (JICSAP 4.2 (2)).
    #[error("EF identifier {0:04X} has no short form (must be 0001-001E)")]
    NoShortEfId(u16),

    /// Record 0 means "the current record", which this crate does not use.
    #[error("record numbers start at 1")]
    InvalidRecordNumber,

    /// The data field does not suit the signing scheme it was given to.
    #[error("{len} bytes is not a valid input for {scheme:?}")]
    BadSigningInput {
        /// The scheme the data was rejected for.
        scheme: crate::ap::jpki::SignatureScheme,
        /// How many bytes were supplied.
        len: usize,
    },

    /// A card-verifiable certificate names a CA this crate has no key for.
    ///
    /// Distinct from a failed signature: nothing was checked. See [`crate::ca`].
    #[error("no CA key for 証明者鍵ID {0:?}")]
    UnknownCertificateAuthority(String),

    /// A signature did not verify under the key it was checked against.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(&'static str),

    /// Data read from the card did not have the expected structure.
    #[error("malformed data: {0}")]
    Malformed(String),
}

impl Error {
    /// Classify a status word, routing the ones we understand to dedicated variants
    /// and everything else to [`Error::Status`].
    ///
    /// Two statuses mean "blocked": 63C0, returned by the attempt that exhausts the counter, and
    /// 6984, returned by every attempt after that (JICSAP 5.2.2, example 1).
    pub(crate) fn from_status(sw: StatusWord) -> Self {
        match sw.value() {
            0x63C0 | 0x6984 => Error::PinBlocked,
            0x6300 => Error::PinIncorrect { retries: None },
            _ => match sw.retries_remaining() {
                Some(retries) => Error::PinIncorrect {
                    retries: Some(retries),
                },
                None => Error::Status(sw),
            },
        }
    }
}
