//! A library for accessing the Japanese Individual Number Card (個人番号カード / My Number Card).
//!
//! # Layout
//!
//! - [`apdu`] — building ISO/IEC 7816-4 APDUs and interpreting responses. Transport agnostic.
//! - [`transport`] — abstraction over the link to the card ([`Transmit`]), including a PC/SC backend.
//! - [`card`] — ISO 7816-4 level operations on top of [`Transmit`] (SELECT FILE, READ BINARY, VERIFY, ...).
//! - [`ap`] — per-application (AP) DF/EF definitions and higher level accessors.
//! - [`data`] — the values the card stores, and the credentials derived from them.
//! - [`ca`] — CA keys for the 券面 card-verifiable certificates, and where they came from.
//! - `certificate` — the X.509 certificates of the 公的個人認証AP (`verify` feature).
//! - [`mf`] — the files under the master file that the JICSAP specification itself defines.
//! - `sm` — secure messaging with the 券面入力補助AP (`sm` feature).
//! - [`tlv`] — readers for the two TLV encodings the card uses.
//!
//! # Specification
//!
//! The card follows the JICSAP specification of IC cards with contacts complying with Japanese
//! Industrial Standard, version 1.1 (July 1998), which in turn builds on JIS X 6306 and
//! ISO/IEC 7816-4. Doc comments cite it as "JICSAP" plus a section or table number.
//!
//! # Example
//!
//! This one needs the default features: the PC/SC backend comes from `pcsc`, and reading a
//! certificate or checking a signature against it comes from `verify`.
//!
//! ```no_run
//! # #[cfg(all(feature = "pcsc", feature = "verify"))]
//! # fn main() -> Result<(), myna_card::Error> {
//! use myna_card::ap::jpki::{JpkiAp, SignatureScheme};
//! use myna_card::transport::pcsc::Sharing;
//! use myna_card::{Pin, transport::pcsc};
//!
//! // Exclusive because this presents a PIN: a security status outlives the command that set it,
//! // and sharing the card would leave the unlocked key to whatever else is on the machine.
//! let mut card = pcsc::connect_any(Sharing::Exclusive)?;
//! let mut jpki = JpkiAp::select(&mut card)?;
//!
//! // The 利用者証明用証明書 is readable without a password.
//! let cert = jpki.read_auth_certificate()?;
//! println!("{}", cert.subject());
//!
//! // Sign with the key that certificate belongs to, and check the result against it.
//! jpki.verify_auth_pin(&Pin::numeric("1234")?)?;
//! let signature =
//!     jpki.sign_with_auth_key_checked(SignatureScheme::Sha256DigestInfo, b"message")?;
//!
//! // The 署名用証明書 and its key need the signature password instead.
//! jpki.verify_sign_pin(&Pin::new("PASSWORD1234")?)?;
//! let cert = jpki.read_sign_certificate()?;
//! # Ok(())
//! # }
//! # #[cfg(not(all(feature = "pcsc", feature = "verify")))]
//! # fn main() {}
//! ```
//!
//! # Warning
//!
//! Every failed VERIFY decrements the card's retry counter. Once a counter reaches zero the
//! corresponding PIN is blocked and can only be unblocked at a municipal office. Use
//! [`Card::pin_retries`] to query the remaining attempts without consuming one.
//!
//! # Feature flags
//!
//! | Feature | Default | What it enables |
//! |---|---:|---|
//! | `pcsc` | yes | The `transport::pcsc` backend for physical readers. |
//! | `verify` | yes | X.509 parsing and RSA signature verification. |
//! | `sm` | no | `SecureSession` and AES secure messaging for the 券面入力補助AP; implies `verify`. |
//! | `mock` | no | `transport::mock` for downstream integration tests. |
//!
//! With default features disabled, the APDU, file, application and parsing layers remain
//! available. Implement [`Transmit`] for another card link and pass it to [`Card::new`] to use
//! them without PC/SC. Methods gated by `verify` or `sm` are absent rather than becoming no-ops.
//!
//! # Security status outlives your program
//!
//! A successful VERIFY stays in effect until the card leaves the field. On a real card, neither
//! dropping the connection nor reconnecting with `SCARD_RESET_CARD` clears it — only
//! `SCARD_UNPOWER_CARD` does. Selecting a different application clears the one you left
//! (JICSAP 5.1.3 rule 3), but re-selecting the same one does not (rule 2).
//!
//! So a fresh process is not a fresh card. If your code needs to know that a file was genuinely
//! unlocked by the PIN it just presented, read it before the VERIFY too and check it was locked.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ap;
pub mod apdu;
pub mod ca;
pub mod card;
#[cfg(feature = "verify")]
pub mod certificate;
pub mod data;
pub mod error;
pub mod mf;
pub mod pin;
#[cfg(feature = "sm")]
pub mod sm;
pub mod tlv;
pub mod transport;

pub use ap::jpki::{TokenInfo, TokenType};
pub use apdu::{Command, Response, StatusWord};
pub use card::{Card, Retries, ShortEfId};
#[cfg(feature = "verify")]
pub use certificate::Certificate;
pub use data::{
    CardVerifiableCertificate, Date, Era, Image, ImageFormat, MyNumber, RsaPublicKey, Sex,
    verification_code_b,
};
pub use error::{Error, Result};
pub use mf::MasterFile;
pub use pin::Pin;
#[cfg(feature = "sm")]
pub use sm::SecureSession;
pub use transport::Transmit;
