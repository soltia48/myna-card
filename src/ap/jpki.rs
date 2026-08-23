//! 公的個人認証AP — the JPKI application.
//!
//! Holds two RSA key pairs and their certificates: the *user authentication* pair, used to log
//! in to online services, and the *digital signature* pair, used to sign documents. The two are
//! protected by different secrets, and by different rules: the authentication key uses a four
//! digit PIN, while the signature key uses an alphanumeric password of six to sixteen
//! characters.
//!
//! Both certificates can be read without presenting anything, but the CA certificates and the
//! keys follow the access rules of their key references.
//!
//! No secure messaging reachable from here. SET SESSION KEY answers `6982` with both the user
//! authentication PIN and the signature password presented, and `CLA=08` on a read answers `69FC`.
//! What this application returns is a certificate or a signature — public values — so there is
//! little for a session to protect. See the `sm` module when that feature is enabled.

use crate::apdu::Command;
use crate::card::{Card, Retries, ShortEfId, ins};
#[cfg(feature = "verify")]
use crate::certificate::Certificate;
use crate::error::{Error, Result};
use crate::pin::Pin;
use crate::transport::Transmit;

/// AID of the JPKI application.
pub const DF: [u8; 10] = [0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01];

/// File identifiers within the JPKI application.
pub mod ef {
    /// Digital signature certificate (署名用証明書).
    pub const SIGN_CERTIFICATE: u16 = 0x0001;
    /// CA certificate for the digital signature certificate (署名用CA証明書).
    pub const SIGN_CA_CERTIFICATE: u16 = 0x0002;
    /// PKCS #11 token information, 160 bytes. See [`TokenInfo`](super::TokenInfo).
    pub const TOKEN_INFO: u16 = 0x0006;
    /// Three bytes saying which of the two certificates this card carries. See
    /// [`CertificateAvailability`](super::CertificateAvailability).
    pub const CERTIFICATE_AVAILABILITY: u16 = 0x0008;
    /// Protected transparent EF whose purpose and complete access condition remain unknown.
    ///
    /// Neither cardholder credential nor an accepted terminal certificate made it readable on
    /// the surveyed card.
    pub const UNKNOWN_0009: u16 = 0x0009;
    /// Key reference against which the proprietary `80 A2` command checks the terminal's
    /// card-verifiable certificate. See [`crate::card::ins::PROPRIETARY_A2`].
    pub const TERMINAL_CA: u16 = 0x0016;
    /// User authentication certificate (利用者証明用証明書).
    pub const AUTH_CERTIFICATE: u16 = 0x000A;
    /// CA certificate for the user authentication certificate (利用者証明用CA証明書).
    pub const AUTH_CA_CERTIFICATE: u16 = 0x000B;
    /// User authentication private key (利用者証明用秘密鍵).
    pub const AUTH_KEY: u16 = 0x0017;
    /// Key reference for the user authentication PIN (利用者証明用秘密鍵暗証番号).
    pub const AUTH_PIN: u16 = 0x0018;
    /// Digital signature private key (署名用秘密鍵).
    pub const SIGN_KEY: u16 = 0x001A;
    /// Key reference for the digital signature password (署名用秘密鍵暗証番号).
    pub const SIGN_PIN: u16 = 0x001B;
}

/// The JPKI application, selected on a card.
#[derive(Debug)]
pub struct JpkiAp<'a, T> {
    card: &'a mut Card<T>,
}

impl<'a, T: Transmit> JpkiAp<'a, T> {
    /// Select the application.
    pub fn select(card: &'a mut Card<T>) -> Result<Self> {
        card.select_df(&DF)?;
        Ok(JpkiAp { card })
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

    /// Read the token type from the first 32 bytes of EF `0006`.
    ///
    /// Readable with nothing presented. This is how a reader tells a physical card apart from the
    /// mobile certificate held in a phone's secure element, which speaks the same protocol.
    pub fn read_token_type(&mut self) -> Result<TokenType> {
        self.card.select_ef(ef::TOKEN_INFO)?;
        // A fixed 160 byte record, not TLV, so read it as stored.
        let raw = self.card.read_binary_physical()?;
        Ok(TokenType::from_bytes(&raw))
    }

    /// Read all of the PKCS #11 `CK_TOKEN_INFO` stored in EF `0006`.
    ///
    /// The card serialises the structure with 32-bit big-endian `CK_ULONG` fields, making it 160
    /// bytes. The two version slots are returned as raw bytes because physical cards have been
    /// observed to put ASCII `"03"` and `"01"` there rather than numeric `CK_VERSION` pairs.
    pub fn read_token_info(&mut self) -> Result<TokenInfo> {
        self.card.select_ef(ef::TOKEN_INFO)?;
        let raw = self.card.read_binary_physical()?;
        TokenInfo::parse(&raw)
    }

    /// Read EF `0008`, which says which of the two certificates the card carries.
    ///
    /// No credential is needed. See [`CertificateAvailability`].
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the file is not three bytes long.
    pub fn read_certificate_availability(&mut self) -> Result<CertificateAvailability> {
        self.card.select_ef(ef::CERTIFICATE_AVAILABILITY)?;
        let raw = self.card.read_binary_physical()?;
        CertificateAvailability::parse(&raw)
    }

    /// Read the 利用者証明用証明書, DER encoded.
    ///
    /// Readable without presenting a PIN.
    pub fn read_auth_certificate_der(&mut self) -> Result<Vec<u8>> {
        self.read_ef(ef::AUTH_CERTIFICATE)
    }

    /// Read the CA certificate above it, DER encoded.
    pub fn read_auth_ca_certificate_der(&mut self) -> Result<Vec<u8>> {
        self.read_ef(ef::AUTH_CA_CERTIFICATE)
    }

    /// Read the 署名用証明書, DER encoded.
    ///
    /// Requires [`JpkiAp::verify_sign_pin`] first.
    pub fn read_sign_certificate_der(&mut self) -> Result<Vec<u8>> {
        self.read_ef(ef::SIGN_CERTIFICATE)
    }

    /// Read the CA certificate above it, DER encoded.
    pub fn read_sign_ca_certificate_der(&mut self) -> Result<Vec<u8>> {
        self.read_ef(ef::SIGN_CA_CERTIFICATE)
    }

    /// Read and parse the 利用者証明用証明書.
    ///
    /// Readable without presenting a PIN.
    #[cfg(feature = "verify")]
    pub fn read_auth_certificate(&mut self) -> Result<Certificate> {
        Certificate::parse(&self.read_auth_certificate_der()?)
    }

    /// Read and parse the CA certificate above the 利用者証明用証明書.
    #[cfg(feature = "verify")]
    pub fn read_auth_ca_certificate(&mut self) -> Result<Certificate> {
        Certificate::parse(&self.read_auth_ca_certificate_der()?)
    }

    /// Read and parse the 署名用証明書.
    ///
    /// Requires [`JpkiAp::verify_sign_pin`] first.
    #[cfg(feature = "verify")]
    pub fn read_sign_certificate(&mut self) -> Result<Certificate> {
        Certificate::parse(&self.read_sign_certificate_der()?)
    }

    /// Read and parse the CA certificate above the 署名用証明書.
    #[cfg(feature = "verify")]
    pub fn read_sign_ca_certificate(&mut self) -> Result<Certificate> {
        Certificate::parse(&self.read_sign_ca_certificate_der()?)
    }

    /// Present the four digit user authentication PIN.
    pub fn verify_auth_pin(&mut self, pin: &Pin) -> Result<()> {
        self.card.select_ef(ef::AUTH_PIN)?;
        self.card.verify(pin)
    }

    /// Present the digital signature password.
    pub fn verify_sign_pin(&mut self, pin: &Pin) -> Result<()> {
        self.card.select_ef(ef::SIGN_PIN)?;
        self.card.verify(pin)
    }

    /// Change the four digit user authentication PIN.
    ///
    /// This first presents `current_pin`, which consumes a retry on failure, then replaces it
    /// with `new_pin`. The card enforces the credential-specific format; construct both values
    /// with [`Pin::numeric`] to reject non-digits before transmission.
    pub fn change_auth_pin(&mut self, current_pin: &Pin, new_pin: &Pin) -> Result<()> {
        self.change_pin(ef::AUTH_PIN, current_pin, new_pin)
    }

    /// Change the digital signature password.
    ///
    /// This first presents `current_pin`, which consumes a retry on failure, then replaces it
    /// with `new_pin`. The card requires six to sixteen uppercase alphanumeric characters.
    pub fn change_sign_pin(&mut self, current_pin: &Pin, new_pin: &Pin) -> Result<()> {
        self.change_pin(ef::SIGN_PIN, current_pin, new_pin)
    }

    /// Attempts remaining on the user authentication PIN, without spending one.
    pub fn auth_pin_retries(&mut self) -> Result<Retries> {
        self.card.select_ef(ef::AUTH_PIN)?;
        self.card.pin_retries()
    }

    /// Attempts remaining on the digital signature password, without spending one.
    pub fn sign_pin_retries(&mut self) -> Result<Retries> {
        self.card.select_ef(ef::SIGN_PIN)?;
        self.card.pin_retries()
    }

    fn change_pin(&mut self, key: u16, current_pin: &Pin, new_pin: &Pin) -> Result<()> {
        self.card.select_ef(key)?;
        self.card.verify(current_pin)?;
        self.card.change_reference_data(new_pin)
    }

    /// Sign with the user authentication key.
    ///
    /// Requires [`JpkiAp::verify_auth_pin`] first. What `data` must be depends on `scheme`.
    /// Returns the 256 byte RSA-2048 signature.
    pub fn sign_with_auth_key(&mut self, scheme: SignatureScheme, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(ef::AUTH_KEY, scheme, data)
    }

    /// Sign with the digital signature key.
    ///
    /// Requires [`JpkiAp::verify_sign_pin`] first. See [`JpkiAp::sign_with_auth_key`].
    pub fn sign_with_sign_key(&mut self, scheme: SignatureScheme, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(ef::SIGN_KEY, scheme, data)
    }

    /// Sign with the 利用者証明用秘密鍵, then check the result against the 利用者証明用証明書.
    ///
    /// The extra round trip reads the certificate, so this costs one more exchange than
    /// [`JpkiAp::sign_with_auth_key`]. What it buys is that a signature which would not verify —
    /// a wrong scheme, a corrupted exchange, a card that is not what it claims — is caught here
    /// rather than by whoever receives it.
    #[cfg(feature = "verify")]
    pub fn sign_with_auth_key_checked(
        &mut self,
        scheme: SignatureScheme,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self.read_auth_certificate()?.public_key()?;
        let signature = self.sign_with_auth_key(scheme, data)?;
        scheme.verify(&key, data, &signature)?;
        Ok(signature)
    }

    /// Sign with the 署名用秘密鍵, then check the result against the 署名用証明書.
    ///
    /// Requires [`JpkiAp::verify_sign_pin`] first — for the signature, and for reading the
    /// certificate to check it with.
    #[cfg(feature = "verify")]
    pub fn sign_with_sign_key_checked(
        &mut self,
        scheme: SignatureScheme,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self.read_sign_certificate()?.public_key()?;
        let signature = self.sign_with_sign_key(scheme, data)?;
        scheme.verify(&key, data, &signature)?;
        Ok(signature)
    }

    fn sign(&mut self, key: u16, scheme: SignatureScheme, data: &[u8]) -> Result<Vec<u8>> {
        scheme.check_input(data)?;
        // P2 names the key EF directly, which saves the SELECT: the card produces a byte-identical
        // signature either way. Le=0 asks for 256 bytes, the size of a 2048 bit signature; a card
        // that answers 61xx instead is handled by `Card::call`.
        let p2 = 0x80 | ShortEfId::from_ef_id(key)?.value();
        let command =
            Command::with_data_le(0x80, ins::COMPUTE_SIGNATURE, scheme.p1(), p2, data, 256);
        self.card.call_ok(&command)
    }
}

/// The 方式種別 in P1 of the card's signing command, `CLA 80 INS 2A`.
///
/// This instruction is the card's own, not one of the five JICSAP extended system commands, and
/// the schemes below were established by exercising every P1 value against a card and recovering
/// the padded block with the public key from the matching certificate. Any value outside this set
/// answers 6A86.
///
/// The six form a 3 × 2 matrix: three padding schemes, each with a variant that takes the message
/// and hashes it on the card, and one that takes a hash you computed yourself.
///
/// | | you supply the SHA-256 | the card computes SHA-256 |
/// |---|---|---|
/// | PKCS #1 v1.5, bare hash | — | [`Sha256Bare`](SignatureScheme::Sha256Bare) |
/// | PKCS #1 v1.5, DigestInfo | [`PreHashedDigestInfo`](SignatureScheme::PreHashedDigestInfo) | [`Sha256DigestInfo`](SignatureScheme::Sha256DigestInfo) |
/// | PSS | [`PreHashedPss`](SignatureScheme::PreHashedPss) | [`Sha256Pss`](SignatureScheme::Sha256Pss) |
///
/// [`Verbatim`](SignatureScheme::Verbatim) sits outside the matrix: it pads whatever you hand it,
/// which is the way to sign with a digest the card does not implement itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// `00` — PKCS #1 v1.5 over `data` exactly as supplied, which must be 1 to 245 bytes: the
    /// `k − 11` a 2048 bit key leaves for the payload. Supply a DigestInfo to get a conventional
    /// signature.
    Verbatim,
    /// `01` — the card takes SHA-256 of `data` and signs the bare 32 byte hash with PKCS #1 v1.5,
    /// with no AlgorithmIdentifier around it. Rarely what you want.
    Sha256Bare,
    /// `02` — `data` is a 32 byte SHA-256 hash, which the card wraps in a DigestInfo and signs
    /// with PKCS #1 v1.5.
    PreHashedDigestInfo,
    /// `03` — the card takes SHA-256 of `data`, wraps it in a DigestInfo and signs with
    /// PKCS #1 v1.5. The usual choice when the card can see the whole message.
    Sha256DigestInfo,
    /// `04` — `data` is a 32 byte SHA-256 hash, signed with RSASSA-PSS. The salt is random, so
    /// two calls over the same hash differ.
    PreHashedPss,
    /// `05` — the card takes SHA-256 of `data` and signs with RSASSA-PSS.
    Sha256Pss,
}

#[cfg(feature = "verify")]
impl SignatureScheme {
    /// Check a signature this scheme produced, against the matching public key.
    ///
    /// `data` is what was handed to the card, so the caller does not have to remember whether the
    /// card hashed it or not — that follows from the scheme.
    pub fn verify(
        &self,
        key: &crate::data::RsaPublicKey,
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        use crate::data::{sha256, sha256_digest_info};
        match self {
            // The card padded whatever it was given, so that is the payload.
            SignatureScheme::Verbatim => key.verify_pkcs1(data, signature),
            // The bare hash, with no AlgorithmIdentifier around it.
            SignatureScheme::Sha256Bare => key.verify_pkcs1(&sha256(data), signature),
            SignatureScheme::PreHashedDigestInfo => {
                key.verify_pkcs1(&sha256_digest_info(data), signature)
            }
            SignatureScheme::Sha256DigestInfo => key.verify_pkcs1_sha256(data, signature),
            SignatureScheme::PreHashedPss => key.verify_pss_prehashed(data, signature),
            SignatureScheme::Sha256Pss => key.verify_pss_sha256(data, signature),
        }
    }
}

impl SignatureScheme {
    /// The P1 byte.
    pub const fn p1(self) -> u8 {
        match self {
            SignatureScheme::Verbatim => 0x00,
            SignatureScheme::Sha256Bare => 0x01,
            SignatureScheme::PreHashedDigestInfo => 0x02,
            SignatureScheme::Sha256DigestInfo => 0x03,
            SignatureScheme::PreHashedPss => 0x04,
            SignatureScheme::Sha256Pss => 0x05,
        }
    }

    /// Whether the card hashes the input itself.
    pub const fn hashes_on_card(self) -> bool {
        matches!(
            self,
            SignatureScheme::Sha256Bare
                | SignatureScheme::Sha256DigestInfo
                | SignatureScheme::Sha256Pss
        )
    }

    /// Reject an input the card would answer 6985 or 6700 to, so the caller gets a reason.
    fn check_input(self, data: &[u8]) -> Result<()> {
        let allowed = match self {
            // Exactly one SHA-256 hash.
            SignatureScheme::PreHashedDigestInfo | SignatureScheme::PreHashedPss => 32..=32,
            // As much as PKCS #1 v1.5 leaves room for under a 2048 bit key.
            SignatureScheme::Verbatim => 1..=245,
            // The card hashes, so only the short APDU limit applies.
            _ => 1..=255,
        };
        if allowed.contains(&data.len()) {
            Ok(())
        } else {
            Err(Error::BadSigningInput {
                scheme: self,
                len: data.len(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    #[test]
    fn select_targets_the_jpki_aid() {
        let mut card = Card::new(MockTransport::new([vec![0x90, 0x00]]));
        JpkiAp::select(&mut card).unwrap();
        assert_eq!(
            card.transport().sent[0],
            [
                0x00, 0xA4, 0x04, 0x0C, 0x0A, 0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00,
                0x01
            ]
        );
    }

    #[test]
    fn verifying_the_sign_password_selects_its_key_reference() {
        let mut card = Card::new(MockTransport::new([
            vec![0x90, 0x00], // SELECT DF
            vec![0x90, 0x00], // SELECT EF 001B
            vec![0x90, 0x00], // VERIFY
        ]));
        let mut jpki = JpkiAp::select(&mut card).unwrap();
        jpki.verify_sign_pin(&Pin::new("PASSWORD1234").unwrap())
            .unwrap();

        assert_eq!(
            card.transport().sent[1],
            [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x1B]
        );
        assert_eq!(
            &card.transport().sent[2][..5],
            [0x00, 0x20, 0x00, 0x80, 0x0C]
        );
    }

    #[test]
    fn changing_the_auth_pin_verifies_the_old_value_before_replacing_it() {
        let mut card = Card::new(MockTransport::new([
            vec![0x90, 0x00], // SELECT DF
            vec![0x90, 0x00], // SELECT EF 0018
            vec![0x90, 0x00], // VERIFY current PIN
            vec![0x90, 0x00], // CHANGE REFERENCE DATA
        ]));
        let mut jpki = JpkiAp::select(&mut card).unwrap();
        jpki.change_auth_pin(
            &Pin::numeric("1234").unwrap(),
            &Pin::numeric("5678").unwrap(),
        )
        .unwrap();

        assert_eq!(
            card.transport().sent[1],
            [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x18]
        );
        assert_eq!(
            card.transport().sent[2],
            [0x00, 0x20, 0x00, 0x80, 0x04, b'1', b'2', b'3', b'4']
        );
        assert_eq!(
            card.transport().sent[3],
            [0x00, 0x24, 0x01, 0x80, 0x04, b'5', b'6', b'7', b'8']
        );
    }

    #[test]
    fn changing_the_sign_pin_stops_when_the_old_value_is_wrong() {
        let mut card = Card::new(MockTransport::new([
            vec![0x90, 0x00], // SELECT DF
            vec![0x90, 0x00], // SELECT EF 001B
            vec![0x63, 0xC2], // VERIFY current PIN
        ]));
        let mut jpki = JpkiAp::select(&mut card).unwrap();
        let err = jpki
            .change_sign_pin(
                &Pin::new("CURRENT1").unwrap(),
                &Pin::new("REPLACEMENT2").unwrap(),
            )
            .unwrap_err();

        assert!(matches!(err, Error::PinIncorrect { retries: Some(2) }));
        assert_eq!(card.transport().sent.len(), 3);
        assert_eq!(
            card.transport().sent[1],
            [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x1B]
        );
    }

    #[test]
    fn signing_names_the_key_in_p2_instead_of_selecting_it() {
        let mut card = Card::new(MockTransport::new([
            vec![0x90, 0x00],             // SELECT DF
            vec![0xAB, 0xCD, 0x90, 0x00], // 80 2A
        ]));
        let mut jpki = JpkiAp::select(&mut card).unwrap();
        let signature = jpki
            .sign_with_auth_key(SignatureScheme::Verbatim, &[0x01, 0x02])
            .unwrap();

        assert_eq!(signature, [0xAB, 0xCD]);
        assert_eq!(card.transport().sent.len(), 2, "no SELECT of the key EF");
        // P2 = 80 | 17: the user authentication key by short EF identifier.
        assert_eq!(
            card.transport().sent[1],
            [0x80, 0x2A, 0x00, 0x97, 0x02, 0x01, 0x02, 0x00]
        );
    }

    #[test]
    fn each_scheme_has_its_own_p1_and_key() {
        for (scheme, p1) in [
            (SignatureScheme::Verbatim, 0x00),
            (SignatureScheme::Sha256Bare, 0x01),
            (SignatureScheme::PreHashedDigestInfo, 0x02),
            (SignatureScheme::Sha256DigestInfo, 0x03),
            (SignatureScheme::PreHashedPss, 0x04),
            (SignatureScheme::Sha256Pss, 0x05),
        ] {
            assert_eq!(scheme.p1(), p1);
            let mut card = Card::new(MockTransport::new([vec![0x90, 0x00], vec![0x90, 0x00]]));
            let mut jpki = JpkiAp::select(&mut card).unwrap();
            jpki.sign_with_sign_key(scheme, &[0u8; 32]).unwrap();
            // P2 = 80 | 1A: the digital signature key.
            assert_eq!(card.transport().sent[1][..4], [0x80, 0x2A, p1, 0x9A]);
        }
    }

    #[test]
    fn rejects_inputs_the_card_would_refuse() {
        let mut card = Card::new(MockTransport::new([vec![0x90, 0x00]]));
        let mut jpki = JpkiAp::select(&mut card).unwrap();

        // 02 and 04 take exactly one SHA-256 hash.
        for scheme in [
            SignatureScheme::PreHashedDigestInfo,
            SignatureScheme::PreHashedPss,
        ] {
            assert!(matches!(
                jpki.sign_with_auth_key(scheme, &[0u8; 31]),
                Err(Error::BadSigningInput { len: 31, .. })
            ));
            assert!(matches!(
                jpki.sign_with_auth_key(scheme, &[0u8; 33]),
                Err(Error::BadSigningInput { len: 33, .. })
            ));
        }
        // 00 caps at the k-11 that PKCS #1 v1.5 leaves under a 2048 bit key.
        assert!(matches!(
            jpki.sign_with_auth_key(SignatureScheme::Verbatim, &[0u8; 246]),
            Err(Error::BadSigningInput { len: 246, .. })
        ));
        assert!(matches!(
            jpki.sign_with_auth_key(SignatureScheme::Verbatim, &[]),
            Err(Error::BadSigningInput { len: 0, .. })
        ));
        // Nothing reached the card.
        assert_eq!(card.transport().sent.len(), 1);
    }

    #[test]
    fn reads_the_certificate_availability() {
        let mut card = Card::new(MockTransport::new([
            vec![0x90, 0x00],
            vec![0x8F, 0x8F, 0x00, 0x90, 0x00],
        ]));
        let mut ap = JpkiAp { card: &mut card };
        let a = ap.read_certificate_availability().unwrap();
        assert_eq!(a.raw, [0x8F, 0x8F, 0x00]);
        assert!(a.has_sign_certificate() && a.has_auth_certificate());
        // A card with no 署名用証明書 — a child under fifteen, for instance.
        let missing = CertificateAvailability::parse(&[0x00, 0x8F, 0x00]).unwrap();
        assert!(!missing.has_sign_certificate());
        assert!(missing.has_auth_certificate());
        // The file has no filler, so a different length is a different card.
        assert!(CertificateAvailability::parse(&[0x8F, 0x8F]).is_err());
        assert!(CertificateAvailability::parse(&[0x8F; 16]).is_err());
    }

    #[test]
    fn knows_which_schemes_hash_on_the_card() {
        assert!(!SignatureScheme::Verbatim.hashes_on_card());
        assert!(!SignatureScheme::PreHashedDigestInfo.hashes_on_card());
        assert!(!SignatureScheme::PreHashedPss.hashes_on_card());
        assert!(SignatureScheme::Sha256Bare.hashes_on_card());
        assert!(SignatureScheme::Sha256DigestInfo.hashes_on_card());
        assert!(SignatureScheme::Sha256Pss.hashes_on_card());
    }
}

/// Which of the application's two certificates the card carries, from EF `0008`.
///
/// A cardholder may hold the 利用者証明用 certificate without the 署名用 one — the signing
/// certificate is optional, and is not issued to children under fifteen — so a reader that is
/// about to ask for a 署名用パスワード can find out first whether there is anything to sign with.
/// The file is readable without a credential.
///
/// The three bytes are `8F 8F 00` on a card carrying both. The first two describe the signature
/// and user-authentication certificates; what the third byte means is not known, so it is kept as
/// [`raw`](Self::raw) rather than interpreted.
///
/// `8F` is not a boolean and nothing here treats it as one. [`has_sign_certificate`] and
/// [`has_auth_certificate`] report "not the value a card with the certificate shows", which is the
/// most that one card can establish.
///
/// [`has_sign_certificate`]: Self::has_sign_certificate
/// [`has_auth_certificate`]: Self::has_auth_certificate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateAvailability {
    /// Byte 0 — signature-certificate availability.
    pub sign: u8,
    /// Byte 1 — user-authentication-certificate availability.
    pub auth: u8,
    /// All three bytes as stored.
    pub raw: [u8; 3],
}

impl CertificateAvailability {
    /// The value both bytes take on a card that carries both certificates.
    pub const PRESENT: u8 = 0x8F;

    /// Parse the three bytes of EF `0008`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if there are not exactly three of them. The EF has no filler, so a
    /// different length means a different card, not a short read.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let len = raw.len();
        let raw: [u8; 3] = raw
            .try_into()
            .map_err(|_| Error::Malformed(format!("EF 0008 is three bytes, not {len}")))?;
        Ok(CertificateAvailability {
            sign: raw[0],
            auth: raw[1],
            raw,
        })
    }

    /// Whether the 署名用証明書 is there, as far as one card can say.
    pub fn has_sign_certificate(&self) -> bool {
        self.sign == Self::PRESENT
    }

    /// Whether the 利用者証明用証明書 is there, as far as one card can say.
    pub fn has_auth_certificate(&self) -> bool {
        self.auth == Self::PRESENT
    }
}

/// What is answering as the 公的個人認証AP.
///
/// The application is not only on the plastic card: the same protocol is served by the
/// スマホ用電子証明書 held in a phone's secure element. The first 32 bytes of EF `0006` say which,
/// as a space-padded ASCII name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// `JPKIAPICCTOKEN2` — a physical Individual Number Card.
    Card,
    /// `JPKIAPGPSETOKEN` — the mobile certificate on an Android device.
    Android,
    /// `JPKIAPIOSTOKEN` — the mobile certificate on an iPhone.
    IPhone,
    /// Something else, kept as written.
    Other([u8; 32]),
    /// EF `0006` was shorter than 32 bytes.
    Absent,
}

/// PKCS #11 token-information flags found in [`TokenInfo::flags`].
pub mod token_flag {
    /// `CKF_RNG`: the token has its own random number generator.
    pub const RNG: u32 = 0x0000_0001;
    /// `CKF_LOGIN_REQUIRED`: some cryptographic operations require login.
    pub const LOGIN_REQUIRED: u32 = 0x0000_0004;
    /// `CKF_USER_PIN_INITIALIZED`: the normal user's PIN has been initialised.
    pub const USER_PIN_INITIALIZED: u32 = 0x0000_0008;
    /// `CKF_CLOCK_ON_TOKEN`: the token has a hardware clock and `utc_time` is meaningful.
    pub const CLOCK_ON_TOKEN: u32 = 0x0000_0040;
    /// `CKF_TOKEN_INITIALIZED`: the token has been initialised.
    pub const TOKEN_INITIALIZED: u32 = 0x0000_0400;
}

/// EF `0006`, a serialised PKCS #11 `CK_TOKEN_INFO` structure.
///
/// PKCS #11 leaves `CK_ULONG` platform-sized. This on-card representation fixes it at four bytes
/// and writes each integer most-significant byte first. Fixed text fields have their trailing
/// spaces removed here; version and time fields stay raw because the physical-card values do not
/// follow the literal `CK_VERSION` and UTC encodings in the PKCS #11 specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    /// The space-padded `label[32]`, classified into the known JPKI token kinds.
    pub token_type: TokenType,
    /// The space-padded `manufacturerID[32]` field, with padding removed.
    pub manufacturer_id: String,
    /// The space-padded `model[16]` field, with padding removed.
    pub model: String,
    /// The space-padded `serialNumber[16]` field, with padding removed.
    pub serial_number: String,
    /// PKCS #11 `CKF_*` token-information flags. See [`token_flag`].
    pub flags: u32,
    /// Maximum sessions one application may open at once.
    pub max_session_count: u32,
    /// Sessions currently open by the application represented by this record.
    pub session_count: u32,
    /// Maximum read/write sessions one application may open at once.
    pub max_rw_session_count: u32,
    /// Read/write sessions currently open by the represented application.
    pub rw_session_count: u32,
    /// Maximum PIN length in bytes.
    pub max_pin_len: u32,
    /// Minimum PIN length in bytes.
    pub min_pin_len: u32,
    /// Total public-object memory, or [`TokenInfo::UNAVAILABLE_INFORMATION`].
    pub total_public_memory: u32,
    /// Free public-object memory, or [`TokenInfo::UNAVAILABLE_INFORMATION`].
    pub free_public_memory: u32,
    /// Total private-object memory, or [`TokenInfo::UNAVAILABLE_INFORMATION`].
    pub total_private_memory: u32,
    /// Free private-object memory, or [`TokenInfo::UNAVAILABLE_INFORMATION`].
    pub free_private_memory: u32,
    /// Raw two-byte `hardwareVersion` slot.
    pub hardware_version: [u8; 2],
    /// Raw two-byte `firmwareVersion` slot.
    pub firmware_version: [u8; 2],
    /// Raw 16-byte `utcTime` slot.
    pub utc_time: [u8; 16],
}

impl TokenInfo {
    /// Size of the fixed on-card structure.
    pub const LEN: usize = 160;
    /// PKCS #11 `CK_UNAVAILABLE_INFORMATION` for this 32-bit representation.
    pub const UNAVAILABLE_INFORMATION: u32 = u32::MAX;
    /// PKCS #11 `CK_EFFECTIVELY_INFINITE`, meaningful in the two maximum-session fields.
    pub const EFFECTIVELY_INFINITE: u32 = 0;

    /// Parse the 160 bytes of EF `0006`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the length is not exactly 160 bytes, or if the manufacturer, model,
    /// or serial-number field is not valid UTF-8.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() != Self::LEN {
            return Err(Error::Malformed(format!(
                "EF 0006 is {} bytes, not {}",
                raw.len(),
                Self::LEN
            )));
        }

        fn text(raw: &[u8], field: &str) -> Result<String> {
            std::str::from_utf8(raw)
                .map(|value| value.trim_end_matches(' ').to_owned())
                .map_err(|_| Error::Malformed(format!("EF 0006 {field} is not valid UTF-8")))
        }

        fn word(raw: &[u8], offset: usize) -> u32 {
            u32::from_be_bytes(
                raw[offset..offset + 4]
                    .try_into()
                    .expect("TokenInfo length was checked"),
            )
        }

        Ok(TokenInfo {
            token_type: TokenType::from_bytes(raw),
            manufacturer_id: text(&raw[32..64], "manufacturer ID")?,
            model: text(&raw[64..80], "model")?,
            serial_number: text(&raw[80..96], "serial number")?,
            flags: word(raw, 96),
            max_session_count: word(raw, 100),
            session_count: word(raw, 104),
            max_rw_session_count: word(raw, 108),
            rw_session_count: word(raw, 112),
            max_pin_len: word(raw, 116),
            min_pin_len: word(raw, 120),
            total_public_memory: word(raw, 124),
            free_public_memory: word(raw, 128),
            total_private_memory: word(raw, 132),
            free_private_memory: word(raw, 136),
            hardware_version: raw[140..142]
                .try_into()
                .expect("TokenInfo length was checked"),
            firmware_version: raw[142..144]
                .try_into()
                .expect("TokenInfo length was checked"),
            utc_time: raw[144..160]
                .try_into()
                .expect("TokenInfo length was checked"),
        })
    }

    /// Whether every bit in `flag` is set.
    pub fn has_flag(&self, flag: u32) -> bool {
        self.flags & flag == flag
    }
}

impl TokenType {
    /// Name of a physical card.
    pub const CARD: &'static [u8; 32] = b"JPKIAPICCTOKEN2                 ";
    /// Name of the Android mobile certificate.
    pub const ANDROID: &'static [u8; 32] = b"JPKIAPGPSETOKEN                 ";
    /// Name of the iPhone mobile certificate.
    pub const IPHONE: &'static [u8; 32] = b"JPKIAPIOSTOKEN                  ";

    /// Classify the start of EF `0006`.
    pub fn from_bytes(token_info: &[u8]) -> Self {
        let Some(name) = token_info.get(..32) else {
            return TokenType::Absent;
        };
        match name {
            n if n == Self::CARD.as_slice() => TokenType::Card,
            n if n == Self::ANDROID.as_slice() => TokenType::Android,
            n if n == Self::IPHONE.as_slice() => TokenType::IPhone,
            n => TokenType::Other(n.try_into().expect("32 bytes")),
        }
    }

    /// The name as written, with the padding trimmed.
    pub fn name(&self) -> &str {
        match self {
            TokenType::Card => "JPKIAPICCTOKEN2",
            TokenType::Android => "JPKIAPGPSETOKEN",
            TokenType::IPhone => "JPKIAPIOSTOKEN",
            TokenType::Other(n) => std::str::from_utf8(n).unwrap_or("?").trim_end(),
            TokenType::Absent => "",
        }
    }

    /// Whether this is the plastic card rather than a phone.
    pub fn is_physical_card(&self) -> bool {
        matches!(self, TokenType::Card)
    }
}

#[cfg(test)]
mod token_tests {
    use super::*;

    #[test]
    fn classifies_the_three_known_tokens() {
        assert_eq!(TokenType::from_bytes(TokenType::CARD), TokenType::Card);
        assert_eq!(
            TokenType::from_bytes(TokenType::ANDROID),
            TokenType::Android
        );
        assert_eq!(TokenType::from_bytes(TokenType::IPHONE), TokenType::IPhone);
        assert!(TokenType::Card.is_physical_card());
        assert!(!TokenType::Android.is_physical_card());
        assert_eq!(TokenType::Card.name(), "JPKIAPICCTOKEN2");
    }

    #[test]
    fn only_the_first_32_bytes_decide() {
        // The file is 160 bytes; what follows the name must not change the answer.
        let mut file = TokenType::CARD.to_vec();
        file.extend_from_slice(&[0xAA; 128]);
        assert_eq!(TokenType::from_bytes(&file), TokenType::Card);
    }

    #[test]
    fn anything_else_is_kept_verbatim() {
        let mut other = *TokenType::CARD;
        other[14] = b'3';
        match TokenType::from_bytes(&other) {
            TokenType::Other(n) => assert_eq!(n, other),
            t => panic!("expected Other, got {t:?}"),
        }
        assert_eq!(TokenType::from_bytes(b"short"), TokenType::Absent);
    }

    #[test]
    fn parses_the_physical_card_token_info_layout() {
        let mut raw = [b' '; TokenInfo::LEN];
        raw[..32].copy_from_slice(TokenType::CARD);
        raw[32..64].copy_from_slice(b"00000000000000000000000000000001");
        raw[64..72].copy_from_slice(b"E16R01NJ");
        raw[80..96].copy_from_slice(b"0000000020500003");
        for (offset, value) in [
            (96, 0x0000_040D),
            (100, 1),
            (104, 0),
            (108, 1),
            (112, 0),
            (116, 16),
            (120, 6),
            (124, u32::MAX),
            (128, u32::MAX),
            (132, u32::MAX),
            (136, u32::MAX),
        ] {
            raw[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        raw[140..142].copy_from_slice(b"03");
        raw[142..144].copy_from_slice(b"01");
        raw[144..160].fill(b'9');

        let info = TokenInfo::parse(&raw).unwrap();
        assert_eq!(info.token_type, TokenType::Card);
        assert_eq!(info.manufacturer_id, "00000000000000000000000000000001");
        assert_eq!(info.model, "E16R01NJ");
        assert_eq!(info.serial_number, "0000000020500003");
        assert!(info.has_flag(token_flag::RNG));
        assert!(info.has_flag(token_flag::LOGIN_REQUIRED));
        assert!(info.has_flag(token_flag::USER_PIN_INITIALIZED));
        assert!(info.has_flag(token_flag::TOKEN_INITIALIZED));
        assert!(!info.has_flag(token_flag::CLOCK_ON_TOKEN));
        assert_eq!((info.max_session_count, info.session_count), (1, 0));
        assert_eq!((info.max_rw_session_count, info.rw_session_count), (1, 0));
        assert_eq!((info.max_pin_len, info.min_pin_len), (16, 6));
        assert_eq!(info.total_public_memory, TokenInfo::UNAVAILABLE_INFORMATION);
        assert_eq!(info.free_public_memory, TokenInfo::UNAVAILABLE_INFORMATION);
        assert_eq!(
            info.total_private_memory,
            TokenInfo::UNAVAILABLE_INFORMATION
        );
        assert_eq!(info.free_private_memory, TokenInfo::UNAVAILABLE_INFORMATION);
        assert_eq!(info.hardware_version, *b"03");
        assert_eq!(info.firmware_version, *b"01");
        assert_eq!(info.utc_time, [b'9'; 16]);
    }

    #[test]
    fn token_info_requires_the_exact_structure_size() {
        let error = TokenInfo::parse(&[0; TokenInfo::LEN - 1]).unwrap_err();
        assert!(error.to_string().contains("159 bytes, not 160"));
    }
}
