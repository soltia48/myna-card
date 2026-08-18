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
//! little for a session to protect. See [`crate::sm`].

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
    /// Token information, 160 bytes. Its first 32 bytes name the token type; see
    /// [`TokenType`](super::TokenType).
    pub const TOKEN_INFO: u16 = 0x0006;
    /// Three bytes saying which of the two certificates this card carries. See
    /// [`CertificateAvailability`](super::CertificateAvailability).
    pub const CERTIFICATE_AVAILABILITY: u16 = 0x0008;
    /// Key reference the terminal's card-verifiable certificate is checked against, by
    /// SET PUBLIC IC KEY. See [`crate::card::ins::SET_PUBLIC_IC_KEY`].
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
}
