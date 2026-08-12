//! X.509 certificates, as the 公的個人認証AP stores them.
//!
//! The JPKI application holds four DER encoded certificates: the two the cardholder uses —
//! 利用者証明用証明書 and 署名用証明書 — and the CA certificate above each. This module reads them
//! far enough to check a signature the card produced: the subject public key, plus the names and
//! validity a caller needs to decide whether to trust it.
//!
//! Nothing here validates a certificate. The signature over the certificate itself is not checked,
//! the chain to the CA is not walked, and revocation is not consulted. Extracting a public key and
//! trusting a certificate are different things, and only the first happens here.

use x509_cert::der::Decode;

use crate::data::{Date, RsaPublicKey, malformed};
use crate::error::Result;

/// A DER encoded X.509 certificate read from the card.
#[derive(Clone)]
pub struct Certificate {
    der: Vec<u8>,
    inner: x509_cert::Certificate,
}

impl Certificate {
    /// Parse a DER encoded certificate.
    pub fn parse(der: &[u8]) -> Result<Self> {
        let inner = x509_cert::Certificate::from_der(der)
            .map_err(|e| malformed(&format!("not a DER X.509 certificate: {e}")))?;
        Ok(Certificate {
            der: der.to_vec(),
            inner,
        })
    }

    /// The certificate as it came off the card.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The parsed certificate, for anything this wrapper does not expose.
    pub fn inner(&self) -> &x509_cert::Certificate {
        &self.inner
    }

    /// The subject public key, in the form the rest of this crate uses.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Malformed`] if the key is not RSA. Every certificate on the card is
    /// RSA-2048, but a caller handling an arbitrary certificate should expect this.
    pub fn public_key(&self) -> Result<RsaPublicKey> {
        let bits = self
            .inner
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| malformed("subject public key is not a whole number of bytes"))?;
        // Hand the PKCS #1 RSAPublicKey to the RSA implementation rather than picking the two
        // integers apart here — one less place to get DER wrong.
        use rsa::pkcs1::DecodeRsaPublicKey as _;
        use rsa::traits::PublicKeyParts as _;
        let key = rsa::RsaPublicKey::from_pkcs1_der(bits)
            .map_err(|_| malformed("subject public key is not an RSA key"))?;
        Ok(RsaPublicKey {
            exponent: key.e().to_bytes_be(),
            modulus: key.n().to_bytes_be(),
        })
    }

    /// Subject distinguished name, rendered.
    pub fn subject(&self) -> String {
        self.inner.tbs_certificate.subject.to_string()
    }

    /// Issuer distinguished name, rendered.
    pub fn issuer(&self) -> String {
        self.inner.tbs_certificate.issuer.to_string()
    }

    /// Serial number, big-endian.
    pub fn serial_number(&self) -> Vec<u8> {
        self.inner.tbs_certificate.serial_number.as_bytes().to_vec()
    }

    /// The validity period, as dates.
    ///
    /// The times of day are dropped; the card's certificates run to a whole second but nothing
    /// here needs that precision.
    pub fn validity(&self) -> (Date, Date) {
        let v = &self.inner.tbs_certificate.validity;
        (
            Date::from_unix_seconds(v.not_before.to_unix_duration().as_secs() as i64),
            Date::from_unix_seconds(v.not_after.to_unix_duration().as_secs() as i64),
        )
    }

    /// Whether `date` falls within the validity period, inclusive.
    ///
    /// This crate has no clock, so the caller supplies the date.
    pub fn is_valid_on(&self, date: Date) -> bool {
        let (from, to) = self.validity();
        from <= date && date <= to
    }

    /// The algorithm the certificate itself is signed with, as a dotted OID.
    pub fn signature_algorithm(&self) -> String {
        self.inner.signature_algorithm.oid.to_string()
    }
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (from, to) = self.validity();
        f.debug_struct("Certificate")
            .field("subject", &self.subject())
            .field("issuer", &self.issuer())
            .field("validity", &format!("{from} .. {to}"))
            .field("der_len", &self.der.len())
            .finish()
    }
}

#[cfg(feature = "verify")]
impl Certificate {
    /// Check this certificate's own signature against the certificate above it.
    ///
    /// One link of a chain, not a chain: the caller decides whether `issuer` is trusted, and
    /// nothing here looks at names, basic constraints, key usage or revocation. Verifying the
    /// 利用者証明用証明書 against the CA certificate in EF `000B` is what this is for.
    ///
    /// # Errors
    ///
    /// [`crate::Error::SignatureInvalid`] if the signature does not verify, or if the certificate
    /// is signed with an algorithm other than `sha256WithRSAEncryption` — the only one the card
    /// uses, and the only one checked here.
    pub fn verify_signature(&self, issuer: &Certificate) -> Result<()> {
        use x509_cert::der::Encode as _;

        const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
        if self.signature_algorithm() != SHA256_WITH_RSA {
            return Err(crate::Error::SignatureInvalid(
                "only sha256WithRSAEncryption is checked",
            ));
        }
        let tbs = self
            .inner
            .tbs_certificate
            .to_der()
            .map_err(|_| malformed("re-encoding the TBSCertificate failed"))?;
        let signature = self
            .inner
            .signature
            .as_bytes()
            .ok_or_else(|| malformed("signature is not a whole number of bytes"))?;
        issuer.public_key()?.verify_pkcs1_sha256(&tbs, signature)
    }
}
