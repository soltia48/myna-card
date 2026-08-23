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
    /// Parse one complete DER encoded X.509 certificate and retain its original bytes.
    ///
    /// Parsing checks the DER and X.509 structure only. It does not verify the certificate's
    /// signature, validity period, purpose or revocation status; see [`Certificate::verify_to_root`]
    /// for the signature and date checks this crate can perform.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Malformed`] if `der` is not a valid certificate encoding.
    pub fn parse(der: &[u8]) -> Result<Self> {
        let inner = x509_cert::Certificate::from_der(der)
            .map_err(|e| malformed(&format!("not a DER X.509 certificate: {e}")))?;
        Ok(Certificate {
            der: der.to_vec(),
            inner,
        })
    }

    /// The complete DER encoding supplied to [`Certificate::parse`].
    ///
    /// The returned bytes are retained separately rather than re-encoded from [`Self::inner`], so
    /// callers can persist or compare the exact input.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The parsed certificate, for anything this wrapper does not expose.
    ///
    /// This provides read-only access to the `x509-cert` representation; mutating it cannot make
    /// [`Self::der`] disagree with the parsed value.
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
            .tbs_certificate()
            .subject_public_key_info()
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

    /// Subject distinguished name rendered with `x509-cert`'s display format.
    ///
    /// Use [`Self::inner`] when structured relative distinguished names are needed; this string is
    /// intended for display and diagnostics rather than identity comparison.
    pub fn subject(&self) -> String {
        self.inner.tbs_certificate().subject().to_string()
    }

    /// Issuer distinguished name rendered with `x509-cert`'s display format.
    ///
    /// [`roots::issuer_of`] uses this only to narrow candidates and confirms the result by
    /// verifying the signature.
    pub fn issuer(&self) -> String {
        self.inner.tbs_certificate().issuer().to_string()
    }

    /// Serial number as unsigned big-endian bytes, without formatting or hexadecimal conversion.
    pub fn serial_number(&self) -> Vec<u8> {
        self.inner
            .tbs_certificate()
            .serial_number()
            .as_bytes()
            .to_vec()
    }

    /// The validity period, as dates.
    ///
    /// The times of day are dropped; the card's certificates run to a whole second but nothing
    /// here needs that precision.
    pub fn validity(&self) -> (Date, Date) {
        let v = self.inner.tbs_certificate().validity();
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
        self.inner.signature_algorithm().oid.to_string()
    }
}

/// The JPKI root certificates, as published by J-LIS.
///
/// The card carries a CA certificate of its own, in 公的個人認証AP `0002` and `000B`, and checking
/// a card's certificate against it proves nothing: both came off the same card. These did not.
/// They are the trust anchors that make the check mean something, and they are compiled in rather
/// than read from disk so that nothing can substitute one at run time.
///
/// # Provenance
///
/// Downloaded from <https://www.jpki.go.jp/ca/index.html> and committed to `certs/` exactly as
/// received. Each is self-signed, RSA-2048 and `sha256WithRSAEncryption`; the tests check the
/// self-signatures with this crate's own verifier rather than taking that on trust.
///
/// # Generations
///
/// There are three of each, and a card is issued under whichever was current. The first pair
/// expired on 2025-10-19 and is kept because certificates issued before then still have to be
/// checkable — [`Certificate::verify_chain`] takes the date as an argument for exactly this
/// reason.
///
/// The 券面 applications' trust anchors are a different set entirely; see [`crate::ca`].
pub mod roots {
    use super::Certificate;
    use crate::error::Result;

    /// Which hierarchy a root belongs to.
    ///
    /// The distinction is not cosmetic. A test hierarchy root will happily certify a test card,
    /// and a test card is not a person's Individual Number Card — so anything deciding whether to
    /// believe a real cardholder must not accept one.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Hierarchy {
        /// `O=JPKI`, issued to the public. Published by J-LIS.
        Production,
        /// `O=JPKI-TEST`. J-LIS publishes no root for it; these were read off test cards.
        Test,
    }

    /// Which roots a lookup is allowed to return.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Accept {
        /// The only setting that belongs in a program that verifies real cardholders.
        ProductionOnly,
        /// Also accept the test hierarchy — for exercising a test card, and nothing else.
        ProductionAndTest,
    }

    impl Accept {
        fn allows(self, hierarchy: Hierarchy) -> bool {
            self == Accept::ProductionAndTest || hierarchy == Hierarchy::Production
        }
    }

    /// Which certificate on the card a root is for.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Purpose {
        /// 利用者証明用証明書 — 公的個人認証AP `000A`.
        UserAuthentication,
        /// 署名用証明書 — 公的個人認証AP `0001`.
        DigitalSignature,
    }

    /// One root.
    #[derive(Debug, Clone, Copy)]
    pub struct Root {
        /// Which certificate it issues.
        pub purpose: Purpose,
        /// Which hierarchy it anchors.
        pub hierarchy: Hierarchy,
        /// The number J-LIS gives it, taken from the published file name — `authca01` is 1.
        ///
        /// `None` for the test hierarchy. J-LIS publishes no list for `O=JPKI-TEST`, so how many
        /// there are, and where the ones here sit among them, is not known. Tell those apart by
        /// serial number or validity instead.
        pub generation: Option<u8>,
        /// The certificate, DER.
        pub der: &'static [u8],
    }

    impl Root {
        /// Parse it.
        pub fn certificate(&self) -> Result<Certificate> {
            Certificate::parse(self.der)
        }
    }

    /// Every root this crate carries: the six J-LIS publishes, then the test hierarchy.
    ///
    /// The three generations of a production root share one distinguished name, and so do the two
    /// test roots. A name does not identify a certificate here — only the signature does.
    ///
    /// The production entries are in J-LIS's order. The test entries are in no meaningful order:
    /// they are simply the two that were read off cards.
    pub const KNOWN: &[Root] = &[
        Root {
            purpose: Purpose::UserAuthentication,
            hierarchy: Hierarchy::Production,
            generation: Some(1),
            der: include_bytes!("../certs/authca01.cer"),
        },
        Root {
            purpose: Purpose::UserAuthentication,
            hierarchy: Hierarchy::Production,
            generation: Some(2),
            der: include_bytes!("../certs/authca02.cer"),
        },
        Root {
            purpose: Purpose::UserAuthentication,
            hierarchy: Hierarchy::Production,
            generation: Some(3),
            der: include_bytes!("../certs/authca03.cer"),
        },
        Root {
            purpose: Purpose::DigitalSignature,
            hierarchy: Hierarchy::Production,
            generation: Some(1),
            der: include_bytes!("../certs/signca01.cer"),
        },
        Root {
            purpose: Purpose::DigitalSignature,
            hierarchy: Hierarchy::Production,
            generation: Some(2),
            der: include_bytes!("../certs/signca02.cer"),
        },
        Root {
            purpose: Purpose::DigitalSignature,
            hierarchy: Hierarchy::Production,
            generation: Some(3),
            der: include_bytes!("../certs/signca03.cer"),
        },
        Root {
            purpose: Purpose::UserAuthentication,
            hierarchy: Hierarchy::Test,
            generation: None,
            der: include_bytes!("../certs/test/authca-test-2019.cer"),
        },
        Root {
            purpose: Purpose::UserAuthentication,
            hierarchy: Hierarchy::Test,
            generation: None,
            der: include_bytes!("../certs/test/authca-test-2023.cer"),
        },
        Root {
            purpose: Purpose::DigitalSignature,
            hierarchy: Hierarchy::Test,
            generation: None,
            der: include_bytes!("../certs/test/signca-test-2019.cer"),
        },
        Root {
            purpose: Purpose::DigitalSignature,
            hierarchy: Hierarchy::Test,
            generation: None,
            der: include_bytes!("../certs/test/signca-test-2024.cer"),
        },
    ];

    /// The root that issued `cert`, found by name and confirmed by signature.
    ///
    /// The name narrows the search and the signature decides it — which is not a nicety. Three
    /// generations of production root share one distinguished name, and so do the test roots, so a
    /// lookup that stopped at the name would pick the wrong certificate about as often as the
    /// right one.
    ///
    /// `accept` decides whether the test hierarchy counts. Use [`Accept::ProductionOnly`] anywhere
    /// the answer decides whether to believe a real cardholder; a test card is not one.
    ///
    /// # Errors
    ///
    /// [`crate::Error::SignatureInvalid`] if no permitted root signed it. There is no X.509
    /// counterpart to [`crate::Error::UnknownCertificateAuthority`], so "nothing was checked" and
    /// "the check failed" arrive as the same variant here; the message distinguishes them.
    pub fn issuer_of(cert: &Certificate, accept: Accept) -> Result<Certificate> {
        let issuer = cert.issuer();
        for root in KNOWN.iter().filter(|r| accept.allows(r.hierarchy)) {
            let candidate = root.certificate()?;
            if candidate.subject() == issuer && cert.verify_signature(&candidate).is_ok() {
                return Ok(candidate);
            }
        }
        Err(crate::Error::SignatureInvalid(
            "no root this crate carries signed this certificate",
        ))
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
    /// Check this certificate up to a root J-LIS publishes, on `on`.
    ///
    /// The difference from [`verify_chain`](Self::verify_chain) is where the anchor comes from.
    /// That one ends at whatever the caller passed last, which for a card is the CA certificate in
    /// EF `0002` or `000B` — the same card, so the chain proves only that the card is internally
    /// consistent. This one ends at [`roots`], which came from J-LIS.
    ///
    /// # Errors
    ///
    /// [`crate::Error::SignatureInvalid`] if no permitted root signed it, and
    /// [`crate::Error::Malformed`] if either certificate is outside its validity on `on`.
    pub fn verify_to_root(&self, on: Date, accept: roots::Accept) -> Result<()> {
        let root = roots::issuer_of(self, accept)?;
        Certificate::verify_chain(&[self.clone(), root], on)
    }

    /// Check a chain, **leaf first**, as the card hands it over: EF `000A` then EF `000B`.
    ///
    /// Note the direction. [`CardVerifiableCertificate::verify_chain`](crate::data::CardVerifiableCertificate::verify_chain) takes its chain root first,
    /// because that is the order *its* certificates come off the card; these two arrive the other
    /// way round, and the type system will not catch a mix-up.
    ///
    /// Each certificate is checked against the next: its signature, that the next one's subject is
    /// the issuer it names, and that `on` falls inside both validity periods. This crate has no
    /// clock, so the caller supplies the date.
    ///
    /// What this does **not** do is decide that the last certificate is trustworthy. It is the top
    /// of what the card carries, not a root you chose; a chain checked against a root that came
    /// off the same card proves only internal consistency. Nor does it look at basic constraints,
    /// key usage or revocation — JPKI publishes its own revocation service, and consulting it
    /// needs a network.
    ///
    /// # Errors
    ///
    /// [`crate::Error::SignatureInvalid`] if a link does not verify, and
    /// [`crate::Error::Malformed`] if the chain is empty, if two certificates do not name each
    /// other, or if one is not valid on `on`.
    pub fn verify_chain(chain: &[Certificate], on: Date) -> Result<()> {
        let (leaf, rest) = chain
            .split_first()
            .ok_or_else(|| malformed("an empty chain verifies nothing"))?;
        let mut subject = leaf;
        if !subject.is_valid_on(on) {
            let (from, to) = subject.validity();
            return Err(malformed(&format!(
                "{} is valid {from} to {to}, not on {on}",
                subject.subject()
            )));
        }
        for issuer in rest {
            if subject.issuer() != issuer.subject() {
                return Err(malformed(&format!(
                    "chain is broken: {:?} names issuer {:?}, next is {:?}",
                    subject.subject(),
                    subject.issuer(),
                    issuer.subject()
                )));
            }
            if !issuer.is_valid_on(on) {
                let (from, to) = issuer.validity();
                return Err(malformed(&format!(
                    "{} is valid {from} to {to}, not on {on}",
                    issuer.subject()
                )));
            }
            subject.verify_signature(issuer)?;
            subject = issuer;
        }
        Ok(())
    }

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
            .tbs_certificate()
            .to_der()
            .map_err(|_| malformed("re-encoding the TBSCertificate failed"))?;
        let signature = self
            .inner
            .signature()
            .as_bytes()
            .ok_or_else(|| malformed("signature is not a whole number of bytes"))?;
        issuer.public_key()?.verify_pkcs1_sha256(&tbs, signature)
    }
}
