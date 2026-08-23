# myna-card

[![CI](https://github.com/soltia48/myna-card/actions/workflows/ci.yml/badge.svg)](https://github.com/soltia48/myna-card/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/myna-card.svg)](https://crates.io/crates/myna-card)
[![docs.rs](https://docs.rs/myna-card/badge.svg)](https://docs.rs/myna-card)

A Rust library for accessing the Japanese Individual Number Card (個人番号カード / My Number Card)
over PC/SC.

## Status

The transport, APDU and file-access layers are implemented and unit tested, and the files whose
layouts have been worked out are decoded into types rather than handed back as bytes: the 個人番号,
the 基本4情報, the card info record, the card face with its images, and the card-verifiable
certificates. Files whose layout has not been worked out are still reachable, as raw bytes, through
the application wrappers' `read_ef` or `read_record` methods, according to the EF structure.

## Layers

```
ap::{common, juki, surface, text, jpki}   which application owns which file, and its access rules
sm::SecureSession                         secure messaging with the 券面入力補助AP (feature `sm`)
mf::MasterFile                            the master file level: GET DATA objects, and the
                                          files JICSAP defines there (001E, 2F10, 2F11)
card::Card                                SELECT FILE, READ BINARY, READ RECORD, VERIFY, GET DATA
apdu::{Command, Response, StatusWord}     ISO/IEC 7816-4 encoding — no I/O
data::{...}                               the values the card stores, and the credentials
certificate::Certificate                  the JPKI X.509 certificates (feature `verify`)
tlv::{ber, simple}                        the two TLV encodings the card uses
transport::Transmit                       the link to the card
    transport::pcsc                       PC/SC backend (feature `pcsc`, on by default)
    transport::mock                       scripted in-memory backend (feature `mock`)
```

### Two TLV encodings

Record structured EFs hold **simple encoded TLV** (JICSAP 4.4.1): a one byte tag, a one *or three*
byte length, then the value. Transparent EFs hold whatever the application put there, which on
this card is BER — DER certificates in JPKI, BER-TLV objects in the 券面 applications. The two are
not interchangeable: a first length byte of `FF` introduces a two byte length in the simple
encoding and is not a valid length at all in BER. Use `tlv::simple` for records and `tlv::ber` for
transparent files.

`Card` is generic over the transport, so everything above it can be exercised without a physical
card. `transport::mock::MockTransport` replays a fixed script of responses and records what was
sent; the unit tests in `card.rs` and `ap/jpki.rs` show the pattern.

## Installation

Add the crate with its default PC/SC and signature-verification support:

```sh
cargo add myna-card
```

The crate's features are:

| Feature | Default | Enables |
|---|---:|---|
| `pcsc` | yes | Access to physical readers through `transport::pcsc`. |
| `verify` | yes | X.509 parsing and RSA signature verification. |
| `sm` | no | AES secure messaging for the 券面入力補助AP; also enables `verify`. |
| `mock` | no | The scripted `transport::mock` backend for downstream tests. |

For secure messaging, enable `sm` explicitly:

```sh
cargo add myna-card --features sm
```

For another card link, disable the defaults and implement `transport::Transmit`. Add `verify`
back if the application still wants the built-in signature checks:

```sh
cargo add myna-card --no-default-features --features verify
```

## Usage

```rust
use myna_card::ap::jpki::{JpkiAp, SignatureScheme};
use myna_card::transport::pcsc::Sharing;
use myna_card::{Pin, transport::pcsc};

// Exclusive because this presents a PIN — see below.
let mut card = pcsc::connect_any(Sharing::Exclusive)?;
let mut jpki = JpkiAp::select(&mut card)?;

// Readable without a password.
let cert = jpki.read_auth_certificate()?;

// Needs the four digit authentication PIN.
jpki.verify_auth_pin(&Pin::numeric("1234")?)?;
let signature = jpki.sign_with_auth_key(SignatureScheme::Sha256DigestInfo, message)?;
```

### Who else may hold the card

Every connection says whether anything else may hold the card at the same time. There is no
default, because the answer follows from what the program is about to do and the wrong one fails
quietly in either direction.

`Sharing::Shared` is the PC/SC default and the right one for reading: several programs can ask a
card what it is at once without disturbing each other.

Signing is different. A successful VERIFY stays in effect until the card leaves the field, so
between presenting a PIN and powering the card down, any other process on the machine can sign with
the key you unlocked — without knowing the PIN. `Sharing::Exclusive` closes that window:

```rust
use myna_card::transport::pcsc::{self, Sharing};

let mut card = pcsc::connect_any(Sharing::Exclusive)?;
```

Nothing else can hold the card until that connection is dropped, and `power_cycle` reconnects on the
same terms rather than quietly giving the reservation up. Connecting fails with
`pcsc::Error::SharingViolation` if something already has the card — the holder keeps it, so this is
a reservation to take when the key needs it and release as soon as you are done. What it locks out
is the card's other legitimate users.

### Secure messaging

One application offers it, and only one. The 券面入力補助AP publishes an RSA public key in EF
`0006`; a terminal encrypts a session key to it with SET SESSION KEY, and afterwards command and
response data travel under AES-128-CBC. Behind the `sm` feature, which is off by default.

```rust
let mut text = TextAp::select(&mut card)?;
text.verify_pin(&Pin::numeric("1234")?)?;          // in the clear — see below

let mut seed = [0u8; myna_card::sm::SEED_LEN];     // from a CSPRNG, fresh per session
rsa::rand_core::RngCore::fill_bytes(&mut rsa::rand_core::OsRng, &mut seed);
let mut session = text.open_secure_session(&seed)?;

session.verify(ef::CODE_A, &code_a)?;              // 照合番号A, encrypted
let my_number = session.read_ef(ef::MY_NUMBER)?;   // and the file it opens
```

**It cannot protect the PIN.** The card will not deliver a session key until the PIN has been
presented in the clear: with nothing presented SET SESSION KEY answers `6982`, and presenting
照合番号A instead — which the card accepts — leaves it at `6982`. The ordering is closed, so treat
the PIN as exposed to anything listening whether or not a session follows.

What it does protect is what comes after, and one thing in particular: 照合番号A *is* the 個人番号,
so presenting it inside a session keeps the number itself off the interface. The 券面事項確認AP has
no equivalent, which is why the 照合番号 that open it are unavoidably in the clear.

There is no integrity, only confidentiality — see "Not implemented yet".

`examples/secure_messaging.rs` runs the whole sequence against a card.

### Signing

`CLA 80 INS 2A` is the card's own command, not one of the JICSAP five. Its P1 selects one of six
schemes — three padding modes, each in a "you supply the SHA-256" and a "the card hashes it"
variant — modelled as `SignatureScheme`. All six were established by exercising every P1 value
against a card and checking each result against the certificate's public key.

`Sha256DigestInfo` is the ordinary choice: hand it the message and the signature verifies as a
standard `sha256WithRSAEncryption`.

### Signature verification

With the `verify` feature — on by default — signatures are checked rather than just produced.

```rust
// JPKI: sign, and check the result against the certificate the key belongs to.
jpki.verify_auth_pin(&Pin::numeric("1234")?)?;
let signature = jpki.sign_with_auth_key_checked(SignatureScheme::Sha256DigestInfo, message)?;

let cert = jpki.read_auth_certificate()?;   // subject, issuer, validity, public key
```

The 券面 applications take two steps, and both are needed. The data is signed by an issuer key,
certified in EF `0004`; the card's own key — carried *inside* the signed data — signs challenges.
So verifying the record proves the data is authentic and that the key belongs to it, and
challenging the card proves the card is present:

```rust
let cert = surface.read_certificate()?;
cert.verify()?;                                               // the issuer key is certified
let face = surface.read_card_face()?;
face.verify(&cert.public_key)?;                               // the data is authentic

let challenge = surface.card().get_challenge(16)?;
let signature = surface.sign(&challenge)?;                    // the card's own key, no PIN
SignatureScheme::Sha256DigestInfo
    .verify(&face.public_key, &challenge, &signature)?;       // the card is here
```

Turn the feature off with `default-features = false` if you would rather check signatures
elsewhere; the RSA and X.509 dependencies go with it.

#### JPKI certificates and their roots

`Certificate::verify_chain` checks the pair the card hands over, EF `000A` then EF `000B`. Both
came off the same card, so that is an internal consistency check and nothing more.
`Certificate::verify_to_root` ends at a root the crate carries instead, compiled in from
[`certs/`](certs/) rather than read at run time: six published by J-LIS, three generations for each
of the two certificate types.

Four test hierarchy roots are carried as well, and reaching them takes asking. Both entry points
take an `Accept`, and `Accept::ProductionOnly` — the setting for any program that verifies real
cardholders — never returns one. A test card is not a person's Individual Number Card.

Note that a distinguished name does not identify a root: all three generations share one. The
lookup narrows by name and decides by signature.

#### Card-verifiable certificates

`CardVerifiableCertificate::verify()` resolves the CA key from the certificate's 証明者鍵ID using
the table in `ca`, or take `verify_with()` to supply one yourself. `verify_chain()` walks a chain,
resolving a key for the root only and checking each later link against the one above it.

Identifiers are a `KeyId`, not loose bytes: `6000023/001` prints as such, and comparison uses all
sixteen bytes, so a certificate from one hierarchy never resolves to another's key by accident.

The table holds six keys: the three production 証明者鍵ID and the three matching ones of the test
hierarchy JPKI test cards are issued under. Certificates from either verify without a key being
supplied by hand, and so do the intermediates below them, whose keys travel inside the certificate
above. Any other 証明者鍵ID returns `UnknownCertificateAuthority` — nothing was checked, which is a
different answer from a bad signature and is reported as one.

### The master file level

No elementary file under the MF is readable on this card, but GET DATA answers there. `MasterFile`
exposes what is: the card identification number, the issuing municipality, the expiry date, and a
chain of card-verifiable certificates that needs a CA key only for its root.

```rust
card.transport_mut().power_cycle()?;      // GET DATA answers only with no application selected
let mut mf = MasterFile::new(&mut card);
CardVerifiableCertificate::verify_chain(&mf.certificate_chain()?)?;
```

`Card::contact_atr()` returns the card's real contact-interface ATR, checksum verified — a
contactless reader reports one it made up instead. Which state answers varies between cards: some
return it at the MF level and some only with an application selected.

### Reading a card

```sh
cargo run --example read_card -- --pin 1234 --birth-date 550217 --code-a 537686677188 --out /tmp
```

Each credential is optional and is only ever presented to the key it belongs to, so a missing one
skips the files it guards rather than costing a retry. `data::verification_code_b` builds 照合番号B
from the date of birth, expiry year and security code — note that the card wants the date of birth
as a **Japanese era** year.

The repository contains these runnable examples:

```sh
cargo run --example list_readers
cargo run --example dump_certificates -- /tmp
cargo run --example read_card -- --pin 1234 --birth-date 550217 --out /tmp
cargo run --features sm --example secure_messaging -- 1234
```

`list_readers` only identifies readers and cards. `dump_certificates` writes the freely readable
JPKI certificates. `read_card` reads and verifies the data unlocked by the credentials supplied.
`secure_messaging` demonstrates an encrypted 照合番号A and read.

## Retry counters

Every failed VERIFY decrements a counter on the card. When a counter reaches zero the key is
blocked and only a municipal office can unblock it. `pin_retries()` sends a VERIFY with an empty
data field, which JICSAP 6.4.9 (5) defines as reporting the remaining attempts without consuming
one — call it before presenting a value you are not sure about.

Two statuses mean blocked: `63C0` from the attempt that exhausts the counter, and `6984` from
every attempt after that. A key with no retry limit answers `6300` and never reports a number.

## Requirements

These apply when the default `pcsc` feature is enabled:

- A PC/SC stack. On Linux that is `pcscd` plus the `libpcsclite` development headers; on macOS and
  Windows it is part of the OS.
- A contactless or contact reader. The card is a Type B contactless card and also works over a
  contact interface.

Neither is required for parsing saved data, using `transport::mock`, or supplying another
`transport::Transmit` implementation with `pcsc` disabled.

## Not implemented yet

- Revocation. Chains are checked against published roots, but JPKI publishes revocation as a
  separate online service and nothing here consults it. Basic constraints and key usage are not
  checked either.
- The files that stay unidentified: 公的個人認証AP `0009`, 券面事項確認AP `0006` and
  券面入力補助AP `0008` — both sixteen `FF` bytes — and the trailing 128 bytes of 券面入力補助AP
  `0005`.
- 券面入力補助AP `0012`, a key reference that arrives blocked with zero attempts left. It answers
  the non-consuming query `63C0` and a VERIFY `6984`. No file was found that it opens.
- Integrity-protected secure messaging. `CLA=0C` needs a CCS key, and the one application that
  offers secure messaging will not accept one: SET SESSION KEY takes `A0 { 80 : … }` and answers
  `6A80` to the forms carrying `81`. Confidentiality is implemented — see `sm` — but there is no
  MAC to be had, so an active attacker on the interface can corrupt a command even though they
  cannot read one.
- Secure messaging on the other four applications, because they do not offer it. 共通カードAP and
  券面事項確認AP answer SET SESSION KEY `66F1`, 公的個人認証AP and 住基AP answer `6982` with every
  credential this crate can present. None answers `6D00`, so the instruction exists card-wide.
- The remaining extended system commands. Their instruction bytes are in `card::ins`, but none of
  them helps read a card.
- Answer-to-Reset parsing (JICSAP 3.2). There is nothing to parse on this card: the contact ATR,
  which the card will hand over through GET DATA, declares zero historical bytes.

## License

MIT
