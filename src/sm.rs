//! Secure messaging for the 券面入力補助AP.
//!
//! One application on this card offers secure messaging, and only one. A terminal generates a
//! session key, encrypts it to a public key the card publishes, and hands it over with SET SESSION
//! KEY; afterwards the command data and the response data of certain commands travel encrypted
//! under AES-128.
//!
//! # What it protects, and what it does not
//!
//! The session cannot be opened until the four digit PIN has been presented **in the clear**:
//! with nothing presented SET SESSION KEY answers `6982`, and presenting 照合番号A instead — which
//! the card accepts, `9000` — leaves it at `6982`. So the ordering is closed. Anything listening
//! to the interface sees the PIN whether or not secure messaging is used afterwards.
//!
//! What the session does protect is everything after that point: the 個人番号 and 基本4情報 as they
//! are read, and 照合番号A/B as they are *presented*. Since 照合番号A is the 個人番号 itself, a
//! terminal that opens a session first never has to send it in the clear. That is the whole of the
//! benefit — treat the PIN as exposed regardless.
//!
//! # No integrity
//!
//! SET SESSION KEY takes three forms (encryption key, CCS key, or both). This application accepts
//! only the first: `A0 { 81 : … }` and `A0 { 80 : …, 81 : … }` are both answered `6A80`. With no
//! CCS key in the session there is no cryptographic checksum to compute, and `CLA=0C` — secure
//! messaging with the header authenticated — answers `6987` for want of the data objects it would
//! need. The session gives confidentiality only. An active attacker on the interface can still
//! corrupt a command; they simply cannot read one.
//!
//! # Message counter
//!
//! Each command carries an implicit counter `N`, starting at 1 for the first command after SET
//! SESSION KEY. The IV for both directions is `AES-128-CBC(key, IV=0)` over `N` written as sixteen
//! big-endian bytes, and `N` advances by one per secure-messaging command.
//!
//! Measured on a card, so that the edges are not guesswork:
//!
//! - Every secure-messaging command advances it, VERIFY and SELECT FILE included, not just the
//!   ones that carry ciphertext.
//! - A command the *application* rejects still advances it. A VERIFY against a blocked key
//!   reference answers `6984` and the next command must use `N + 1` regardless.
//! - Plain commands interleaved with secure ones do not advance it.
//! - Getting it wrong is unrecoverable: the card fails to strip the padding from what it
//!   decrypts, answers `6988`, and destroys the session. Every later command answers `69FC`.
//!
//! [`SecureSession`] tracks the counter so that callers do not have to, and refuses to keep going
//! once the card has reported a secure-messaging error — see [`SecureSession::is_broken`].
//!
//! # Data objects
//!
//! The command data field holds **exactly one** data object, and which tag is right depends on the
//! command rather than on the caller:
//!
//! ```text
//! VERIFY, SELECT FILE    86 <len> 01 || ciphertext      encrypted command data
//! READ BINARY            96 03 00 <Le, 2 bytes>         the expected length
//! ```
//!
//! Both are strict. Swapping them (`86` on READ BINARY, `96` on VERIFY) is answered `6988`, as is
//! a second data object of any tag beside a correct one — including a second copy of the correct
//! one. Of the 256 single byte tags only `86` is accepted where `86` belongs, the padding
//! indicator must be `01`, and the length may be short form or long form (`86 81 11 01 …` is
//! accepted).
//!
//! The response carries the same `86 <len> 01 || ciphertext` object.
//!
//! # Padding
//!
//! ISO/IEC 7816-4 padding: `80` followed by `00` up to a multiple of the block size, always added,
//! so a plaintext that is already block-aligned grows by a whole block.

use aes::Aes128;
use aes::cipher::{Block, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};

use crate::apdu::{Command, StatusWord, cla};
use crate::card::{Card, ShortEfId, ins};
use crate::data::{RsaPublicKey, malformed};
use crate::error::{Error, Result};
use crate::pin::Pin;
use crate::tlv::ber;
use crate::transport::Transmit;

type CbcEncryptor = cbc::Encryptor<Aes128>;
type CbcDecryptor = cbc::Decryptor<Aes128>;

/// AES block size, and the length of the session key this application uses.
const BLOCK: usize = 16;

/// Length of the key material SET SESSION KEY carries.
///
/// The specification fixes it at 32 bytes whichever cipher is in use. With AES-128 the first 16
/// become the session key and the remainder is unused — but all 32 still have to be unpredictable,
/// since the card decides how many it takes.
pub const SEED_LEN: usize = 32;

/// Tag of the encrypted data object, in both directions.
const TAG_CRYPTOGRAM: u8 = 0x86;
/// Tag of the expected-length data object.
const TAG_EXPECTED_LENGTH: u8 = 0x96;
/// The padding-content indicator that precedes a cryptogram. Any other value is rejected.
const PADDING_INDICATOR: u8 = 0x01;

/// Tag of the outer object of the key delivery message.
const TAG_KEY_DELIVERY: u8 = 0xA0;
/// Tag of the encryption key inside it.
const TAG_ENCRYPTION_KEY: u8 = 0x80;

/// A secure messaging session with the 券面入力補助AP.
///
/// Obtained from [`TextAp::open_secure_session`](crate::ap::text::TextAp::open_secure_session).
/// The session belongs to the card, not to this value: it survives being dropped and is cleared
/// when an application is selected or the card leaves the field, exactly like a security status.
#[derive(Debug)]
pub struct SecureSession<'a, T> {
    card: &'a mut Card<T>,
    key: [u8; BLOCK],
    counter: u32,
    broken: bool,
}

impl<'a, T: Transmit> SecureSession<'a, T> {
    /// Open a session by delivering `seed` under `public_key`.
    ///
    /// `public_key` is the one from EF `0006`; `seed` must come from a cryptographically secure
    /// random number generator, and must be fresh for every session — the counter starts over at 1
    /// each time, so reusing a seed reuses the whole IV sequence.
    ///
    /// The PIN has to have been presented already, in the clear. See the module documentation.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] with `6982` if no PIN has been presented, `6A80` if the card rejected the
    /// delivered structure, or `6F00` if `seed` happened to encrypt to a value at or above the
    /// modulus — retry with a fresh one.
    pub fn establish(
        card: &'a mut Card<T>,
        public_key: &RsaPublicKey,
        seed: &[u8; SEED_LEN],
    ) -> Result<Self> {
        let mut message = Vec::with_capacity(4 + SEED_LEN);
        message.extend_from_slice(&[
            TAG_KEY_DELIVERY,
            (2 + SEED_LEN) as u8,
            TAG_ENCRYPTION_KEY,
            SEED_LEN as u8,
        ]);
        message.extend_from_slice(seed);
        let delivered = public_key.encrypt_oaep_sha256(&message)?;
        card.call_ok(&Command::with_data(
            cla::SYSTEM,
            ins::SET_SESSION_KEY,
            0x00,
            0x00,
            delivered,
        ))?;
        let mut key = [0u8; BLOCK];
        key.copy_from_slice(&seed[..BLOCK]);
        Ok(SecureSession {
            card,
            key,
            counter: 1,
            broken: false,
        })
    }

    /// The counter the next command will use.
    pub fn counter(&self) -> u32 {
        self.counter
    }

    /// Whether the card has reported a secure messaging error.
    ///
    /// Once this is true the session on the card is gone and every further command answers
    /// `69FC`; open a new one. Nothing here can repair it, because the counter the card expects is
    /// no longer knowable.
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// Borrow the underlying card, for plain commands.
    ///
    /// Plain commands do not advance the counter, so interleaving them is safe.
    pub fn card(&mut self) -> &mut Card<T> {
        self.card
    }

    /// Present a secret under secure messaging.
    ///
    /// `key` is a key reference EF of the application — [`ef::PIN`](crate::ap::text::ef::PIN),
    /// [`ef::CODE_A`](crate::ap::text::ef::CODE_A) or
    /// [`ef::CODE_B`](crate::ap::text::ef::CODE_B). The reference travels in P2 as its short EF
    /// identifier, so no SELECT is needed and none is sent.
    ///
    /// Presenting 照合番号A this way is the reason to open a session at all: it is the 個人番号,
    /// and this keeps it off the interface.
    ///
    /// # Errors
    ///
    /// The same as a plain VERIFY: [`Error::PinIncorrect`] carrying the remaining attempts, or
    /// [`Error::PinBlocked`]. **A failed attempt is spent exactly as it is in the clear** — secure
    /// messaging protects the value, not the counter.
    pub fn verify(&mut self, key: u16, value: &Pin) -> Result<()> {
        let p2 = 0x80 | ShortEfId::from_ef_id(key)?.value();
        let cryptogram = self.encrypt(value.as_bytes());
        self.call(&Command::with_data(
            cla::SM_WITHOUT_INTEGRITY,
            ins::VERIFY,
            0x00,
            p2,
            cryptogram_object(&cryptogram),
        ))?;
        Ok(())
    }

    /// Select an EF of the current application under secure messaging.
    ///
    /// The plain [`Card::select_ef`] does the same thing and does not spend a counter step; use
    /// this one when the identifier itself should not be on the interface.
    pub fn select_ef(&mut self, id: u16) -> Result<()> {
        let cryptogram = self.encrypt(&id.to_be_bytes());
        self.call(&Command::with_data(
            cla::SM_WITHOUT_INTEGRITY,
            ins::SELECT_FILE,
            0x02,
            0x0C,
            cryptogram_object(&cryptogram),
        ))?;
        Ok(())
    }

    /// Read from the current EF under secure messaging.
    ///
    /// `offset` goes in P1-P2 as it does for a plain READ BINARY. `length` is the number of
    /// plaintext bytes wanted; 0 asks for the whole file from `offset`, filler included, which is
    /// what the card returns for every file this application holds.
    ///
    /// The returned plaintext has had its padding removed, so it is exactly `length` bytes when a
    /// length was given.
    pub fn read_binary(&mut self, offset: u16, length: u16) -> Result<Vec<u8>> {
        let expected = [
            TAG_EXPECTED_LENGTH,
            0x03,
            0x00,
            (length >> 8) as u8,
            length as u8,
        ];
        let response = self.call(&Command::with_data_le(
            cla::SM_WITHOUT_INTEGRITY,
            ins::READ_BINARY,
            (offset >> 8) as u8,
            offset as u8,
            expected,
            65536,
        ))?;
        let counter = self.counter - 1;
        self.decrypt(&parse_cryptogram(&response)?, counter)
    }

    /// Select an EF and read it, stopping at the end of the BER-TLV object it holds.
    ///
    /// The same trimming as [`Card::read_binary_all`], so what comes back parses with the same
    /// functions as a plain read — [`Attributes::parse`](crate::ap::text::Attributes::parse) and
    /// the rest expect a trimmed buffer and reject a padded one.
    ///
    /// Two counter steps: one for the SELECT, one for the READ. A file too large for a single
    /// response costs one more per continuation.
    pub fn read_ef(&mut self, id: u16) -> Result<Vec<u8>> {
        let mut out = self.read_ef_physical(id)?;
        if out.is_empty() {
            return Ok(out);
        }
        match ber::parse_header(&out).map(|header| header.total_len()) {
            Ok(total) if total <= out.len() => out.truncate(total),
            // The card answered short of the object. Keep going from where it stopped.
            Ok(total) => {
                while out.len() < total {
                    let offset =
                        u16::try_from(out.len()).map_err(|_| Error::OffsetOutOfRange(out.len()))?;
                    let want = u16::try_from(total - out.len()).unwrap_or(u16::MAX);
                    let chunk = self.read_binary(offset, want)?;
                    if chunk.is_empty() {
                        break;
                    }
                    out.extend_from_slice(&chunk);
                }
            }
            // Not a TLV file. Give back what the card sent.
            Err(_) => {}
        }
        Ok(out)
    }

    /// Select an EF and read its whole physical content, filler included.
    ///
    /// The counterpart of [`Card::read_binary_physical`], and what
    /// [`IntegrityRecord::matches_my_number_file`](crate::ap::text::IntegrityRecord::matches_my_number_file)
    /// wants: that digest covers the 個人番号 file as stored, a 15 byte object followed by two
    /// `FF`, and the trimmed 15 do not match it.
    ///
    /// Two counter steps.
    pub fn read_ef_physical(&mut self, id: u16) -> Result<Vec<u8>> {
        self.select_ef(id)?;
        self.read_binary(0, 0)
    }

    /// Send one secure messaging command, advancing the counter.
    ///
    /// The counter advances whether or not the card accepts the command, because the card advances
    /// it whenever the secure messaging layer decrypted something — an application level refusal
    /// such as `6984` still counts. Only a secure messaging error means it did not, and that ends
    /// the session anyway.
    fn call(&mut self, command: &Command) -> Result<Vec<u8>> {
        if self.broken {
            return Err(Error::Status(StatusWord::new(0x69FC)));
        }
        let response = self.card.call(command)?;
        self.counter += 1;
        let sw = response.status;
        if is_secure_messaging_error(sw) {
            self.broken = true;
        }
        if sw.is_success() {
            Ok(response.data)
        } else {
            Err(Error::from_status(sw))
        }
    }

    /// The IV for counter `n`: the counter as sixteen big-endian bytes, encrypted under the
    /// session key with an all-zero IV.
    fn iv(&self, n: u32) -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        block[BLOCK - 4..].copy_from_slice(&n.to_be_bytes());
        let mut cipher = CbcEncryptor::new(&self.key.into(), &[0u8; BLOCK].into());
        cipher.encrypt_block((&mut block).into());
        block
    }

    /// Pad and encrypt for the counter this command will use.
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let iv = self.iv(self.counter);
        let mut buffer = pad(plaintext);
        let mut cipher = CbcEncryptor::new(&self.key.into(), &iv.into());
        let (blocks, remainder) = Block::<CbcEncryptor>::slice_as_chunks_mut(&mut buffer);
        debug_assert!(remainder.is_empty());
        cipher.encrypt_blocks(blocks);
        buffer
    }

    /// Decrypt and unpad what the card sent for counter `n`.
    fn decrypt(&self, ciphertext: &[u8], n: u32) -> Result<Vec<u8>> {
        if ciphertext.is_empty() || ciphertext.len() % BLOCK != 0 {
            return Err(malformed(&format!(
                "a cryptogram of {} bytes is not a whole number of blocks",
                ciphertext.len()
            )));
        }
        let iv = self.iv(n);
        let mut buffer = ciphertext.to_vec();
        let mut cipher = CbcDecryptor::new(&self.key.into(), &iv.into());
        let (blocks, remainder) = Block::<CbcDecryptor>::slice_as_chunks_mut(&mut buffer);
        debug_assert!(remainder.is_empty());
        cipher.decrypt_blocks(blocks);
        unpad(buffer)
    }
}

/// Wrap a cryptogram in the data object the card expects beside a command.
fn cryptogram_object(cryptogram: &[u8]) -> Vec<u8> {
    let inner = cryptogram.len() + 1;
    let mut out = Vec::with_capacity(inner + 4);
    out.push(TAG_CRYPTOGRAM);
    // The card takes either length form. Use the shortest that fits, as the specification's own
    // example does. Commands only ever carry a padded secret or a file identifier, so in practice
    // this is always the short form; the wider arms exist so the encoding is not silently wrong if
    // it is ever called with more.
    if inner < 0x80 {
        out.push(inner as u8);
    } else if inner <= 0xFF {
        out.push(0x81);
        out.push(inner as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(inner as u16).to_be_bytes());
    }
    out.push(PADDING_INDICATOR);
    out.extend_from_slice(cryptogram);
    out
}

/// Pull the cryptogram out of a response data object.
fn parse_cryptogram(response: &[u8]) -> Result<Vec<u8>> {
    let tlv = ber::parse(response)?;
    if tlv.tag != u32::from(TAG_CRYPTOGRAM) {
        return Err(malformed(&format!(
            "expected a cryptogram under tag 86, got {:02X}",
            tlv.tag
        )));
    }
    match tlv.value.split_first() {
        Some((&PADDING_INDICATOR, cryptogram)) => Ok(cryptogram.to_vec()),
        Some((other, _)) => Err(malformed(&format!(
            "padding-content indicator is {other:02X}, expected 01"
        ))),
        None => Err(malformed("the cryptogram object is empty")),
    }
}

/// ISO/IEC 7816-4 padding, always applied.
fn pad(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + BLOCK);
    out.extend_from_slice(data);
    out.push(0x80);
    while out.len() % BLOCK != 0 {
        out.push(0x00);
    }
    out
}

/// Remove ISO/IEC 7816-4 padding.
fn unpad(mut data: Vec<u8>) -> Result<Vec<u8>> {
    while let Some(&last) = data.last() {
        match last {
            0x00 => {
                data.pop();
            }
            0x80 => {
                data.pop();
                return Ok(data);
            }
            _ => break,
        }
    }
    Err(malformed(
        "decrypted data does not end in 80 00 … padding; the message counter is probably out of \
         step with the card",
    ))
}

/// Whether a status word says the secure messaging layer refused, which ends the session.
fn is_secure_messaging_error(sw: StatusWord) -> bool {
    matches!(sw.value(), 0x6987 | 0x6988 | 0x69FC | 0x6882)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_to_a_whole_block_and_always_adds_one() {
        assert_eq!(pad(b"1234").len(), BLOCK);
        assert_eq!(pad(b"537686677188").len(), BLOCK);
        // Already aligned, so a whole block is added.
        assert_eq!(pad(&[0u8; BLOCK]).len(), BLOCK * 2);
        assert_eq!(pad(b"1234")[4], 0x80);
    }

    #[test]
    fn unpad_reverses_pad() {
        for message in [&b""[..], b"1234", b"537686677188", &[0xFFu8; 40][..]] {
            assert_eq!(unpad(pad(message)).unwrap(), message);
        }
    }

    #[test]
    fn unpad_rejects_data_without_the_marker() {
        assert!(unpad(vec![0x01; BLOCK]).is_err());
        assert!(unpad(vec![0x00; BLOCK]).is_err());
    }

    #[test]
    fn builds_the_data_object_the_card_accepts() {
        // The specification's own VERIFY example: Lc 13, data 86 11 01 || 16 bytes.
        let object = cryptogram_object(&[0xAA; 16]);
        assert_eq!(object.len(), 0x13);
        assert_eq!(&object[..3], &[0x86, 0x11, 0x01]);
    }

    #[test]
    fn switches_to_the_long_length_form_when_needed() {
        // 127 bytes of cryptogram plus the indicator is 128, one past the short form.
        let object = cryptogram_object(&[0xAA; 127]);
        assert_eq!(&object[..3], &[0x86, 0x81, 0x80]);
        // Past 255 the length needs two bytes, not one.
        let object = cryptogram_object(&[0xAA; 640]);
        assert_eq!(&object[..4], &[0x86, 0x82, 0x02, 0x81]);
        assert_eq!(object.len(), 640 + 5);
    }

    #[test]
    fn parses_a_response_object() {
        let mut response = vec![0x86, 0x11, 0x01];
        response.extend_from_slice(&[0xBB; 16]);
        assert_eq!(parse_cryptogram(&response).unwrap(), vec![0xBB; 16]);
    }

    #[test]
    fn rejects_a_response_with_the_wrong_indicator() {
        let mut response = vec![0x86, 0x11, 0x02];
        response.extend_from_slice(&[0xBB; 16]);
        assert!(parse_cryptogram(&response).is_err());
    }

    /// The IV is a function of the key and the counter only, so the same counter under the same
    /// key always gives the same one — which is why a seed must never be reused.
    #[test]
    fn the_iv_depends_only_on_the_key_and_the_counter() {
        let session = |key: [u8; BLOCK]| SecureSession::<crate::transport::mock::MockTransport> {
            card: Box::leak(Box::new(Card::new(
                crate::transport::mock::MockTransport::new([]),
            ))),
            key,
            counter: 1,
            broken: false,
        };
        let a = session([0x11; BLOCK]);
        let b = session([0x11; BLOCK]);
        let c = session([0x22; BLOCK]);
        assert_eq!(a.iv(1), b.iv(1));
        assert_ne!(a.iv(1), a.iv(2));
        assert_ne!(a.iv(1), c.iv(1));
    }
}
