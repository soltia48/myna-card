//! ISO 7816-4 level operations on a connected card.
//!
//! Section numbers in this module refer to the JICSAP specification of IC cards with contacts
//! complying with Japanese Industrial Standard, version 1.1 (July 1998).

use crate::apdu::{Command, Response, StatusWord, cla};
use crate::error::{Error, Result};
use crate::pin::Pin;
use crate::tlv::ber;
use crate::transport::Transmit;

/// Instruction bytes, per JICSAP Table 4.
pub mod ins {
    /// ERASE ALL RECORDS (extended system command, CLA 8x).
    pub const ERASE_ALL_RECORDS: u8 = 0x06;
    /// VERIFY.
    pub const VERIFY: u8 = 0x20;
    /// CHANGE REFERENCE DATA. Not a JICSAP command; used by the JPKI and 券面入力補助
    /// applications to replace a PIN after a successful VERIFY.
    pub const CHANGE_REFERENCE_DATA: u8 = 0x24;
    /// CHANGE KEY (extended system command, CLA 8x).
    pub const CHANGE_KEY: u8 = 0x32;
    /// LOCK DF (extended system command, CLA 8x).
    pub const LOCK_DF: u8 = 0x50;
    /// UNLOCK DF (extended system command, CLA 8x).
    pub const UNLOCK_DF: u8 = 0x52;
    /// UNLOCK KEY (extended system command, CLA 8x).
    pub const UNLOCK_KEY: u8 = 0x54;
    /// EXTERNAL AUTHENTICATE.
    pub const EXTERNAL_AUTHENTICATE: u8 = 0x82;
    /// GET CHALLENGE.
    pub const GET_CHALLENGE: u8 = 0x84;
    /// INTERNAL AUTHENTICATE.
    pub const INTERNAL_AUTHENTICATE: u8 = 0x88;
    /// MANAGE ATTRIBUTES (extended system command, CLA 8x).
    ///
    /// This is an issuance/administration command that sets or updates file attributes. It is
    /// intentionally not wrapped by [`super::Card`]: a successful call can persistently change a
    /// DF or EF. On the issued Individual Number Card, probes reach the issuer-security check only
    /// for P1 `22` (update current EF) and `24` (update current DF).
    pub const MANAGE_ATTRIBUTES: u8 = 0x8A;
    /// SELECT FILE.
    pub const SELECT_FILE: u8 = 0xA4;
    /// READ BINARY.
    pub const READ_BINARY: u8 = 0xB0;
    /// READ RECORD(S).
    pub const READ_RECORD: u8 = 0xB2;
    /// GET RESPONSE. Not a JICSAP command; used to collect a chained 61xx response.
    pub const GET_RESPONSE: u8 = 0xC0;
    /// GET DATA. Not a JICSAP command, but the card implements it; see [`Card::get_data`](super::Card::get_data).
    pub const GET_DATA: u8 = 0xCA;
    /// SET SESSION KEY, used by secure messaging in the 券面入力補助 application (CLA 80).
    pub const SET_SESSION_KEY: u8 = 0xAE;
    /// COMPUTE DIGITAL SIGNATURE. Not a JICSAP command; the JPKI application's own, CLA 80.
    pub const COMPUTE_SIGNATURE: u8 = 0x2A;
    /// Proprietary instruction `A2`, used with CLA `80`; its formal name is not established.
    ///
    /// The observed operation is that the terminal hands over a card-verifiable certificate, the
    /// card verifies it against the CA key in
    /// [`jpki::ef::TERMINAL_CA`](crate::ap::jpki::ef::TERMINAL_CA), and keeps the public key the
    /// certificate carries. This description is deliberately not presented as a command name.
    ///
    /// The certificate body is 307 bytes, which is why [`Command`](crate::apdu::Command) needs the
    /// extended `Lc` encoding at all. What P1 and P2 select is not established: `00 00`, `00 AE`,
    /// `80 00` and `00 B6` all answer `6A86` on the cards examined, and nothing here has a
    /// certificate signed by a terminal CA to complete the exchange with.
    pub const PROPRIETARY_A2: u8 = 0xA2;
    /// The last-command indicator, `80 FC 00 00` with no data. Not a JICSAP command; CLA 80.
    ///
    /// This belongs to the iPhone JPKI-token profile, not to the physical-card profile: the
    /// physical cards examined reject the exact four-byte command with `6700`.
    pub const LAST_COMMAND_INDICATOR: u8 = 0xFC;
}

/// The largest number of bytes a single short READ BINARY can return.
const MAX_CHUNK: usize = 256;

/// The largest offset expressible in P1-P2 of a short READ BINARY (JICSAP Table 5: b8 of P1 is
/// zero and the remaining 15 bits are the relative address).
const MAX_OFFSET: usize = 0x7FFF;

/// Attempts left on a key's retry counter, as reported by an empty VERIFY (JICSAP 6.4.9 (5)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retries {
    /// 63Cx — this many attempts remain.
    Remaining(u8),
    /// 63C0 — the counter is exhausted and the key is blocked.
    Blocked,
    /// 6300 — the key has no retry limit, so there is no counter to report.
    Unlimited,
    /// The card answered 9000, which JICSAP does not define for an empty VERIFY. Some cards do
    /// this when the key has already been verified in the current session.
    NotReported,
}

impl Retries {
    /// The remaining attempts as a number, where a blocked key is zero.
    ///
    /// `None` when there is no number to give: an unlimited counter, or a card that did not
    /// report one.
    pub fn count(self) -> Option<u8> {
        match self {
            Retries::Remaining(n) => Some(n),
            Retries::Blocked => Some(0),
            Retries::Unlimited | Retries::NotReported => None,
        }
    }
}

/// A short EF identifier: the 5 bit form of an EF identifier in the range `0001`-`001E`
/// (JICSAP 4.2 (2)).
///
/// A command that carries one selects the EF and acts on it in a single exchange, saving the
/// separate SELECT FILE. Every EF of every application on this card is in that range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortEfId(u8);

impl ShortEfId {
    /// Build a short EF identifier from a full EF identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoShortEfId`] unless the identifier is in `0001`-`001E`. Identifier 0 is
    /// excluded because a command uses it to mean "the current EF", and `001F` and above have no
    /// short form.
    pub fn from_ef_id(id: u16) -> Result<Self> {
        match id {
            0x0001..=0x001E => Ok(ShortEfId(id as u8)),
            _ => Err(Error::NoShortEfId(id)),
        }
    }

    /// The 5 bit value.
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// A connected card.
///
/// This layer knows about files, offsets and PINs, but not about which application owns which
/// file. For that, see the wrappers in [`crate::ap`].
#[derive(Debug)]
pub struct Card<T> {
    transport: T,
}

impl<T: Transmit> Card<T> {
    /// Wrap a transport.
    pub fn new(transport: T) -> Self {
        Card { transport }
    }

    /// Borrow the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Mutably borrow the underlying transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Give back the underlying transport.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Send a command and return the response, whatever its status word.
    ///
    /// Two conventions are handled transparently: a 6Cxx reply causes the command to be resent
    /// with the corrected `Le`, and a 61xx reply causes the remaining data to be collected with
    /// GET RESPONSE. The status word returned is the one that ended the exchange.
    pub fn call(&mut self, command: &Command) -> Result<Response> {
        let mut response = self.transmit_once(command)?;

        if let Some(le) = response.status.correct_le() {
            let mut retry = command.clone();
            // 6C00 asks for 256, the same zero-means-maximum convention as Le itself.
            retry.le = Some(if le == 0 { 256 } else { u32::from(le) });
            response = self.transmit_once(&retry)?;
        }

        while let Some(available) = response.status.more_data_available() {
            let get_response = Command::with_le(
                cla::USER,
                ins::GET_RESPONSE,
                0x00,
                0x00,
                u32::from(available),
            );
            let next = self.transmit_once(&get_response)?;
            response.data.extend_from_slice(&next.data);
            response.status = next.status;
        }

        Ok(response)
    }

    /// Send a command and return its data, failing unless the status word is 9000.
    pub fn call_ok(&mut self, command: &Command) -> Result<Vec<u8>> {
        self.call(command)?.into_data()
    }

    fn transmit_once(&mut self, command: &Command) -> Result<Response> {
        let raw = self.transport.transmit(&command.to_bytes()?)?;
        Response::parse(&raw)
    }

    // There is deliberately no ISO `select_mf`. JICSAP 6.4.8 (3) ① specifies `00 A4 00 00`
    // for it, but on the Individual Number Card that command is worse than unsupported:
    //
    //   - issued straight after a cold reset, it answers 6A86 (incorrect P1-P2);
    //   - issued while an application DF is current, it answers 9000 and leaves the current DF
    //     exactly where it was.
    //
    // Selecting 3F00 by file identifier answers 6A82 either way. So a wrapper for the ISO form
    // would report success while doing nothing, and every read after it would silently come from
    // the previous DF. The power-on card-manager state can instead be restored by selecting the
    // GlobalPlatform Issuer Security Domain; see [`crate::mf::MasterFile::select`].

    /// SELECT FILE, selecting a dedicated file by its name (AID).
    ///
    /// The name may be 1 to 16 bytes. JICSAP 4.2 (1) also allows selecting by a *prefix* of a DF
    /// name, so a short name can match a DF you did not mean; pass the full name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDfName`] if the name is empty or longer than 16 bytes.
    pub fn select_df(&mut self, name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > 16 {
            return Err(Error::InvalidDfName(name.len()));
        }
        // P1=04: direct selection with a filename. P2=0C: first occurrence, no FCI output.
        self.call_ok(&Command::with_data(
            cla::USER,
            ins::SELECT_FILE,
            0x04,
            0x0C,
            name,
        ))?;
        Ok(())
    }

    /// SELECT FILE, selecting an elementary file under the current DF by its identifier.
    pub fn select_ef(&mut self, id: u16) -> Result<()> {
        // P1=02: select an EF under the current DF by file ID. P2=0C: no FCI output.
        self.call_ok(&Command::with_data(
            cla::USER,
            ins::SELECT_FILE,
            0x02,
            0x0C,
            id.to_be_bytes(),
        ))?;
        Ok(())
    }

    /// A single READ BINARY of the selected transparent EF.
    ///
    /// `le` is how many bytes to ask for, at most 256. Per JICSAP 6.4.1 (4) the card reads to the
    /// end of the file within that limit, so it may return fewer bytes than requested.
    pub fn read_binary_chunk(&mut self, offset: usize, le: u32) -> Result<Vec<u8>> {
        if offset > MAX_OFFSET {
            return Err(Error::OffsetOutOfRange(offset));
        }
        // P1 b8 = 0, so P1-P2 is a 15 bit relative address (JICSAP Table 5).
        let [p1, p2] = (offset as u16).to_be_bytes();
        self.call_ok(&Command::with_le(cla::USER, ins::READ_BINARY, p1, p2, le))
    }

    /// A single READ BINARY that names its EF by short identifier, with no prior SELECT FILE.
    ///
    /// The offset is then limited to 8 bits (JICSAP Table 5: with b8 of P1 set, P1 carries the
    /// short EF identifier and only P2 is left for the address), so this reads at most the first
    /// 256 bytes of a file. It also becomes the current EF, and it clears the record pointer.
    pub fn read_binary_chunk_sfi(
        &mut self,
        sfi: ShortEfId,
        offset: u8,
        le: u32,
    ) -> Result<Vec<u8>> {
        // P1 = 100xxxxx: b8 set, b7-b6 zero, b5-b1 the short EF identifier.
        let p1 = 0x80 | sfi.value();
        self.call_ok(&Command::with_le(
            cla::USER,
            ins::READ_BINARY,
            p1,
            offset,
            le,
        ))
    }

    /// Read exactly `length` bytes of the selected transparent EF, in as many chunks as needed.
    ///
    /// Stops early, returning what it has, if the card reports the end of the file.
    pub fn read_binary(&mut self, offset: usize, length: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(length);
        while out.len() < length {
            let want = (length - out.len()).min(MAX_CHUNK);
            let le = want as u32;
            match self.read_binary_chunk(offset + out.len(), le) {
                Ok(chunk) if chunk.is_empty() => break,
                Ok(chunk) => out.extend_from_slice(&chunk),
                Err(Error::Status(sw)) if is_end_of_file(sw) => break,
                Err(err) => return Err(err),
            }
        }
        Ok(out)
    }

    /// Read the whole content of the selected transparent EF.
    ///
    /// If the file starts with a BER-TLV object, its header decides how much is read, so the
    /// filler bytes past the end of the object are not returned. Otherwise the file is read in
    /// chunks until the card signals the end.
    pub fn read_binary_all(&mut self) -> Result<Vec<u8>> {
        let mut out = match self.read_binary_chunk(0, MAX_CHUNK as u32) {
            Ok(head) => head,
            Err(Error::Status(sw)) if is_end_of_file(sw) => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };
        if out.is_empty() {
            return Ok(out);
        }

        match ber::parse_header(&out).map(|header| header.total_len()) {
            Ok(total) if total <= out.len() => {
                out.truncate(total);
            }
            Ok(total) => {
                let rest = self.read_binary(out.len(), total - out.len())?;
                out.extend_from_slice(&rest);
            }
            // Not a TLV file: keep reading until the card stops giving us bytes.
            Err(_) => {
                while out.len() <= MAX_OFFSET {
                    match self.read_binary_chunk(out.len(), MAX_CHUNK as u32) {
                        Ok(chunk) if chunk.is_empty() => break,
                        Ok(chunk) => {
                            let short = chunk.len() < MAX_CHUNK;
                            out.extend_from_slice(&chunk);
                            if short {
                                break;
                            }
                        }
                        Err(Error::Status(sw)) if is_end_of_file(sw) => break,
                        Err(err) => return Err(err),
                    }
                }
            }
        }
        Ok(out)
    }

    /// Read the selected transparent EF's whole physical content, filler included.
    ///
    /// [`Card::read_binary_all`] stops at the end of the BER-TLV object it finds, which is what a
    /// caller wanting the *data* should use. This one reads until the card refuses, so whatever
    /// padding follows the object is included.
    ///
    /// The difference matters. 券面入力補助AP `0003` holds a SHA-256 of the 個人番号 file, and that
    /// digest covers the physical content — a 15 byte object followed by two `FF` bytes, 17 in
    /// all. Hashing the trimmed 15 does not match.
    pub fn read_binary_physical(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() <= MAX_OFFSET {
            match self.read_binary_chunk(out.len(), MAX_CHUNK as u32) {
                Ok(chunk) if chunk.is_empty() => break,
                Ok(chunk) => {
                    let short = chunk.len() < MAX_CHUNK;
                    out.extend_from_slice(&chunk);
                    if short {
                        break;
                    }
                }
                Err(Error::Status(sw)) if is_end_of_file(sw) => break,
                Err(err) => return Err(err),
            }
        }
        Ok(out)
    }

    /// READ RECORD(S), reading one record of the selected record structured EF.
    ///
    /// Records are numbered from 1. Record 0 means the current record, which does not exist until
    /// something has set the record pointer, so this rejects it rather than letting the card do so.
    ///
    /// The value is a simple encoded TLV object; parse it with [`crate::tlv::simple`].
    pub fn read_record(&mut self, record: u8) -> Result<Vec<u8>> {
        if record == 0 {
            return Err(Error::InvalidRecordNumber);
        }
        // P2 = 00000100: current EF, and P1 is an absolute record number (JICSAP Table 8).
        self.call_ok(&Command::with_le(
            cla::USER,
            ins::READ_RECORD,
            record,
            0x04,
            256,
        ))
    }

    /// READ RECORD(S), reading every record from `first` to the last one in a single command.
    ///
    /// The response is the records concatenated, each still a simple encoded TLV object; iterate
    /// them with [`crate::tlv::simple::iter`]. JICSAP 6.4.4 (5) notes that this is how you learn
    /// how many records a file has.
    ///
    /// Not every card implements the multi-record form; one that does not answers 6A81 ("feature
    /// not provided"), in which case read the records one at a time.
    pub fn read_records_from(&mut self, first: u8) -> Result<Vec<u8>> {
        if first == 0 {
            return Err(Error::InvalidRecordNumber);
        }
        // P2 = 00000101: current EF, P1 is a record number, read from P1 to the last record.
        self.call_ok(&Command::with_le(
            cla::USER,
            ins::READ_RECORD,
            first,
            0x05,
            256,
        ))
    }

    /// The card's contact interface ATR, complete and checked.
    ///
    /// A contactless reader synthesises an ATR of its own, so this is the only way to see the real
    /// one over that interface. The card stores it without the initial `TS`, which is always `3B`
    /// for direct convention; this prepends it and verifies `TCK`, the exclusive-or of everything
    /// after `TS`.
    ///
    /// Which state answers varies between cards: some return it with the master file current and
    /// some only with an application selected, so try it in both if the first answers 6A88.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the checksum does not match, which would mean the bytes are not an
    /// ATR at all.
    pub fn contact_atr(&mut self) -> Result<Vec<u8>> {
        let stored = self.get_data(0x5F51)?;
        let (tck, body) = stored
            .split_last()
            .ok_or_else(|| Error::Malformed("contact ATR is empty".into()))?;
        let computed = body.iter().fold(0u8, |acc, b| acc ^ b);
        if computed != *tck {
            return Err(Error::Malformed(format!(
                "contact ATR checksum is {tck:02X}, computed {computed:02X}"
            )));
        }
        Ok([&[0x3B][..], &stored].concat())
    }

    /// INTERNAL AUTHENTICATE — have the card sign a challenge with the key named by `sfi`.
    ///
    /// The card hashes nothing: it signs `DigestInfo(SHA-256(challenge))` under PKCS #1 v1.5, so
    /// the result is an ordinary `sha256WithRSAEncryption` signature over the challenge. It is
    /// deterministic, and the challenge may be 1 to 255 bytes.
    ///
    /// Only one key on this card answers: 共通カードAP `0019`, and it answers with no credential
    /// presented. Every other key refuses — 6982 if it is behind a PIN, 6985 for the two 券面
    /// signing keys, which sign through [`ins::COMPUTE_SIGNATURE`] instead.
    ///
    /// The public half of `0019` is not on the card, so nothing read from the card can check the
    /// result. A verifier needs that key from somewhere else.
    pub fn internal_authenticate(&mut self, sfi: ShortEfId, challenge: &[u8]) -> Result<Vec<u8>> {
        if challenge.is_empty() || challenge.len() > 255 {
            return Err(Error::Malformed(format!(
                "challenge must be 1 to 255 bytes, got {}",
                challenge.len()
            )));
        }
        self.call_ok(&Command::with_data_le(
            cla::USER,
            ins::INTERNAL_AUTHENTICATE,
            0x00,
            0x80 | sfi.value(),
            challenge.to_vec(),
            256,
        ))
    }

    /// GET CHALLENGE — `len` random bytes from the card, 1 to 256 of them.
    ///
    /// Every length in that range is honoured exactly; the extended form is refused with 6985, so
    /// 256 is the ceiling. P1 and P2 must both be zero and the card answers at the master file
    /// level as well as inside an application.
    ///
    /// Sixteen is what the 券面 protocol wants for a challenge. Larger values make this the card's
    /// random number generator, which is a fair description of it: sixteen 256 byte draws come
    /// back distinct with a byte distribution flat to the limit of that sample.
    ///
    /// # Errors
    ///
    /// [`Error::ExpectedLengthOutOfRange`] if `len` is zero or above 256, before anything is sent.
    pub fn get_challenge(&mut self, len: u16) -> Result<Vec<u8>> {
        if len == 0 || len > 256 {
            return Err(Error::ExpectedLengthOutOfRange(u32::from(len)));
        }
        let data = self.call_ok(&Command::with_le(
            cla::USER,
            ins::GET_CHALLENGE,
            0x00,
            0x00,
            u32::from(len),
        ))?;
        if data.len() != usize::from(len) {
            return Err(Error::Malformed(format!(
                "asked for a {len} byte challenge and got {}",
                data.len()
            )));
        }
        Ok(data)
    }

    /// GET DATA — retrieve the data object named by `tag`, which goes in P1-P2.
    ///
    /// Not a JICSAP command. The card implements it anyway, and with the default GlobalPlatform
    /// Issuer Security Domain current it is the only route to a set of objects that no EF holds;
    /// see [`crate::mf::MasterFile`].
    ///
    /// Objects here range from one byte to several hundred, and the card refuses a short `Le` for
    /// the large ones rather than reporting the right length, so a 6700 is retried with an
    /// extended `Le`. That costs one extra APDU on the large objects and none on the rest.
    pub fn get_data(&mut self, tag: u16) -> Result<Vec<u8>> {
        let [p1, p2] = tag.to_be_bytes();
        let short = Command::with_le(cla::USER, ins::GET_DATA, p1, p2, 256);
        match self.call(&short)? {
            response if response.status.is_success() => Ok(response.data),
            response if response.status.value() == 0x6700 => {
                let extended = Command::with_le(cla::USER, ins::GET_DATA, p1, p2, 65536);
                self.call_ok(&extended)
            }
            response => Err(Error::from_status(response.status)),
        }
    }

    /// VERIFY the currently selected internal EF against `pin`.
    ///
    /// A failure decrements the card's retry counter. Once it reaches zero the key is blocked
    /// and only a municipal office can unblock it, so check [`Card::pin_retries`] first if the
    /// value might be wrong.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PinIncorrect`] with the remaining attempts, or [`Error::PinBlocked`].
    pub fn verify(&mut self, pin: &Pin) -> Result<()> {
        // P2 = 10000000: the key of the current EF (JICSAP Table 19).
        self.call_ok(&Command::with_data(
            cla::USER,
            ins::VERIFY,
            0x00,
            0x80,
            pin.as_bytes(),
        ))?;
        Ok(())
    }

    /// VERIFY a key named by short EF identifier, with no prior SELECT FILE.
    ///
    /// Same effect as [`Card::select_ef`] followed by [`Card::verify`], in one exchange.
    pub fn verify_sfi(&mut self, sfi: ShortEfId, pin: &Pin) -> Result<()> {
        let p2 = 0x80 | sfi.value();
        self.call_ok(&Command::with_data(
            cla::USER,
            ins::VERIFY,
            0x00,
            p2,
            pin.as_bytes(),
        ))?;
        Ok(())
    }

    /// Replace the PIN in the currently selected internal EF with `new_pin` using ISO/IEC
    /// 7816-4 CHANGE REFERENCE DATA.
    ///
    /// The current PIN must already have been presented with [`Card::verify`]. This is the form
    /// used by the JPKI and 券面入力補助 applications: P1=`01` means replacement data, and
    /// P2=`80` refers to the current EF.
    ///
    /// Prefer the per-application change methods, which select the right EF and verify the old
    /// PIN before reaching this command.
    pub fn change_reference_data(&mut self, new_pin: &Pin) -> Result<()> {
        self.call_ok(&Command::with_data(
            cla::USER,
            ins::CHANGE_REFERENCE_DATA,
            0x01,
            0x80,
            new_pin.as_bytes(),
        ))?;
        Ok(())
    }

    /// Replace the PIN in the currently selected internal EF with `new_pin` using JICSAP CHANGE
    /// KEY.
    ///
    /// The current PIN must already have been presented with [`Card::verify`], so that the
    /// changing security condition of the IEF is fulfilled. This is the form used by the 共通
    /// カード and 住基 applications: P1=`00`, and P2=`80` refers to the current EF.
    ///
    /// This accepts a [`Pin`] rather than arbitrary key material because it exposes only the PIN
    /// changing use of the broader JICSAP command. Prefer the per-application change methods.
    pub fn change_key(&mut self, new_pin: &Pin) -> Result<()> {
        self.call_ok(&Command::with_data(
            cla::SYSTEM,
            ins::CHANGE_KEY,
            0x00,
            0x80,
            new_pin.as_bytes(),
        ))?;
        Ok(())
    }

    /// Ask how many attempts remain on the currently selected internal EF.
    ///
    /// This sends a VERIFY with no data field, which JICSAP 6.4.9 (5) defines as querying the
    /// retry counter without consuming an attempt.
    pub fn pin_retries(&mut self) -> Result<Retries> {
        let response = self.call(&Command::new(cla::USER, ins::VERIFY, 0x00, 0x80))?;
        interpret_retries(response.status)
    }

    /// Ask how many attempts remain on the key named by a short EF identifier.
    pub fn pin_retries_sfi(&mut self, sfi: ShortEfId) -> Result<Retries> {
        let p2 = 0x80 | sfi.value();
        let response = self.call(&Command::new(cla::USER, ins::VERIFY, 0x00, p2))?;
        interpret_retries(response.status)
    }
}

fn interpret_retries(status: StatusWord) -> Result<Retries> {
    match status.value() {
        0x6300 => Ok(Retries::Unlimited),
        0x63C0 => Ok(Retries::Blocked),
        0x6984 => Ok(Retries::Blocked),
        0x9000 => Ok(Retries::NotReported),
        _ => match status.retries_remaining() {
            Some(n) => Ok(Retries::Remaining(n)),
            None => Err(Error::from_status(status)),
        },
    }
}

/// Whether a status word means "there is nothing more to read here".
fn is_end_of_file(sw: StatusWord) -> bool {
    match sw.value() {
        // The status JICSAP 7.3.1 defines for READ BINARY past the end of the file.
        0x6B00 => true,
        // Not in the JICSAP list, but the ISO/IEC 7816-4 warning for "end of file reached before
        // reading Le bytes"; tolerated so a card that prefers it is not treated as failing.
        0x6282 => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;

    fn ok(data: &[u8]) -> Vec<u8> {
        let mut v = data.to_vec();
        v.extend_from_slice(&[0x90, 0x00]);
        v
    }

    #[test]
    fn selects_a_df_by_name() {
        let mut card = Card::new(MockTransport::new([ok(&[])]));
        card.select_df(&[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00])
            .unwrap();
        assert_eq!(
            card.transport().sent[0],
            [
                0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn rejects_a_df_name_the_command_cannot_carry() {
        let mut card = Card::new(MockTransport::new([]));
        assert!(matches!(card.select_df(&[]), Err(Error::InvalidDfName(0))));
        assert!(matches!(
            card.select_df(&[0u8; 17]),
            Err(Error::InvalidDfName(17))
        ));
        assert!(card.transport().sent.is_empty());
    }

    #[test]
    fn selects_an_ef_by_identifier() {
        let mut card = Card::new(MockTransport::new([ok(&[])]));
        card.select_ef(0x000A).unwrap();
        assert_eq!(
            card.transport().sent[0],
            [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x0A]
        );
    }

    #[test]
    fn short_ef_ids_cover_exactly_0001_to_001e() {
        assert_eq!(ShortEfId::from_ef_id(0x0001).unwrap().value(), 0x01);
        assert_eq!(ShortEfId::from_ef_id(0x001E).unwrap().value(), 0x1E);
        assert!(matches!(
            ShortEfId::from_ef_id(0x0000),
            Err(Error::NoShortEfId(0))
        ));
        assert!(matches!(
            ShortEfId::from_ef_id(0x001F),
            Err(Error::NoShortEfId(0x1F))
        ));
        assert!(matches!(
            ShortEfId::from_ef_id(0x2F10),
            Err(Error::NoShortEfId(0x2F10))
        ));
    }

    #[test]
    fn reads_by_short_ef_id_without_selecting_first() {
        let mut card = Card::new(MockTransport::new([ok(&[0xAA])]));
        let sfi = ShortEfId::from_ef_id(0x000A).unwrap();
        card.read_binary_chunk_sfi(sfi, 0x00, 256).unwrap();
        // P1 = 1000_1010: short EF identifier 0x0A; P2 is an 8 bit offset.
        assert_eq!(card.transport().sent[0], [0x00, 0xB0, 0x8A, 0x00, 0x00]);
    }

    #[test]
    fn verifies_by_short_ef_id_without_selecting_first() {
        let mut card = Card::new(MockTransport::new([ok(&[])]));
        let sfi = ShortEfId::from_ef_id(0x0018).unwrap();
        card.verify_sfi(sfi, &Pin::numeric("1234").unwrap())
            .unwrap();
        assert_eq!(
            card.transport().sent[0],
            [0x00, 0x20, 0x00, 0x98, 0x04, b'1', b'2', b'3', b'4']
        );
    }

    #[test]
    fn retries_with_the_length_the_card_asks_for() {
        let mut card = Card::new(MockTransport::new([vec![0x6C, 0x04], ok(&[1, 2, 3, 4])]));
        let data = card.read_binary_chunk(0, 256).unwrap();
        assert_eq!(data, [1, 2, 3, 4]);
        assert_eq!(card.transport().sent[0], [0x00, 0xB0, 0x00, 0x00, 0x00]);
        assert_eq!(card.transport().sent[1], [0x00, 0xB0, 0x00, 0x00, 0x04]);
    }

    #[test]
    fn collects_chained_responses_with_get_response() {
        let mut card = Card::new(MockTransport::new([
            vec![0xAA, 0x61, 0x02],
            ok(&[0xBB, 0xCC]),
        ]));
        let data = card
            .call_ok(&Command::with_le(0x00, 0xB0, 0x00, 0x00, 256))
            .unwrap();
        assert_eq!(data, [0xAA, 0xBB, 0xCC]);
        assert_eq!(card.transport().sent[1], [0x00, 0xC0, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn read_binary_all_stops_at_the_end_of_the_tlv_object() {
        // A 300 byte object: the header says 0x0128 bytes of value, so two chunks are needed.
        let mut head = vec![0x30, 0x82, 0x01, 0x28];
        head.extend(std::iter::repeat_n(0xAA, MAX_CHUNK - 4));
        let tail = vec![0xBB; 0x012C - MAX_CHUNK];
        let mut card = Card::new(MockTransport::new([ok(&head), ok(&tail)]));

        let data = card.read_binary_all().unwrap();
        assert_eq!(data.len(), 0x012C);
        assert_eq!(card.transport().sent[1], [0x00, 0xB0, 0x01, 0x00, 0x2C]);
    }

    #[test]
    fn read_binary_all_trims_filler_after_the_object() {
        let mut file = vec![0x30, 0x02, 0xAA, 0xBB];
        file.extend(std::iter::repeat_n(0xFF, MAX_CHUNK - 4));
        let mut card = Card::new(MockTransport::new([ok(&file)]));
        assert_eq!(card.read_binary_all().unwrap(), [0x30, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn read_binary_all_stops_on_the_jicsap_end_of_file_status() {
        // An indefinite BER length is not something we parse, so the fallback loop runs and has
        // to recognise 6B00 — the status JICSAP 7.3.1 defines for reading past the end.
        let mut file = vec![0x30, 0x80];
        file.resize(MAX_CHUNK, 0xAA);
        let mut card = Card::new(MockTransport::new([ok(&file), vec![0x6B, 0x00]]));
        assert_eq!(card.read_binary_all().unwrap().len(), MAX_CHUNK);
        assert_eq!(card.transport().sent[1], [0x00, 0xB0, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn reads_one_record_and_a_run_of_records() {
        let mut card = Card::new(MockTransport::new([ok(&[0x01, 0x01, 0xAA]), ok(&[])]));
        card.read_record(1).unwrap();
        card.read_records_from(1).unwrap();
        assert_eq!(card.transport().sent[0], [0x00, 0xB2, 0x01, 0x04, 0x00]);
        assert_eq!(card.transport().sent[1], [0x00, 0xB2, 0x01, 0x05, 0x00]);
    }

    #[test]
    fn rejects_record_zero() {
        let mut card = Card::new(MockTransport::new([]));
        assert!(matches!(
            card.read_record(0),
            Err(Error::InvalidRecordNumber)
        ));
        assert!(matches!(
            card.read_records_from(0),
            Err(Error::InvalidRecordNumber)
        ));
        assert!(card.transport().sent.is_empty());
    }

    #[test]
    fn reports_the_retry_counter_without_spending_an_attempt() {
        let mut card = Card::new(MockTransport::new([vec![0x63, 0xC3]]));
        assert_eq!(card.pin_retries().unwrap(), Retries::Remaining(3));
        assert_eq!(card.transport().sent[0], [0x00, 0x20, 0x00, 0x80]);
    }

    #[test]
    fn distinguishes_blocked_unlimited_and_unreported_counters() {
        let mut card = Card::new(MockTransport::new([
            vec![0x63, 0xC0],
            vec![0x69, 0x84],
            vec![0x63, 0x00],
            vec![0x90, 0x00],
        ]));
        assert_eq!(card.pin_retries().unwrap(), Retries::Blocked);
        assert_eq!(card.pin_retries().unwrap(), Retries::Blocked);
        assert_eq!(card.pin_retries().unwrap(), Retries::Unlimited);
        assert_eq!(card.pin_retries().unwrap(), Retries::NotReported);

        assert_eq!(Retries::Blocked.count(), Some(0));
        assert_eq!(Retries::Remaining(2).count(), Some(2));
        assert_eq!(Retries::Unlimited.count(), None);
    }

    #[test]
    fn verify_surfaces_the_remaining_attempts() {
        let mut card = Card::new(MockTransport::new([vec![0x63, 0xC2]]));
        let err = card.verify(&Pin::new("1234").unwrap()).unwrap_err();
        assert!(matches!(err, Error::PinIncorrect { retries: Some(2) }));
        assert_eq!(
            card.transport().sent[0],
            [0x00, 0x20, 0x00, 0x80, 0x04, b'1', b'2', b'3', b'4']
        );
    }

    #[test]
    fn changes_reference_data_with_the_current_ef_form() {
        let mut card = Card::new(MockTransport::new([ok(&[])]));
        card.change_reference_data(&Pin::numeric("5678").unwrap())
            .unwrap();
        assert_eq!(
            card.transport().sent[0],
            [0x00, 0x24, 0x01, 0x80, 0x04, b'5', b'6', b'7', b'8']
        );
    }

    #[test]
    fn changes_a_jicsap_key_with_the_current_ef_form() {
        let mut card = Card::new(MockTransport::new([ok(&[])]));
        card.change_key(&Pin::numeric("5678").unwrap()).unwrap();
        assert_eq!(
            card.transport().sent[0],
            [0x80, 0x32, 0x00, 0x80, 0x04, b'5', b'6', b'7', b'8']
        );
    }

    #[test]
    fn verify_reports_a_blocked_key_from_either_status() {
        for status in [[0x63, 0xC0], [0x69, 0x84]] {
            let mut card = Card::new(MockTransport::new([status.to_vec()]));
            assert!(matches!(
                card.verify(&Pin::new("1234").unwrap()).unwrap_err(),
                Error::PinBlocked
            ));
        }
    }

    #[test]
    fn internal_authenticate_names_the_key_by_short_identifier() {
        let mut card = Card::new(MockTransport::new([ok(&[0xAA; 256])]));
        let sfi = ShortEfId::from_ef_id(0x0019).unwrap();
        card.internal_authenticate(sfi, b"hello").unwrap();
        assert_eq!(
            card.transport().sent[0],
            [&[0x00, 0x88, 0x00, 0x99, 0x05][..], b"hello", &[0x00][..]].concat()
        );
    }

    #[test]
    fn get_challenge_asks_for_the_length_it_was_given() {
        // 256 is the largest the card will produce, and it travels as an Le of zero.
        let mut card = Card::new(MockTransport::new([ok(&[0xAB; 256]), ok(&[0xCD; 8])]));
        assert_eq!(card.get_challenge(256).unwrap().len(), 256);
        assert_eq!(card.get_challenge(8).unwrap(), [0xCD; 8]);
        assert_eq!(card.transport().sent[0], [0x00, 0x84, 0x00, 0x00, 0x00]);
        assert_eq!(card.transport().sent[1], [0x00, 0x84, 0x00, 0x00, 0x08]);
    }

    #[test]
    fn get_challenge_rejects_a_length_the_card_will_not_produce() {
        let mut card = Card::new(MockTransport::new([]));
        assert!(card.get_challenge(0).is_err());
        assert!(card.get_challenge(257).is_err());
        // Neither reached the card: the extended form is refused with 6985 anyway.
        assert!(card.transport().sent.is_empty());
    }

    #[test]
    fn get_challenge_notices_a_short_answer() {
        let mut card = Card::new(MockTransport::new([ok(&[0x01, 0x02, 0x03])]));
        assert!(card.get_challenge(16).is_err());
    }

    #[test]
    fn internal_authenticate_rejects_a_challenge_the_command_cannot_carry() {
        let mut card = Card::new(MockTransport::new([ok(&[])]));
        let sfi = ShortEfId::from_ef_id(0x0019).unwrap();
        assert!(card.internal_authenticate(sfi, b"").is_err());
        assert!(card.internal_authenticate(sfi, &[0u8; 256]).is_err());
        // Neither reached the card.
        assert!(card.transport().sent.is_empty());
    }

    #[test]
    fn the_contact_atr_gets_its_ts_back_and_is_checked() {
        let stored = [0xE0, 0x00, 0xFF, 0x81, 0x31, 0xFE, 0x45, 0x14];
        let mut card = Card::new(MockTransport::new([[&stored[..], &[0x90, 0x00]].concat()]));
        assert_eq!(
            card.contact_atr().unwrap(),
            [0x3B, 0xE0, 0x00, 0xFF, 0x81, 0x31, 0xFE, 0x45, 0x14]
        );

        // One bit off and the checksum no longer matches.
        let mut bad = stored;
        bad[1] ^= 0x01;
        let mut card = Card::new(MockTransport::new([[&bad[..], &[0x90, 0x00]].concat()]));
        assert!(matches!(card.contact_atr(), Err(Error::Malformed(_))));
    }

    #[test]
    fn verify_reports_an_unlimited_counter() {
        let mut card = Card::new(MockTransport::new([vec![0x63, 0x00]]));
        assert!(matches!(
            card.verify(&Pin::new("1234").unwrap()).unwrap_err(),
            Error::PinIncorrect { retries: None }
        ));
    }
}
