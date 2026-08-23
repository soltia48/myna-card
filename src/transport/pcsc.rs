//! PC/SC backend.

use std::ffi::CString;

use crate::card::Card;
use crate::error::{Error, Result};
use crate::transport::Transmit;

/// Return the names of the readers currently known to the PC/SC service.
///
/// Names are converted lossily to UTF-8 so every platform reader name can be represented as a
/// [`String`]. An empty vector means the PC/SC service is available but currently knows no
/// readers; [`connect_any`] converts that condition to [`Error::NoReader`].
///
/// # Errors
///
/// Returns [`Error::Pcsc`] if a context cannot be established or the reader list cannot be
/// obtained from the service.
pub fn list_readers() -> Result<Vec<String>> {
    let context = ::pcsc::Context::establish(::pcsc::Scope::User)?;
    Ok(context
        .list_readers_owned()?
        .iter()
        .map(|name| name.to_string_lossy().into_owned())
        .collect())
}

/// Whether anything else may hold the card while this connection is open.
///
/// PC/SC lets several processes hold one card at once, and for reading that is the right default:
/// two programs can each ask the card what it is without getting in each other's way.
///
/// It is the wrong default for signing. A successful VERIFY stays in effect until the card leaves
/// the field — see [`PcscTransport::power_cycle`] — so between presenting a PIN and powering the
/// card down, anything else on the machine can use the key this connection unlocked, without
/// knowing the PIN. [`Sharing::Exclusive`] is what closes that window.
///
/// There is deliberately no [`Default`]. Which of these a program wants follows from what it is
/// about to do with the card, and the wrong one fails silently in opposite directions: sharing
/// when signing leaves the key open to the rest of the machine, and holding the card alone when
/// only reading locks out software the person at the keyboard is relying on. Neither shows up in
/// testing. Every connection says which it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sharing {
    /// Other processes may hold the same card at the same time. The PC/SC default.
    Shared,
    /// Nothing else may hold the card until this connection is dropped.
    ///
    /// This reserves the card rather than the key: it keeps other software away from a security
    /// status this connection established, and it does so for as long as the connection lives. The
    /// software being kept away is the card's other legitimate users, so hold the reservation for
    /// as long as the key needs it and no longer.
    ///
    /// It is not a lock the card enforces, and it protects nothing the card is not currently in a
    /// reader for. Something already holding the card keeps it — connecting is what fails.
    Exclusive,
}

impl Sharing {
    fn mode(self) -> ::pcsc::ShareMode {
        match self {
            Sharing::Shared => ::pcsc::ShareMode::Shared,
            Sharing::Exclusive => ::pcsc::ShareMode::Exclusive,
        }
    }
}

/// Connect to the card in the first available reader.
///
/// # Errors
///
/// Returns [`Error::NoReader`] if no reader is present, and
/// [`Error::Pcsc`]\([`SharingViolation`](::pcsc::Error::SharingViolation)) if `sharing` is
/// [`Sharing::Exclusive`] and something else is already holding the card.
pub fn connect_any(sharing: Sharing) -> Result<Card<PcscTransport>> {
    let context = ::pcsc::Context::establish(::pcsc::Scope::User)?;
    let reader = context
        .list_readers_owned()?
        .into_iter()
        .next()
        .ok_or(Error::NoReader)?;
    open(&context, &reader, sharing)
}

/// Connect to the card in the reader with the given name.
///
/// # Errors
///
/// Returns [`Error::ReaderNotFound`] if no reader has that name, and
/// [`Error::Pcsc`]\([`SharingViolation`](::pcsc::Error::SharingViolation)) if `sharing` is
/// [`Sharing::Exclusive`] and something else is already holding the card.
pub fn connect(reader: &str, sharing: Sharing) -> Result<Card<PcscTransport>> {
    let context = ::pcsc::Context::establish(::pcsc::Scope::User)?;
    let name = context
        .list_readers_owned()?
        .into_iter()
        .find(|name| name.to_string_lossy() == reader)
        .ok_or_else(|| Error::ReaderNotFound(reader.to_owned()))?;
    open(&context, &name, sharing)
}

fn open(
    context: &::pcsc::Context,
    reader: &CString,
    sharing: Sharing,
) -> Result<Card<PcscTransport>> {
    let card = context.connect(reader, sharing.mode(), ::pcsc::Protocols::ANY)?;
    Ok(Card::new(PcscTransport::new(card, sharing)))
}

/// A [`Transmit`] implementation backed by a PC/SC connection.
pub struct PcscTransport {
    card: ::pcsc::Card,
    buffer: Vec<u8>,
    /// What the card was connected as, so that [`Self::power_cycle`] can reconnect it the same
    /// way. Reconnecting is a fresh `SCardReconnect` and takes a share mode of its own; taking
    /// the shared one there would drop an exclusive reservation in the middle of holding it.
    sharing: Sharing,
}

impl PcscTransport {
    /// Wrap an already connected PC/SC card.
    ///
    /// `sharing` is how the card was connected, not a request: it is what
    /// [`power_cycle`](Self::power_cycle) reconnects with, so a value that disagrees with the
    /// `SCardConnect` behind `card` is how an exclusive reservation gets handed back mid-session.
    pub fn new(card: ::pcsc::Card, sharing: Sharing) -> Self {
        PcscTransport {
            card,
            buffer: vec![0; ::pcsc::MAX_BUFFER_SIZE_EXTENDED],
            sharing,
        }
    }

    /// How this connection is shared with anything else that talks to the card.
    ///
    /// This is the mode recorded at construction and used for reconnects. It does not query
    /// whether another process currently has a compatible connection.
    pub fn sharing(&self) -> Sharing {
        self.sharing
    }

    /// The underlying PC/SC card, for operations this crate does not cover.
    ///
    /// Use [`Self::into_inner`] when ownership or a mutable PC/SC operation is required. Raw
    /// commands sent outside [`Transmit`] bypass the APDU response handling in [`Card`]
    /// and may change the selected file or security status.
    pub fn card(&self) -> &::pcsc::Card {
        &self.card
    }

    /// Power the card down and back up.
    ///
    /// This is the only thing that clears the card's security status. A warm reset does not, and
    /// neither does disconnecting and reconnecting: whatever was verified stays verified until the
    /// card leaves the field. It is also what makes the master file current again, which is the
    /// state [`crate::mf::MasterFile`] needs.
    ///
    /// The first command after the card comes back is answered 6F00 on the card this was measured
    /// against, so one throwaway SELECT is sent and its result discarded — otherwise every caller
    /// would have to know that.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Pcsc`] if PC/SC cannot reconnect and power-cycle the card. The status and
    /// transport result of the documented throwaway command are intentionally ignored.
    pub fn power_cycle(&mut self) -> Result<()> {
        self.card.reconnect(
            self.sharing.mode(),
            ::pcsc::Protocols::ANY,
            ::pcsc::Disposition::UnpowerCard,
        )?;
        // 00 A4 00 00 selects nothing on this card, so it is safe to throw away.
        let _ = self.transmit(&[0x00, 0xA4, 0x00, 0x00]);
        Ok(())
    }

    /// Give back the underlying PC/SC card without disconnecting or changing its disposition.
    ///
    /// The connection remains in the sharing mode reported by [`Self::sharing`]. Its eventual
    /// drop follows the `pcsc` crate's normal disconnect behavior.
    pub fn into_inner(self) -> ::pcsc::Card {
        self.card
    }
}

impl Transmit for PcscTransport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        Ok(self.card.transmit(command, &mut self.buffer)?.to_vec())
    }
}

/// `pcsc::Card` is not `Debug`, so there is nothing useful to show.
impl std::fmt::Debug for PcscTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcscTransport").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping is the whole of what [`Sharing`] does, and reversing it fails open: a caller
    /// that asked to be alone with the card would get a shared connection, succeed, and only find
    /// out on a machine where something else is talking to the reader.
    #[test]
    fn sharing_maps_to_the_pcsc_mode_of_the_same_name() {
        assert_eq!(Sharing::Shared.mode(), ::pcsc::ShareMode::Shared);
        assert_eq!(Sharing::Exclusive.mode(), ::pcsc::ShareMode::Exclusive);
    }
}
