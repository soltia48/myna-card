//! PC/SC backend.

use std::ffi::CString;

use crate::card::Card;
use crate::error::{Error, Result};
use crate::transport::Transmit;

/// Return the names of the readers currently known to the PC/SC service.
pub fn list_readers() -> Result<Vec<String>> {
    let context = ::pcsc::Context::establish(::pcsc::Scope::User)?;
    Ok(context
        .list_readers_owned()?
        .iter()
        .map(|name| name.to_string_lossy().into_owned())
        .collect())
}

/// Connect to the card in the first available reader.
///
/// # Errors
///
/// Returns [`Error::NoReader`] if no reader is present.
pub fn connect_any() -> Result<Card<PcscTransport>> {
    let context = ::pcsc::Context::establish(::pcsc::Scope::User)?;
    let reader = context
        .list_readers_owned()?
        .into_iter()
        .next()
        .ok_or(Error::NoReader)?;
    connect_with(context, &reader)
}

/// Connect to the card in the reader with the given name.
///
/// # Errors
///
/// Returns [`Error::ReaderNotFound`] if no reader has that name.
pub fn connect(reader: &str) -> Result<Card<PcscTransport>> {
    let context = ::pcsc::Context::establish(::pcsc::Scope::User)?;
    let name = context
        .list_readers_owned()?
        .into_iter()
        .find(|name| name.to_string_lossy() == reader)
        .ok_or_else(|| Error::ReaderNotFound(reader.to_owned()))?;
    connect_with(context, &name)
}

fn connect_with(context: ::pcsc::Context, reader: &CString) -> Result<Card<PcscTransport>> {
    let card = context.connect(reader, ::pcsc::ShareMode::Shared, ::pcsc::Protocols::ANY)?;
    Ok(Card::new(PcscTransport::new(card)))
}

/// A [`Transmit`] implementation backed by a PC/SC connection.
pub struct PcscTransport {
    card: ::pcsc::Card,
    buffer: Vec<u8>,
}

impl PcscTransport {
    /// Wrap an already connected PC/SC card.
    pub fn new(card: ::pcsc::Card) -> Self {
        PcscTransport {
            card,
            buffer: vec![0; ::pcsc::MAX_BUFFER_SIZE_EXTENDED],
        }
    }

    /// The underlying PC/SC card, for operations this crate does not cover.
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
    pub fn power_cycle(&mut self) -> Result<()> {
        self.card.reconnect(
            ::pcsc::ShareMode::Shared,
            ::pcsc::Protocols::ANY,
            ::pcsc::Disposition::UnpowerCard,
        )?;
        // 00 A4 00 00 selects nothing on this card, so it is safe to throw away.
        let _ = self.transmit(&[0x00, 0xA4, 0x00, 0x00]);
        Ok(())
    }

    /// Give back the underlying PC/SC card.
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
