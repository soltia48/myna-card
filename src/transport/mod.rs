//! Abstraction over the link that carries APDUs to and from the card.
//!
//! [`Card`](crate::Card) owns a transport and layers APDU encoding, response parsing and card
//! operations over it. Applications that already have another smart-card link can use the rest
//! of this crate without enabling the `pcsc` feature by implementing [`Transmit`].

use crate::error::Result;

#[cfg(feature = "pcsc")]
pub mod pcsc;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

/// Something that can exchange raw APDUs with a card.
///
/// Implementors are responsible for the physical link only. They do not interpret the bytes,
/// and in particular they must return the response *including* its trailing status word.
/// `command` is already encoded by [`Command::to_bytes`](crate::Command::to_bytes), so it must be
/// forwarded unchanged. Protocol recovery such as retrying `6Cxx` and collecting `61xx` belongs
/// to [`Card::call`](crate::Card::call), not to the transport.
///
/// Transport failures should be returned as [`Error`](crate::Error). A status reported by the
/// card is not a transport failure: include its SW1-SW2 bytes in the returned vector and let the
/// card layer classify it.
///
/// # Example
///
/// A minimal transport can be useful when embedding the crate behind an existing device API:
///
/// ```
/// use myna_card::{Card, Command, Result, Transmit};
///
/// struct AlwaysSucceeds;
///
/// impl Transmit for AlwaysSucceeds {
///     fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
///         assert_eq!(command, [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x01]);
///         Ok(vec![0x90, 0x00]) // response data is empty; SW is 9000
///     }
/// }
///
/// let mut card = Card::new(AlwaysSucceeds);
/// card.select_ef(0x0001)?;
/// # Ok::<(), myna_card::Error>(())
/// ```
pub trait Transmit {
    /// Send one encoded command APDU and return the complete raw response APDU.
    ///
    /// A successful transport exchange may still carry a failing card status. Even a response
    /// with no data therefore contains at least the two status bytes; shorter responses are
    /// rejected later as [`Error::ShortResponse`](crate::Error::ShortResponse).
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>>;
}

impl<T: Transmit + ?Sized> Transmit for &mut T {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        (**self).transmit(command)
    }
}

impl<T: Transmit + ?Sized> Transmit for Box<T> {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        (**self).transmit(command)
    }
}
