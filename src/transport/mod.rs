//! Abstraction over the link that carries APDUs to and from the card.

use crate::error::Result;

#[cfg(feature = "pcsc")]
pub mod pcsc;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

/// Something that can exchange raw APDUs with a card.
///
/// Implementors are responsible for the physical link only. They do not interpret the bytes,
/// and in particular they must return the response *including* its trailing status word.
pub trait Transmit {
    /// Send an encoded command APDU and return the raw response.
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
