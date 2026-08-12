//! 住基AP — the resident registry network application.
//!
//! The least understood of the five. It exposes one record structured EF whose content has not
//! been identified, and a key reference whose verification does not visibly change the security
//! status of anything else in the application.

use crate::card::{Card, Retries};
use crate::error::Result;
use crate::pin::Pin;
use crate::transport::Transmit;

/// AID of the resident registry network application.
pub const DF: [u8; 10] = [0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x01];

/// File identifiers within the resident registry network application.
pub mod ef {
    /// Purpose not yet identified; the same content as EF 0002 of the 共通カード application.
    pub const UNKNOWN_0002: u16 = 0x0002;
    /// Key reference for the PIN.
    pub const PIN: u16 = 0x001C;
}

/// The resident registry network application, selected on a card.
#[derive(Debug)]
pub struct JukiAp<'a, T> {
    card: &'a mut Card<T>,
}

impl<'a, T: Transmit> JukiAp<'a, T> {
    /// Select the application.
    pub fn select(card: &'a mut Card<T>) -> Result<Self> {
        card.select_df(&DF)?;
        Ok(JukiAp { card })
    }

    /// Borrow the underlying card, for operations this wrapper does not cover.
    pub fn card(&mut self) -> &mut Card<T> {
        self.card
    }

    /// Read one record of a record structured EF of this application. Records start at 1.
    pub fn read_record(&mut self, id: u16, record: u8) -> Result<Vec<u8>> {
        self.card.select_ef(id)?;
        self.card.read_record(record)
    }

    /// Present the PIN.
    pub fn verify_pin(&mut self, pin: &Pin) -> Result<()> {
        self.card.select_ef(ef::PIN)?;
        self.card.verify(pin)
    }

    /// Attempts remaining on the PIN, without spending one.
    pub fn pin_retries(&mut self) -> Result<Retries> {
        self.card.select_ef(ef::PIN)?;
        self.card.pin_retries()
    }
}
