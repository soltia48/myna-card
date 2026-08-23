//! An in-memory [`Transmit`] implementation for tests.

use std::collections::VecDeque;

use crate::error::Result;
use crate::transport::Transmit;

/// A transport that replays a fixed script of responses and records what was sent.
///
/// Useful for exercising the command layer without a physical card. Responses are consumed in
/// FIFO order. After the script is exhausted, further transmissions receive `6F00` ("no precise
/// diagnosis") rather than panicking; [`MockTransport::is_drained`] only reports whether the
/// explicit responses were consumed.
///
/// # Example
///
/// ```
/// use myna_card::{Card, StatusWord};
/// use myna_card::transport::mock::MockTransport;
///
/// let transport = MockTransport::new([vec![0xDE, 0xAD, 0x90, 0x00]]);
/// let mut card = Card::new(transport);
/// let response = card.call(&myna_card::Command::new(0x00, 0x84, 0x00, 0x00))?;
///
/// assert_eq!(response.data, [0xDE, 0xAD]);
/// assert_eq!(response.status, StatusWord::SUCCESS);
/// assert!(card.transport().is_drained());
/// assert_eq!(card.transport().sent, [vec![0x00, 0x84, 0x00, 0x00]]);
/// # Ok::<(), myna_card::Error>(())
/// ```
#[derive(Debug, Default)]
pub struct MockTransport {
    responses: VecDeque<Vec<u8>>,
    /// Every command APDU that was transmitted, in order.
    pub sent: Vec<Vec<u8>>,
}

impl MockTransport {
    /// Build a transport that returns the given complete response APDUs in order.
    ///
    /// Each response must include SW1-SW2. An invalid short response is deliberately retained so
    /// tests can exercise [`Error::ShortResponse`](crate::Error::ShortResponse).
    pub fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
        MockTransport {
            responses: responses.into_iter().collect(),
            sent: Vec::new(),
        }
    }

    /// Queue one more response after every response already waiting.
    ///
    /// This also works after the original script has been drained.
    pub fn push(&mut self, response: Vec<u8>) {
        self.responses.push_back(response);
    }

    /// Whether every explicitly queued response has been consumed.
    ///
    /// This does not mean that transmission is disabled: an exhausted mock continues to answer
    /// `6F00`.
    pub fn is_drained(&self) -> bool {
        self.responses.is_empty()
    }
}

impl Transmit for MockTransport {
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        self.sent.push(command.to_vec());
        // An exhausted script answers "no precise diagnosis" rather than panicking, so that a
        // test asserting on error paths does not have to pad its script.
        Ok(self
            .responses
            .pop_front()
            .unwrap_or_else(|| vec![0x6F, 0x00]))
    }
}
