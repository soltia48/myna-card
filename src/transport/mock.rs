//! An in-memory [`Transmit`] implementation for tests.

use std::collections::VecDeque;

use crate::error::Result;
use crate::transport::Transmit;

/// A transport that replays a fixed script of responses and records what was sent.
///
/// Useful for exercising the command layer without a physical card.
#[derive(Debug, Default)]
pub struct MockTransport {
    responses: VecDeque<Vec<u8>>,
    /// Every command APDU that was transmitted, in order.
    pub sent: Vec<Vec<u8>>,
}

impl MockTransport {
    /// Build a transport that returns the given responses in order.
    pub fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
        MockTransport {
            responses: responses.into_iter().collect(),
            sent: Vec::new(),
        }
    }

    /// Queue one more response.
    pub fn push(&mut self, response: Vec<u8>) {
        self.responses.push_back(response);
    }

    /// Whether every queued response has been consumed.
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
