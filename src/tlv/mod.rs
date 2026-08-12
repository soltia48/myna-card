//! TLV readers for the two encodings the card uses.
//!
//! The card does not use one TLV encoding but two, and which applies depends on the file:
//!
//! - Record structured working EFs hold records in the **simple encoded TLV** format of JICSAP
//!   4.4.1 (1): a one byte tag, a one *or three* byte length, and the value. See [`simple`].
//! - Transparent working EFs are, as far as the card is concerned, just bytes (JICSAP 4.4.2).
//!   What the applications put there is BER-TLV — DER certificates in the JPKI application, and
//!   BER-TLV objects in the 券面 applications. See [`ber`].
//!
//! The two are not interchangeable. In the simple encoding a first length byte of `FF` introduces
//! a two byte length; in BER that same byte is not a valid length at all. In BER a tag whose low
//! five bits are all set continues into further bytes; in the simple encoding every tag is one
//! byte and `FF` is not a valid tag.

pub mod ber;
pub mod simple;
