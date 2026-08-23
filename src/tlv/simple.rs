//! The simple encoded TLV format of JICSAP 4.4.1 (1).
//!
//! This is the record format of record structured working EFs, and the format of the card
//! identifier (Annex B), the application folder list file (Annex D) and the IC manufacturer ID
//! file (Annex F).
//!
//! ```text
//! ┌─────────┬──────────────────┬───────────────┐
//! │ tag     │ length           │ value         │
//! │ 1 byte  │ 1 byte or 3 byte │ 0..65535 byte │
//! └─────────┴──────────────────┴───────────────┘
//! ```
//!
//! - **Tag**: one byte, 1 to 254. `00` marks an unused tag; `FF` is never a valid tag.
//! - **Length**: one byte for 0 to 254. If that byte is `FF`, the two bytes after it hold the
//!   length big-endian, for 0 to 65535.
//!
//! Both length forms may appear in the same EF.

use crate::error::{Error, Result};

/// A tag value of `00`, which JICSAP 4.4.1 (1) defines as "the tag is not used".
pub const TAG_UNUSED: u8 = 0x00;

/// A tag value of `FF`, which is never valid and which is also the initial value of an erased
/// byte in a transparent EF (JICSAP 4.4.2 (1)).
pub const TAG_INVALID: u8 = 0xFF;

/// The tag and length of a simple encoded TLV object, without its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The one byte tag, also called the record identifier.
    pub tag: u8,
    /// Length of the value field in bytes.
    pub length: usize,
    /// Combined length of the encoded tag and length fields: 2, or 4 for the long length form.
    pub header_len: usize,
}

impl Header {
    /// Total size of the object: header plus value.
    pub fn total_len(&self) -> usize {
        self.header_len + self.length
    }
}

/// A parsed simple encoded TLV object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The one byte tag, also called the record identifier.
    pub tag: u8,
    /// The value field.
    pub value: &'a [u8],
}

/// Parse the tag and length at the start of `data`.
///
/// The value itself need not be present, so this works on a partially read file.
///
/// # Errors
///
/// Returns [`Error::Malformed`] if the tag is [`TAG_INVALID`], if the tag or length is truncated,
/// or if the two bytes following a long-form `FF` length marker are missing. The declared value
/// need not be present; [`parse`] checks it.
///
/// # Example
///
/// ```
/// use myna_card::tlv::simple;
///
/// let header = simple::parse_header(&[0x01, 0xFF, 0x01, 0x00])?;
/// assert_eq!(header.tag, 0x01);
/// assert_eq!(header.length, 256);
/// assert_eq!(header.header_len, 4);
/// # Ok::<(), myna_card::Error>(())
/// ```
pub fn parse_header(data: &[u8]) -> Result<Header> {
    let tag = *data.first().ok_or_else(|| malformed("empty TLV"))?;
    if tag == TAG_INVALID {
        return Err(malformed("tag 'FF' is not a valid simple TLV tag"));
    }
    let first_len = *data
        .get(1)
        .ok_or_else(|| malformed("truncated TLV length"))?;
    if first_len != 0xFF {
        return Ok(Header {
            tag,
            length: usize::from(first_len),
            header_len: 2,
        });
    }
    let bytes = data
        .get(2..4)
        .ok_or_else(|| malformed("truncated long-form TLV length"))?;
    let length = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    Ok(Header {
        tag,
        length,
        header_len: 4,
    })
}

/// Parse the first complete TLV object in `data`.
///
/// Bytes following the first object are ignored. Use [`iter`] for the concatenated response from
/// a multi-record READ RECORD(S). The returned [`Tlv::value`] excludes the header and borrows from
/// `data`.
///
/// # Errors
///
/// Returns [`Error::Malformed`] for every header error described by [`parse_header`], or if the
/// complete declared value is not present.
pub fn parse(data: &[u8]) -> Result<Tlv<'_>> {
    let header = parse_header(data)?;
    let value = data
        .get(header.header_len..header.total_len())
        .ok_or_else(|| malformed("TLV value is truncated"))?;
    Ok(Tlv {
        tag: header.tag,
        value,
    })
}

/// Iterate over the TLV objects concatenated in `data`, as returned by a multi-record READ
/// RECORD(S).
///
/// Iteration stops cleanly at a `FF` tag, which JICSAP 4.4.1 (1) never assigns and which is also
/// the value of an erased byte.
///
/// Tag `00` is *not* a terminator, even though 4.4.1 (1) calls it "the tag is not used": Annex B
/// gives it to the mandatory first record of the card identifier. Callers that read a file where
/// `00` really does mean an empty slot should stop on it themselves.
///
/// Tag `FE` is not skipped either. The application folder list file uses it to mark a record as
/// invalidated, but the object is otherwise well formed, so [`crate::mf::ApplicationFolders`]
/// filters it rather than this iterator.
///
/// A malformed object is yielded once as [`Err`], after which the iterator is exhausted. Values
/// yielded earlier continue to borrow their original bytes from `data`.
pub fn iter(data: &[u8]) -> Iter<'_> {
    Iter { rest: data }
}

/// Iterator returned by [`iter`].
#[derive(Debug, Clone)]
pub struct Iter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Iter<'a> {
    type Item = Result<Tlv<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.rest.first() {
            None | Some(&TAG_INVALID) => return None,
            Some(_) => {}
        }
        let result = parse_header(self.rest).and_then(|header| {
            let value = self
                .rest
                .get(header.header_len..header.total_len())
                .ok_or_else(|| malformed("TLV value is truncated"))?;
            Ok((
                header.total_len(),
                Tlv {
                    tag: header.tag,
                    value,
                },
            ))
        });
        match result {
            Ok((consumed, tlv)) => {
                self.rest = &self.rest[consumed..];
                Some(Ok(tlv))
            }
            Err(err) => {
                self.rest = &[];
                Some(Err(err))
            }
        }
    }
}

/// Find the value of the first object with the given tag.
///
/// Returns `Ok(None)` when the iterator reaches the end or erased `FF` filler without finding the
/// tag. An invalid object before the requested tag is returned as [`Error::Malformed`]; malformed
/// bytes after an already found object are never inspected.
pub fn find(data: &[u8], tag: u8) -> Result<Option<&[u8]>> {
    for tlv in iter(data) {
        let tlv = tlv?;
        if tlv.tag == tag {
            return Ok(Some(tlv.value));
        }
    }
    Ok(None)
}

fn malformed(what: &str) -> Error {
    Error::Malformed(what.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_short_length_form() {
        let header = parse_header(&[0x00, 0x03, 0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(
            header,
            Header {
                tag: 0x00,
                length: 3,
                header_len: 2
            }
        );
        assert_eq!(header.total_len(), 5);
    }

    #[test]
    fn parses_the_long_length_form() {
        // 'FF' as the first length byte introduces a two byte big-endian length.
        let header = parse_header(&[0x01, 0xFF, 0x01, 0x00]).unwrap();
        assert_eq!(
            header,
            Header {
                tag: 0x01,
                length: 256,
                header_len: 4
            }
        );
        assert_eq!(header.total_len(), 260);
    }

    #[test]
    fn length_254_still_uses_the_short_form() {
        let header = parse_header(&[0x01, 0xFE]).unwrap();
        assert_eq!(
            header,
            Header {
                tag: 0x01,
                length: 254,
                header_len: 2
            }
        );
    }

    #[test]
    fn rejects_the_invalid_tag_and_truncation() {
        assert!(parse_header(&[0xFF, 0x02]).is_err());
        assert!(parse_header(&[0x01]).is_err());
        assert!(parse_header(&[0x01, 0xFF, 0x00]).is_err());
        assert!(parse_header(&[]).is_err());
    }

    #[test]
    fn iterates_concatenated_records() {
        // Two records as a multi-record READ RECORD(S) would return them, then erased filler.
        let data = [0x01, 0x02, 0xAA, 0xBB, 0x02, 0x01, 0xCC, 0xFF, 0xFF];
        let items: Vec<_> = iter(&data).map(|t| t.unwrap()).collect();
        assert_eq!(
            items,
            [
                Tlv {
                    tag: 0x01,
                    value: &[0xAA, 0xBB]
                },
                Tlv {
                    tag: 0x02,
                    value: &[0xCC]
                },
            ]
        );
    }

    #[test]
    fn tag_00_is_an_object_not_a_terminator() {
        // Annex B gives tag '00' to the mandatory first record of the card identifier.
        let data = [0x00, 0x03, 0x07, 0x0A, 0x02, 0x01, 0x01, 0x05];
        let items: Vec<_> = iter(&data).map(|t| t.unwrap()).collect();
        assert_eq!(
            items,
            [
                Tlv {
                    tag: 0x00,
                    value: &[0x07, 0x0A, 0x02]
                },
                Tlv {
                    tag: 0x01,
                    value: &[0x05]
                },
            ]
        );
    }

    #[test]
    fn finds_by_tag() {
        // The card identifier of JICSAP Annex B: manufacturer record then optional function record.
        let data = [0x00, 0x03, 0x01, 0x04, 0x02, 0x01, 0x01, 0x09];
        assert_eq!(find(&data, 0x00).unwrap(), Some(&[0x01, 0x04, 0x02][..]));
        assert_eq!(find(&data, 0x01).unwrap(), Some(&[0x09][..]));
        assert_eq!(find(&data, 0x02).unwrap(), None);
    }
}
