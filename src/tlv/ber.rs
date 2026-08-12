//! A minimal BER-TLV reader, for the contents of transparent EFs.
//!
//! JICSAP says nothing about what goes inside a transparent EF — 4.4.2 treats it as a plain byte
//! sequence — but the applications on the card put BER-TLV there: DER certificates in the JPKI
//! application, and BER-TLV objects in the 券面 applications. Such a file is usually one object
//! followed by filler bytes up to the physical size of the file, so parsing just the header is
//! enough to know how many bytes are worth reading, which is what
//! [`Card::read_binary_all`](crate::Card::read_binary_all) uses it for.
//!
//! For the records of a record structured EF, use [`crate::tlv::simple`] instead.
//!
//! Only the definite-length form is supported; the card does not use indefinite lengths.

use crate::error::{Error, Result};

/// The tag and length of a BER-TLV object, without its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The tag, with its bytes packed big-endian into a `u32`.
    pub tag: u32,
    /// Length of the value field in bytes.
    pub length: usize,
    /// Combined length of the encoded tag and length fields.
    pub header_len: usize,
}

impl Header {
    /// Total size of the object: header plus value.
    pub fn total_len(&self) -> usize {
        self.header_len + self.length
    }
}

/// A parsed BER-TLV object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The tag, with its bytes packed big-endian into a `u32`.
    pub tag: u32,
    /// The value field.
    pub value: &'a [u8],
}

/// Parse the tag and length at the start of `data`.
///
/// The value itself need not be present, so this works on a partially read file.
pub fn parse_header(data: &[u8]) -> Result<Header> {
    let mut pos = 0;
    let first = *data.first().ok_or_else(|| malformed("empty TLV"))?;
    pos += 1;

    let mut tag = u32::from(first);
    if first & 0x1F == 0x1F {
        // Multi-byte tag: subsequent bytes carry a continuation flag in bit 8.
        loop {
            let byte = *data
                .get(pos)
                .ok_or_else(|| malformed("truncated TLV tag"))?;
            pos += 1;
            if pos > 4 {
                return Err(malformed("TLV tag longer than 4 bytes"));
            }
            tag = (tag << 8) | u32::from(byte);
            if byte & 0x80 == 0 {
                break;
            }
        }
    }

    let first_len = *data
        .get(pos)
        .ok_or_else(|| malformed("truncated TLV length"))?;
    pos += 1;
    let length = if first_len < 0x80 {
        usize::from(first_len)
    } else {
        let count = usize::from(first_len & 0x7F);
        if count == 0 {
            return Err(malformed("indefinite TLV length is not supported"));
        }
        if count > size_of::<usize>() {
            return Err(malformed("TLV length does not fit in usize"));
        }
        let bytes = data
            .get(pos..pos + count)
            .ok_or_else(|| malformed("truncated TLV length"))?;
        pos += count;
        bytes
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
    };

    Ok(Header {
        tag,
        length,
        header_len: pos,
    })
}

/// Parse the first complete TLV object in `data`.
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

/// Iterate over the TLV objects concatenated in `data`.
///
/// Iteration stops at the first filler byte (`0x00` or `0xFF`), which is how the card pads the
/// unused tail of an elementary file.
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
            None | Some(0x00) | Some(0xFF) => return None,
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

fn malformed(what: &str) -> Error {
    Error::Malformed(what.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_byte_tag_and_length() {
        let header = parse_header(&[0x30, 0x03, 0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(
            header,
            Header {
                tag: 0x30,
                length: 3,
                header_len: 2
            }
        );
        assert_eq!(header.total_len(), 5);
    }

    #[test]
    fn parses_multi_byte_tag() {
        let header = parse_header(&[0xFF, 0x21, 0x02, 0x01, 0x02]).unwrap();
        assert_eq!(
            header,
            Header {
                tag: 0xFF21,
                length: 2,
                header_len: 3
            }
        );
    }

    #[test]
    fn parses_long_form_length() {
        // A 2048-bit certificate is the reason this matters: 0x82 introduces a 2-byte length.
        let header = parse_header(&[0x30, 0x82, 0x04, 0x11]).unwrap();
        assert_eq!(
            header,
            Header {
                tag: 0x30,
                length: 0x0411,
                header_len: 4
            }
        );
        assert_eq!(header.total_len(), 0x0415);
    }

    #[test]
    fn rejects_truncated_and_indefinite_lengths() {
        assert!(parse_header(&[0x30]).is_err());
        assert!(parse_header(&[0x30, 0x82, 0x04]).is_err());
        assert!(parse_header(&[0x30, 0x80]).is_err());
        assert!(parse_header(&[]).is_err());
    }

    #[test]
    fn parse_requires_the_whole_value() {
        assert!(parse(&[0x30, 0x03, 0xAA]).is_err());
        assert_eq!(
            parse(&[0x30, 0x02, 0xAA, 0xBB]).unwrap().value,
            [0xAA, 0xBB]
        );
    }

    #[test]
    fn iterates_until_filler() {
        let data = [0x30, 0x01, 0x0A, 0x31, 0x02, 0x0B, 0x0C, 0xFF, 0xFF];
        let items: Vec<_> = iter(&data).map(|t| t.unwrap()).collect();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0],
            Tlv {
                tag: 0x30,
                value: &[0x0A]
            }
        );
        assert_eq!(
            items[1],
            Tlv {
                tag: 0x31,
                value: &[0x0B, 0x0C]
            }
        );
    }
}
