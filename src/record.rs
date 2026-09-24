//! A resource record, RFC 1035 section 3.2, and what it carries by type —
//! PTR, SRV, TXT, A and AAAA, the types DNS-SD is made of and a dynamic
//! update carries — written and read inside a message, where a name in
//! rdata may point back into the message before it.

use std::net::{Ipv4Addr, Ipv6Addr};

use transport::error::{Result, protocol_error};
use transport::label::{read_name, write_name};

pub const TYPE_A: u16 = 1;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_ANY: u16 = 255;
pub const CLASS_IN: u16 = 1;
pub const CLASS_ANY: u16 = 255;
/// The top bit of a class: RFC 6762's QU bit on a question, its
/// cache-flush bit on a record. Unicast DNS assigns no class there, so a
/// record's rdata is read by its type whether the bit is set or not.
pub const BIT_UNICAST: u16 = 0x8000;

/// What a record carries, by type. Read by type only in class IN, where
/// RFC 1035 defines these shapes; any other class — the ANY and NONE of
/// an RFC 2136 update, the payload size of an OPT — keeps its rdata as it
/// came.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordData {
    Ptr(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// The character strings, each at most 255 bytes, every one kept: a
    /// record of one empty string is the empty TXT RFC 6763 section 6.1
    /// asks for, a record of none is the empty rdata of an update.
    Txt(Vec<Vec<u8>>),
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// Any other type or class, as it came.
    Other(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub kind: u16,
    /// `CLASS_IN`, with [`BIT_UNICAST`] where an mDNS record replaces the
    /// cache.
    pub class: u16,
    pub ttl: u32,
    pub data: RecordData,
}

/// The rdata `data` is written as.
///
/// # Errors
/// A name too long, or a TXT string over 255 bytes.
pub(crate) fn rdata(data: &RecordData) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match data {
        RecordData::Ptr(target) => write_name(&mut out, target)?,
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            for value in [priority, weight, port] {
                out.extend_from_slice(&value.to_be_bytes());
            }
            write_name(&mut out, target)?;
        }
        RecordData::Txt(strings) => {
            for string in strings {
                let length = u8::try_from(string.len())
                    .map_err(|_| protocol_error("a TXT string over 255 bytes"))?;
                out.push(length);
                out.extend_from_slice(string);
            }
        }
        RecordData::A(address) => out.extend_from_slice(&address.octets()),
        RecordData::Aaaa(address) => out.extend_from_slice(&address.octets()),
        RecordData::Other(bytes) => out.extend_from_slice(bytes),
    }
    Ok(out)
}

/// One record at `at`, and where the next begins.
///
/// # Errors
/// A record shorter than its fields, or class IN rdata of a known type
/// not shaped as that type.
pub(crate) fn read_record(bytes: &[u8], at: usize) -> Result<(Record, usize)> {
    let (text, next) = read_name(bytes, at)?;
    let kind = field16(bytes, next)?;
    let class = field16(bytes, next + 2)?;
    let ttl = u32::from(field16(bytes, next + 4)?) << 16 | u32::from(field16(bytes, next + 6)?);
    let length = usize::from(field16(bytes, next + 8)?);
    let start = next + 10;
    let raw = bytes.get(start..start + length).ok_or_else(short)?;
    let data = if class & !BIT_UNICAST == CLASS_IN {
        read_data(bytes, start, raw, kind)?
    } else {
        RecordData::Other(raw.to_vec())
    };
    Ok((
        Record {
            name: text,
            kind,
            class,
            ttl,
            data,
        },
        start + length,
    ))
}

/// The rdata `raw`, at `start` in `bytes`, read as `kind` — whole
/// message at hand, since a name in rdata may point back into it.
fn read_data(bytes: &[u8], start: usize, raw: &[u8], kind: u16) -> Result<RecordData> {
    Ok(match kind {
        TYPE_PTR => RecordData::Ptr(read_name(bytes, start)?.0),
        TYPE_SRV => RecordData::Srv {
            priority: field16(raw, 0)?,
            weight: field16(raw, 2)?,
            port: field16(raw, 4)?,
            target: read_name(bytes, start + 6)?.0,
        },
        TYPE_TXT => RecordData::Txt(read_strings(raw)?),
        TYPE_A => {
            let octets: [u8; 4] = raw
                .try_into()
                .map_err(|_| protocol_error("an A record that is not four bytes"))?;
            RecordData::A(Ipv4Addr::from(octets))
        }
        TYPE_AAAA => {
            let octets: [u8; 16] = raw
                .try_into()
                .map_err(|_| protocol_error("an AAAA record that is not sixteen bytes"))?;
            RecordData::Aaaa(Ipv6Addr::from(octets))
        }
        _ => RecordData::Other(raw.to_vec()),
    })
}

fn read_strings(raw: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut strings = Vec::new();
    let mut at = 0;
    while at < raw.len() {
        let length = usize::from(raw[at]);
        let string = raw
            .get(at + 1..at + 1 + length)
            .ok_or_else(|| protocol_error("a TXT string shorter than its length"))?;
        strings.push(string.to_vec());
        at += 1 + length;
    }
    Ok(strings)
}

pub(crate) fn short() -> transport::TransportError {
    protocol_error("a section shorter than its count")
}

pub(crate) fn field16(bytes: &[u8], at: usize) -> Result<u16> {
    let pair = bytes.get(at..at + 2).ok_or_else(short)?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}
