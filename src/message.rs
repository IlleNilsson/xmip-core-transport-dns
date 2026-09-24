//! RFC 1035 section 4: the header, questions and resource records — and
//! the RFC 2136 UPDATE that reuses the four sections as zone, prerequisite,
//! update and additional. The one DNS message codec in the estate: mdns
//! speaks RFC 6762, which is this wire format with two bits repurposed, and
//! reads and writes its messages here. A name's label-and-pointer form is
//! the capability's (ADR-0044); a record and what it carries are
//! [`crate::record`]'s.

use transport::error::{Result, protocol_error};
use transport::label::{read_name, write_name};

use crate::record::{
    CLASS_IN, Record, RecordData, TYPE_OPT, TYPE_SOA, TYPE_TXT, field16, rdata, read_record,
};

/// The largest message a UDP datagram carries without EDNS.
pub const UDP_CLASSIC: usize = 512;
/// The payload size this transport advertises in its OPT record.
pub const UDP_EDNS: usize = 4096;
/// The largest message at all: what a TCP length prefix can say.
pub const MAX_MESSAGE: usize = 65_535;

/// The header's QR bit: this is a response.
pub const FLAG_RESPONSE: u16 = 0x8000;
/// The header's AA bit: the answer is authoritative.
pub const FLAG_AUTHORITATIVE: u16 = 0x0400;
pub const OPCODE_QUERY: u16 = 0;
pub const OPCODE_UPDATE: u16 = 5;
pub const RCODE_NOERROR: u16 = 0;
pub const RCODE_FORMERR: u16 = 1;
pub const RCODE_SERVFAIL: u16 = 2;
pub const RCODE_NOTIMP: u16 = 4;
pub const RCODE_REFUSED: u16 = 5;

/// A character string's most bytes, RFC 1035 section 3.3.
const STRING: usize = 255;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub kind: u16,
    /// `CLASS_IN`, with [`BIT_UNICAST`](crate::record::BIT_UNICAST) where
    /// mDNS asks a unicast answer.
    pub class: u16,
}

/// One message, its four sections by their RFC 1035 names. An UPDATE reads
/// them as zone, prerequisite, update and additional.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

impl Message {
    /// A query for `kind` records at `name`, id 0 as mDNS queries carry;
    /// a unicast resolver sets its own.
    #[must_use]
    pub fn query(name: &str, kind: u16) -> Self {
        Self {
            questions: vec![Question {
                name: name.to_string(),
                kind,
                class: CLASS_IN,
            }],
            ..Self::default()
        }
    }

    /// An authoritative response carrying `answers` — unsolicited, an mDNS
    /// announcement, when `id` is 0.
    #[must_use]
    pub fn authoritative(id: u16, answers: Vec<Record>) -> Self {
        Self {
            id,
            flags: FLAG_RESPONSE | FLAG_AUTHORITATIVE,
            answers,
            ..Self::default()
        }
    }

    /// An UPDATE adding one TXT record `name` in `zone` carrying `payload`,
    /// split into the 255-byte character strings TXT is made of.
    #[must_use]
    pub fn update_adding_txt(id: u16, zone: &str, name: &str, payload: &[u8]) -> Self {
        let mut strings: Vec<Vec<u8>> = payload.chunks(STRING).map(<[u8]>::to_vec).collect();
        if strings.is_empty() {
            strings.push(Vec::new());
        }
        Self {
            id,
            flags: OPCODE_UPDATE << 11,
            questions: vec![Question {
                name: zone.to_string(),
                kind: TYPE_SOA,
                class: CLASS_IN,
            }],
            authority: vec![Record {
                name: name.to_string(),
                kind: TYPE_TXT,
                class: CLASS_IN,
                ttl: 0,
                data: RecordData::Txt(strings),
            }],
            ..Self::default()
        }
    }

    /// The opcode, bits 11 to 14 of the flags.
    #[must_use]
    pub const fn opcode(&self) -> u16 {
        (self.flags >> 11) & 0x0f
    }

    /// Whether this is a response, bit 15.
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags & FLAG_RESPONSE != 0
    }

    /// The response code, the low four bits.
    #[must_use]
    pub const fn rcode(&self) -> u16 {
        self.flags & 0x0f
    }

    /// Every record in every section, in order.
    pub fn records(&self) -> impl Iterator<Item = &Record> + Clone {
        self.answers
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
    }

    /// The payload the TXT records of the update section carry, their
    /// character strings concatenated in order.
    #[must_use]
    pub fn txt_payload(&self) -> Vec<u8> {
        self.authority
            .iter()
            .filter_map(|record| match &record.data {
                RecordData::Txt(strings) => Some(strings),
                _ => None,
            })
            .flatten()
            .flatten()
            .copied()
            .collect()
    }

    /// The response to `self`: same id, opcode and question, `rcode` set.
    #[must_use]
    pub fn response(&self, rcode: u16) -> Self {
        Self {
            id: self.id,
            flags: FLAG_RESPONSE | (self.flags & 0x7800) | (rcode & 0x0f),
            questions: self.questions.clone(),
            ..Self::default()
        }
    }

    /// Say in the additional section that this side takes [`UDP_EDNS`]
    /// bytes over UDP, RFC 6891.
    #[must_use]
    pub fn with_edns(mut self) -> Self {
        self.additional.push(Record {
            name: String::new(),
            kind: TYPE_OPT,
            class: u16::try_from(UDP_EDNS).unwrap_or(u16::MAX),
            ttl: 0,
            data: RecordData::Other(Vec::new()),
        });
        self
    }
}

/// Encode `message`. Names are written whole; compression is read but not
/// written, which every resolver accepts.
///
/// # Errors
/// A label over 63 bytes, a name over 255, a TXT string over 255, rdata
/// over 65535, or a message over [`MAX_MESSAGE`].
pub fn encode(message: &Message) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for value in [message.id, message.flags] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    for section in [
        message.questions.len(),
        message.answers.len(),
        message.authority.len(),
        message.additional.len(),
    ] {
        let count = u16::try_from(section).map_err(|_| protocol_error("a section too long"))?;
        out.extend_from_slice(&count.to_be_bytes());
    }
    for question in &message.questions {
        write_name(&mut out, &question.name)?;
        out.extend_from_slice(&question.kind.to_be_bytes());
        out.extend_from_slice(&question.class.to_be_bytes());
    }
    for record in message.records() {
        write_name(&mut out, &record.name)?;
        out.extend_from_slice(&record.kind.to_be_bytes());
        out.extend_from_slice(&record.class.to_be_bytes());
        out.extend_from_slice(&record.ttl.to_be_bytes());
        let rdata = rdata(&record.data)?;
        let length = u16::try_from(rdata.len())
            .map_err(|_| protocol_error("rdata over what a record carries"))?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    if out.len() > MAX_MESSAGE {
        return Err(protocol_error("a message over what DNS can frame"));
    }
    Ok(out)
}

/// Decode one message.
///
/// # Errors
/// Shorter than its header, a section shorter than its count, a
/// compression pointer that loops or points forward, a label over 63, or
/// class IN rdata of a known type that is not shaped as that type.
pub fn decode(bytes: &[u8]) -> Result<Message> {
    if bytes.len() < 12 {
        return Err(protocol_error("a message shorter than its header"));
    }
    let counts = [
        field16(bytes, 4)?,
        field16(bytes, 6)?,
        field16(bytes, 8)?,
        field16(bytes, 10)?,
    ];
    let mut at = 12;
    let mut questions = Vec::new();
    for _ in 0..counts[0] {
        let (text, next) = read_name(bytes, at)?;
        questions.push(Question {
            name: text,
            kind: field16(bytes, next)?,
            class: field16(bytes, next + 2)?,
        });
        at = next + 4;
    }
    let mut sections: [Vec<Record>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for (section, count) in sections.iter_mut().zip(&counts[1..]) {
        for _ in 0..*count {
            let (record, next) = read_record(bytes, at)?;
            section.push(record);
            at = next;
        }
    }
    let [answers, authority, additional] = sections;
    Ok(Message {
        id: field16(bytes, 0)?,
        flags: field16(bytes, 2)?,
        questions,
        answers,
        authority,
        additional,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{BIT_UNICAST, CLASS_ANY, TYPE_A, TYPE_AAAA, TYPE_PTR, TYPE_SRV};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn record(name: &str, kind: u16, data: RecordData) -> Record {
        Record {
            name: name.to_string(),
            kind,
            class: CLASS_IN | BIT_UNICAST,
            ttl: 120,
            data,
        }
    }

    #[test]
    fn an_update_round_trips_and_its_payload_reads_back() {
        let payload: Vec<u8> = (0..600)
            .map(|i| u8::try_from(i % 256).unwrap_or(0))
            .collect();
        let update =
            Message::update_adding_txt(0x1234, "xmip.example.", "probe.", &payload).with_edns();
        let bytes = encode(&update).expect("encode");
        let back = decode(&bytes).expect("decode");
        assert_eq!(back, update);
        assert_eq!(back.opcode(), OPCODE_UPDATE);
        assert!(!back.is_response());
        assert_eq!(back.txt_payload(), payload);
        assert_eq!(back.questions[0].name, "xmip.example.");
        let RecordData::Txt(strings) = &back.authority[0].data else {
            panic!("a TXT record");
        };
        assert_eq!(
            strings.iter().map(Vec::len).collect::<Vec<_>>(),
            [255, 255, 90]
        );
        let empty = Message::update_adding_txt(1, "z.", "n.", &[]);
        let back = decode(&encode(&empty).expect("encode")).expect("decode");
        assert_eq!(back, empty, "one empty string, as RFC 6763 6.1 writes it");
        assert!(back.txt_payload().is_empty());
        let response = update.response(RCODE_REFUSED);
        assert!(response.is_response());
        assert_eq!(response.rcode(), RCODE_REFUSED);
        assert_eq!(response.opcode(), OPCODE_UPDATE);
        assert_eq!(response.id, 0x1234);
    }

    #[test]
    fn a_service_response_round_trips() {
        let response = Message::authoritative(
            0,
            vec![
                record(
                    "_ipp._tcp.local.",
                    TYPE_PTR,
                    RecordData::Ptr("Printer._ipp._tcp.local.".into()),
                ),
                record(
                    "Printer._ipp._tcp.local.",
                    TYPE_SRV,
                    RecordData::Srv {
                        priority: 0,
                        weight: 0,
                        port: 631,
                        target: "printer.local.".into(),
                    },
                ),
                record(
                    "Printer._ipp._tcp.local.",
                    TYPE_TXT,
                    RecordData::Txt(vec![b"txtvers=1".to_vec(), Vec::new(), vec![0xff]]),
                ),
                record(
                    "printer.local.",
                    TYPE_A,
                    RecordData::A(Ipv4Addr::new(10, 0, 0, 5)),
                ),
                record(
                    "printer.local.",
                    TYPE_AAAA,
                    RecordData::Aaaa(Ipv6Addr::LOCALHOST),
                ),
                record("printer.local.", 47, RecordData::Other(vec![1, 2, 3])),
            ],
        );
        let back = decode(&encode(&response).expect("encode")).expect("decode");
        assert_eq!(back, response, "every string kept, the empty one and bytes");
        assert!(back.is_response());
        assert_eq!(back.records().count(), 6);
        let query = Message::query("_ipp._tcp.local.", TYPE_PTR);
        let back = decode(&encode(&query).expect("encode")).expect("decode");
        assert_eq!(back, query);
        assert!(!back.is_response());
    }

    #[test]
    fn rdata_outside_class_in_keeps_its_bytes() {
        // RFC 2136 2.5.2: delete an RRset — class ANY, type A, no rdata.
        let mut update = Message::update_adding_txt(1, "z.", "n.", b"x");
        update.authority.push(Record {
            name: "n.".into(),
            kind: TYPE_A,
            class: CLASS_ANY,
            ttl: 0,
            data: RecordData::Other(Vec::new()),
        });
        let back = decode(&encode(&update).expect("encode")).expect("decode");
        assert_eq!(back, update);
        assert_eq!(back.txt_payload(), b"x");
    }

    #[test]
    fn compression_is_followed_in_names_and_rdata_and_bad_shapes_refused() {
        // A question for a.b., a PTR answer whose name and target point at it.
        let mut bytes = vec![0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        bytes.extend_from_slice(&[1, b'a', 1, b'b', 0, 0, 12, 0, 1]);
        bytes.extend_from_slice(&[0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 5, 0, 4, 1, b'x', 0xc0, 12]);
        let message = decode(&bytes).expect("decode");
        assert_eq!(message.answers[0].name, "a.b.");
        assert_eq!(message.answers[0].ttl, 5);
        assert_eq!(message.answers[0].data, RecordData::Ptr("x.a.b.".into()));
        let mut looping = bytes.clone();
        looping[21] = 21; // points at itself
        assert!(decode(&looping).is_err(), "pointer at itself");
        assert!(decode(&bytes[..11]).is_err(), "short header");
        assert!(decode(&bytes[..25]).is_err(), "short section");
        let short_a =
            Message::authoritative(0, vec![record("n.", TYPE_A, RecordData::Other(vec![1]))]);
        assert!(
            decode(&encode(&short_a).expect("encode")).is_err(),
            "A of one byte"
        );
        // A TXT string cut short was read as far as it went until 2026-09-24.
        let bad_txt = Message::authoritative(
            0,
            vec![record("n.", TYPE_TXT, RecordData::Other(vec![5, b'a']))],
        );
        assert!(
            decode(&encode(&bad_txt).expect("encode")).is_err(),
            "TXT string cut"
        );
        let long_label = "x".repeat(64);
        assert!(encode(&Message::query(&long_label, TYPE_PTR)).is_err());
        let long_txt = RecordData::Txt(vec![vec![b'y'; 256]]);
        assert!(
            encode(&Message::authoritative(
                0,
                vec![record("n.", TYPE_TXT, long_txt)]
            ))
            .is_err()
        );
        let too_big = Message::update_adding_txt(1, "z.", "n", &vec![0; 70_000]);
        assert!(encode(&too_big).is_err());
    }
}
