//! RFC 1035 section 4: the header, questions and resource records — and
//! the RFC 2136 UPDATE that reuses the four sections as zone, prerequisite,
//! update and additional. A name's label-and-pointer form is the
//! capability's, shared with mdns (ADR-0044).

use transport::error::{Result, protocol_error};
use transport::label::{read_name, write_name};

/// The largest message a UDP datagram carries without EDNS.
pub const UDP_CLASSIC: usize = 512;
/// The payload size this transport advertises in its OPT record.
pub const UDP_EDNS: usize = 4096;
/// The largest message at all: what a TCP length prefix can say.
pub const MAX_MESSAGE: usize = 65_535;

pub const TYPE_SOA: u16 = 6;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_ANY: u16 = 255;
pub const CLASS_IN: u16 = 1;
pub const CLASS_ANY: u16 = 255;

pub const OPCODE_QUERY: u16 = 0;
pub const OPCODE_UPDATE: u16 = 5;
pub const RCODE_NOERROR: u16 = 0;
pub const RCODE_FORMERR: u16 = 1;
pub const RCODE_SERVFAIL: u16 = 2;
pub const RCODE_NOTIMP: u16 = 4;
pub const RCODE_REFUSED: u16 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub kind: u16,
    pub class: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub kind: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// One message, its four sections by their RFC 1035 names. An UPDATE reads
/// them as zone, prerequisite, update and additional.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

impl Message {
    /// An UPDATE adding one TXT record `name` in `zone` carrying `payload`,
    /// split into the 255-byte character strings TXT is made of.
    #[must_use]
    pub fn update_adding_txt(id: u16, zone: &str, name: &str, payload: &[u8]) -> Self {
        let mut rdata = Vec::with_capacity(payload.len() + payload.len() / 255 + 1);
        for chunk in payload.chunks(255) {
            rdata.push(u8::try_from(chunk.len()).unwrap_or(255));
            rdata.extend_from_slice(chunk);
        }
        if payload.is_empty() {
            rdata.push(0);
        }
        Self {
            id,
            flags: OPCODE_UPDATE << 11,
            questions: vec![Question {
                name: zone.to_string(),
                kind: TYPE_SOA,
                class: CLASS_IN,
            }],
            answers: Vec::new(),
            authority: vec![Record {
                name: name.to_string(),
                kind: TYPE_TXT,
                class: CLASS_IN,
                ttl: 0,
                rdata,
            }],
            additional: Vec::new(),
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
        self.flags & 0x8000 != 0
    }

    /// The response code, the low four bits.
    #[must_use]
    pub const fn rcode(&self) -> u16 {
        self.flags & 0x0f
    }

    /// The payload the TXT records of the update section carry, their
    /// character strings concatenated in order.
    #[must_use]
    pub fn txt_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for record in self.authority.iter().filter(|r| r.kind == TYPE_TXT) {
            let mut at = 0;
            while at < record.rdata.len() {
                let length = usize::from(record.rdata[at]);
                let end = (at + 1 + length).min(record.rdata.len());
                out.extend_from_slice(&record.rdata[at + 1..end]);
                at = end;
            }
        }
        out
    }

    /// The response to `self`: same id, opcode and question, `rcode` set.
    #[must_use]
    pub fn response(&self, rcode: u16) -> Self {
        Self {
            id: self.id,
            flags: 0x8000 | (self.flags & 0x7800) | (rcode & 0x0f),
            questions: self.questions.clone(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
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
            rdata: Vec::new(),
        });
        self
    }
}

/// Encode `message`. Names are written whole; compression is read but not
/// written, which every resolver accepts.
///
/// # Errors
/// A label over 63 bytes, a name over 255, rdata over 65535, or a message
/// over [`MAX_MESSAGE`].
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
    for record in [&message.answers, &message.authority, &message.additional]
        .into_iter()
        .flatten()
    {
        write_name(&mut out, &record.name)?;
        out.extend_from_slice(&record.kind.to_be_bytes());
        out.extend_from_slice(&record.class.to_be_bytes());
        out.extend_from_slice(&record.ttl.to_be_bytes());
        let length = u16::try_from(record.rdata.len())
            .map_err(|_| protocol_error("rdata over what a record carries"))?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&record.rdata);
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
/// compression pointer that loops or points forward, a label over 63.
pub fn decode(bytes: &[u8]) -> Result<Message> {
    if bytes.len() < 12 {
        return Err(protocol_error("a message shorter than its header"));
    }
    let u16_at = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    let counts = [u16_at(4), u16_at(6), u16_at(8), u16_at(10)];
    let mut at = 12;
    let mut questions = Vec::new();
    for _ in 0..counts[0] {
        let (text, next) = read_name(bytes, at)?;
        let kind = field16(bytes, next)?;
        let class = field16(bytes, next + 2)?;
        questions.push(Question {
            name: text,
            kind,
            class,
        });
        at = next + 4;
    }
    let mut sections: [Vec<Record>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for (section, count) in sections.iter_mut().zip(&counts[1..]) {
        for _ in 0..*count {
            let (text, next) = read_name(bytes, at)?;
            let kind = field16(bytes, next)?;
            let class = field16(bytes, next + 2)?;
            let ttl = u32::from_be_bytes([
                *bytes.get(next + 4).ok_or_else(short)?,
                *bytes.get(next + 5).ok_or_else(short)?,
                *bytes.get(next + 6).ok_or_else(short)?,
                *bytes.get(next + 7).ok_or_else(short)?,
            ]);
            let length = usize::from(field16(bytes, next + 8)?);
            let start = next + 10;
            let rdata = bytes.get(start..start + length).ok_or_else(short)?.to_vec();
            section.push(Record {
                name: text,
                kind,
                class,
                ttl,
                rdata,
            });
            at = start + length;
        }
    }
    let [answers, authority, additional] = sections;
    Ok(Message {
        id: u16_at(0),
        flags: u16_at(2),
        questions,
        answers,
        authority,
        additional,
    })
}

fn short() -> transport::TransportError {
    protocol_error("a section shorter than its count")
}

fn field16(bytes: &[u8], at: usize) -> Result<u16> {
    let pair = bytes.get(at..at + 2).ok_or_else(short)?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(back.authority[0].rdata.len(), 600 + 3);
        let empty = Message::update_adding_txt(1, "z.", "n", &[]);
        assert!(
            decode(&encode(&empty).expect("encode"))
                .expect("decode")
                .txt_payload()
                .is_empty()
        );
        let response = back.response(RCODE_REFUSED);
        assert!(response.is_response());
        assert_eq!(response.rcode(), RCODE_REFUSED);
        assert_eq!(response.opcode(), OPCODE_UPDATE);
        assert_eq!(response.id, 0x1234);
    }

    #[test]
    fn compression_pointers_are_followed_and_loops_refused() {
        // A query for a.b. then an answer whose name points back at it.
        let mut bytes = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        bytes.extend_from_slice(&[1, b'a', 1, b'b', 0, 0, 16, 0, 1]);
        bytes.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 5, 0, 3, 2, b'h', b'i']);
        let message = decode(&bytes).expect("decode");
        assert_eq!(message.answers[0].name, "a.b.");
        assert_eq!(message.answers[0].ttl, 5);
        assert_eq!(message.answers[0].rdata, [2, b'h', b'i']);
        let mut looping = bytes.clone();
        looping[21] = 21; // points at itself
        assert!(decode(&looping).is_err());
        assert!(decode(&bytes[..11]).is_err(), "short header");
        assert!(decode(&bytes[..20]).is_err(), "short section");
        let long_label = "x".repeat(64);
        assert!(encode(&Message::update_adding_txt(1, &long_label, "n", b"")).is_err());
        let too_big = Message::update_adding_txt(1, "z.", "n", &vec![0; 70_000]);
        assert!(encode(&too_big).is_err());
    }
}
