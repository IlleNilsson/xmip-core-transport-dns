#![forbid(unsafe_code)]

//! Streams that travel as DNS dynamic updates. One UPDATE is one Stream: the
//! TXT record it adds carries the bytes, and the zone and owner name it
//! writes them under are the address.
//!
//! DNS is the one protocol every network already lets through, which is why
//! integrations end up riding it: service records that announce an endpoint,
//! TXT records that carry a token or a small document, a zone a partner
//! updates instead of a drop box. A Send Location sends an RFC 2136 UPDATE
//! adding a TXT record to a zone; a Receive Location binds as the server
//! that zone's updates reach, takes each update's TXT payload as a Stream,
//! and answers NOERROR. A QUERY that reaches a Receive Location is answered
//! NOTIMP and skipped — serving names is a resolver's business.
//!
//! Over UDP with EDNS a message is at most [`UDP_EDNS`] bytes; over TCP,
//! RFC 1035 section 4.2.2, [`MAX_MESSAGE`]. A larger Stream is refused, and
//! says so. TSIG, the signature that makes an update trustworthy, is
//! identity and joins with the identification gate (ADR-0019).
//!
//! The origin URI carries what the header knew:
//! `dns://peer/probe.xmip.example.?zone=xmip.example.&id=4660`.

pub mod message;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

pub use message::{MAX_MESSAGE, Message, UDP_EDNS};
use transport::error::{Result, classify, protocol_error};
use transport::socket;
use transport::{Arrived, Directions, Transport};

/// UDP datagrams with EDNS, or TCP with a length prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    Udp,
    Tcp,
}

pub struct DnsTransport {
    bind: String,
    zone: String,
    name: String,
    carrier: Carrier,
    timeout: Option<Duration>,
    next_id: AtomicU16,
}

impl DnsTransport {
    /// Listen at `bind`, `0.0.0.0:53` being the standard port, for updates
    /// to `zone`; send updates adding `name` in it.
    #[must_use]
    pub fn new(bind: impl Into<String>, zone: &str, name: &str) -> Self {
        Self {
            bind: bind.into(),
            zone: zone.to_string(),
            name: name.to_string(),
            carrier: Carrier::Udp,
            timeout: None,
            next_id: AtomicU16::new(1),
        }
    }

    /// Over TCP rather than UDP.
    #[must_use]
    pub const fn over(mut self, carrier: Carrier) -> Self {
        self.carrier = carrier;
        self
    }

    /// Give up waiting for an update or an answer after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Bind the UDP socket and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind_udp(&self) -> Result<(UdpSocket, String)> {
        socket::bind_udp(&self.bind, self.timeout)
    }

    /// Bind the TCP listener and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind_tcp(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.bind)
    }

    /// Take one update from an already-bound UDP socket and answer it. A
    /// query is answered NOTIMP and skipped.
    ///
    /// # Errors
    /// Where nothing arrived in time, or what arrived is not DNS.
    pub fn receive_datagram(&self, socket: &UdpSocket) -> Result<Arrived> {
        let mut buffer = vec![0u8; UDP_EDNS];
        loop {
            let (read, peer) = socket
                .recv_from(&mut buffer)
                .map_err(|e| classify("receiving a datagram", &e))?;
            let message = message::decode(&buffer[..read])?;
            let (rcode, arrived) = self.judge(peer, &message);
            let answer = message::encode(&message.response(rcode))?;
            socket
                .send_to(&answer, peer)
                .map_err(|e| classify("answering", &e))?;
            if let Some(arrived) = arrived {
                return Ok(arrived);
            }
        }
    }

    /// Accept one TCP peer on an already-bound listener, take its update
    /// and answer it.
    ///
    /// # Errors
    /// Where the connection could not be accepted, or what came is not DNS.
    pub fn receive_connection(&self, listener: &TcpListener) -> Result<Arrived> {
        let (mut stream, peer) = listener
            .accept()
            .map_err(|e| classify("accepting a connection", &e))?;
        if let Some(timeout) = self.timeout {
            stream
                .set_read_timeout(Some(timeout))
                .map_err(|e| classify("setting the read timeout", &e))?;
        }
        loop {
            let message = read_framed(&mut stream)?;
            let (rcode, arrived) = self.judge(peer, &message);
            write_framed(&mut stream, &message::encode(&message.response(rcode))?)?;
            if let Some(arrived) = arrived {
                return Ok(arrived);
            }
        }
    }

    /// The rcode `message` earns, and the Stream it carries where it is an
    /// update to this zone.
    fn judge(&self, peer: SocketAddr, message: &Message) -> (u16, Option<Arrived>) {
        if message.opcode() != message::OPCODE_UPDATE {
            return (message::RCODE_NOTIMP, None);
        }
        let zone = message.questions.first().map_or("", |q| q.name.as_str());
        if !self.zone.is_empty() && !zone.eq_ignore_ascii_case(&self.zone) {
            return (message::RCODE_REFUSED, None);
        }
        let name = message.authority.first().map_or("", |r| r.name.as_str());
        let origin = format!("dns://{peer}/{name}?zone={zone}&id={}", message.id);
        (
            message::RCODE_NOERROR,
            Some(Arrived::new(origin, message.txt_payload())),
        )
    }

    /// Send an update adding a TXT record carrying `payload` to the server at
    /// `target`: `dns://host:53/name?zone=zone.`, or `host:port` with the
    /// configured zone and name. The server's response, checked NOERROR.
    ///
    /// # Errors
    /// A payload the carrier cannot frame, a server that did not answer, or
    /// an rcode that is not NOERROR — REFUSED is permanent, SERVFAIL retryable.
    pub fn update(&self, target: &str, payload: &[u8]) -> Result<Message> {
        let (address, name, zone) = self.resolve(target);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut update = Message::update_adding_txt(id, zone, name, payload);
        let response = match self.carrier {
            Carrier::Udp => {
                update = update.with_edns();
                let bytes = message::encode(&update)?;
                if bytes.len() > UDP_EDNS {
                    return Err(protocol_error(
                        "an update over what a UDP datagram carries; use TCP",
                    ));
                }
                let socket = UdpSocket::bind("0.0.0.0:0")
                    .map_err(|e| classify("binding the sending socket", &e))?;
                socket
                    .set_read_timeout(self.timeout)
                    .map_err(|e| classify("setting the answer timeout", &e))?;
                socket
                    .send_to(&bytes, address)
                    .map_err(|e| classify("sending the update", &e))?;
                let mut buffer = vec![0u8; UDP_EDNS];
                let read = socket
                    .recv(&mut buffer)
                    .map_err(|e| classify("awaiting the answer", &e))?;
                message::decode(&buffer[..read])?
            }
            Carrier::Tcp => {
                let bytes = message::encode(&update)?;
                let mut stream = TcpStream::connect(address)
                    .map_err(|e| classify("connecting to the server", &e))?;
                stream
                    .set_read_timeout(self.timeout)
                    .map_err(|e| classify("setting the answer timeout", &e))?;
                write_framed(&mut stream, &bytes)?;
                read_framed(&mut stream)?
            }
        };
        if response.id != id {
            return Err(protocol_error("an answer to another message"));
        }
        match response.rcode() {
            message::RCODE_NOERROR => Ok(response),
            message::RCODE_SERVFAIL => Err(transport::TransportError::retryable(
                "the server answered SERVFAIL",
            )),
            other => Err(protocol_error(format!("the server answered rcode {other}"))),
        }
    }

    fn resolve<'a>(&'a self, target: &'a str) -> (&'a str, &'a str, &'a str) {
        let Some(rest) = target.strip_prefix("dns://") else {
            return (target, &self.name, &self.zone);
        };
        let (address, rest) = rest.split_once('/').unwrap_or((rest, ""));
        let (name, query) = rest.split_once('?').unwrap_or((rest, ""));
        let zone = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("zone="))
            .unwrap_or(&self.zone);
        let name = if name.is_empty() { &self.name } else { name };
        (address, name, zone)
    }
}

/// One message with its two-byte length before it, RFC 1035 section 4.2.2.
fn read_framed(stream: &mut TcpStream) -> Result<Message> {
    let mut length = [0u8; 2];
    stream
        .read_exact(&mut length)
        .map_err(|e| classify("reading the length", &e))?;
    let mut bytes = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream
        .read_exact(&mut bytes)
        .map_err(|e| classify("reading the message", &e))?;
    message::decode(&bytes)
}

fn write_framed(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    let length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    stream
        .write_all(&length.to_be_bytes())
        .map_err(|e| classify("writing the length", &e))?;
    stream
        .write_all(bytes)
        .map_err(|e| classify("writing the message", &e))?;
    stream
        .flush()
        .map_err(|e| classify("flushing the message", &e))
}

impl Transport for DnsTransport {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn receive(&self) -> Result<Vec<Arrived>> {
        match self.carrier {
            Carrier::Udp => {
                let (socket, _) = self.bind_udp()?;
                Ok(vec![self.receive_datagram(&socket)?])
            }
            Carrier::Tcp => {
                let (listener, _) = self.bind_tcp()?;
                Ok(vec![self.receive_connection(&listener)?])
            }
        }
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        self.update(target, bytes).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> DnsTransport {
        DnsTransport::new("127.0.0.1:0", "xmip.example.", "probe.xmip.example.")
            .timing_out_after(Duration::from_secs(2))
    }

    #[test]
    fn an_update_over_udp_carries_the_payload_and_is_answered() {
        let far_end = node();
        let (socket, address) = far_end.bind_udp().expect("binding");
        let payload: Vec<u8> = (0..3000)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();
        let sent = payload.clone();
        let sender = std::thread::spawn(move || {
            let near = node();
            near.send(
                &format!("dns://{address}/order.xmip.example.?zone=xmip.example."),
                &sent,
            )?;
            near.send(&address, b"")
        });
        let arrived = far_end.receive_datagram(&socket).expect("receiving");
        assert_eq!(arrived.bytes, payload);
        assert!(
            arrived
                .origin_uri
                .contains("/order.xmip.example.?zone=xmip.example.&id=")
        );
        let empty = far_end.receive_datagram(&socket).expect("receiving");
        assert!(empty.bytes.is_empty());
        assert!(empty.origin_uri.contains("/probe.xmip.example.?"));
        sender.join().expect("thread").expect("sending");
    }

    #[test]
    fn an_update_over_tcp_carries_more_and_a_query_is_not_implemented() {
        let far_end = node().over(Carrier::Tcp);
        let (listener, address) = far_end.bind_tcp().expect("binding");
        let payload = vec![0x2a; 40_000];
        let sent = payload.clone();
        let sender = std::thread::spawn(move || {
            let near = node().over(Carrier::Tcp);
            let query = Message {
                id: 9,
                flags: 0,
                questions: vec![message::Question {
                    name: "xmip.example.".into(),
                    kind: message::TYPE_TXT,
                    class: message::CLASS_IN,
                }],
                answers: Vec::new(),
                authority: Vec::new(),
                additional: Vec::new(),
            };
            let mut stream = TcpStream::connect(&address).expect("connecting");
            write_framed(&mut stream, &message::encode(&query).expect("encode")).expect("query");
            let answer = read_framed(&mut stream).expect("answer");
            assert_eq!(answer.rcode(), message::RCODE_NOTIMP);
            let update = Message::update_adding_txt(10, "xmip.example.", "n.", &sent);
            write_framed(&mut stream, &message::encode(&update).expect("encode")).expect("update");
            let answer = read_framed(&mut stream).expect("answer");
            assert_eq!(answer.rcode(), message::RCODE_NOERROR);
            drop(stream);
            near.send(&address, &vec![0; UDP_EDNS])
        });
        let arrived = far_end.receive_connection(&listener).expect("receiving");
        assert_eq!(arrived.bytes, payload);
        let second = far_end.receive_connection(&listener).expect("second");
        assert_eq!(second.bytes.len(), UDP_EDNS);
        sender.join().expect("thread").expect("sending");
    }

    #[test]
    fn the_wrong_zone_is_refused_and_too_much_does_not_fit() {
        let far_end = node();
        let (socket, address) = far_end.bind_udp().expect("binding");
        let sender = std::thread::spawn(move || {
            node().send(&format!("dns://{address}/n.?zone=other.example."), b"x")
        });
        let error = far_end
            .receive_datagram(&socket)
            .expect_err("refused, then timeout");
        assert!(error.retryable, "the timeout after the refusal: {error}");
        let refused = sender.join().expect("thread").expect_err("refused");
        assert!(!refused.retryable);
        assert!(refused.message.contains("rcode 5"));
        let too_big = node()
            .send("127.0.0.1:1", &vec![0; UDP_EDNS])
            .expect_err("too big for UDP");
        assert!(!too_big.retryable);
        let too_big = node()
            .over(Carrier::Tcp)
            .send("127.0.0.1:1", &vec![0; MAX_MESSAGE])
            .expect_err("too big at all");
        assert!(!too_big.retryable);
        assert!(node().claims().is_none());
    }
}
