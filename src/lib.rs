#![forbid(unsafe_code)]

//! Streams that travel as DNS dynamic updates. One UPDATE is one Stream: the
//! TXT record it adds carries the bytes, and the zone and owner name it
//! writes them under are the address.
//!
//! DNS is the one protocol every network already lets through, which is why
//! integrations end up riding it: service records that announce an endpoint,
//! TXT records that carry a token or a small document, a zone a Party
//! updates instead of a drop box. A Send Location sends an RFC 2136 UPDATE
//! adding a TXT record to a zone; a Receive Location binds as the server
//! that zone's updates reach, takes each update's TXT payload as a Stream,
//! whole, and answers it after the whole receive cycle (`receiving.rs`):
//! NOERROR on accepted, REFUSED on refused, SERVFAIL on failed, so the
//! client sends it again.
//! A QUERY that reaches a Receive Location is answered NOTIMP and skipped —
//! serving names is a resolver's business — and an update to another zone
//! REFUSED, both at once.
//!
//! Over UDP with EDNS a message is at most [`UDP_EDNS`] bytes; over TCP,
//! RFC 1035 section 4.2.2, [`MAX_MESSAGE`]. A larger Stream is refused, and
//! says so. TSIG, the signature that makes an update trustworthy, is
//! identity and joins with the identification gate (ADR-0019).
//!
//! The origin URI carries what the header knew:
//! `dns://peer/probe.xmip.example.?zone=xmip.example.&id=4660`.
//!
//! **Built with its `declaration` feature alone** the crate is
//! [`declaration`].

#[cfg(feature = "declaration")]
pub mod declaration;
#[cfg(feature = "default")]
pub mod label;
#[cfg(feature = "default")]
pub mod loopback;
#[cfg(feature = "default")]
pub mod message;
#[cfg(feature = "default")]
pub mod receiving;
#[cfg(feature = "default")]
pub mod record;

#[cfg(feature = "default")]
use std::{
    io::{Read, Write},
    net::{TcpListener, UdpSocket},
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

#[cfg(feature = "default")]
pub use loopback::{datagram_ceiling, message_ceiling};
#[cfg(feature = "default")]
pub use message::{MAX_MESSAGE, Message, UDP_EDNS};
#[cfg(feature = "default")]
use net::Target;
#[cfg(feature = "default")]
pub use receiving::Client;
#[cfg(feature = "default")]
use transport::error::{Result, classify, protocol_error};
#[cfg(feature = "default")]
use transport::{
    Arrived, Configured, Directions, Transport, kept::Kept, sender::Sender, serving::Serving,
    socket,
};
#[cfg(feature = "default")]
use xcore::settings::Settings;

/// UDP datagrams with EDNS, or TCP with a length prefix.
#[cfg(feature = "default")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    Udp,
    Tcp,
}

#[cfg(feature = "default")]
pub struct DnsTransport {
    bind: String,
    zone: String,
    name: String,
    carrier: Carrier,
    timeout: Option<Duration>,
    next_id: AtomicU16,
    /// The socket every update over UDP leaves from, bound once.
    sender: Sender,
    /// What its open binds for the carrier, and every receive
    /// takes from: the datagram socket, or the listener and the clients'
    /// connections kept open on it between their updates.
    datagrams: Kept<UdpSocket>,
    connections: Serving<Client>,
}

#[cfg(feature = "default")]
impl Clone for DnsTransport {
    /// The same ends and the id count as it stands, so a copy's updates go
    /// on from where this one's have got to.
    fn clone(&self) -> Self {
        Self {
            bind: self.bind.clone(),
            zone: self.zone.clone(),
            name: self.name.clone(),
            carrier: self.carrier,
            timeout: self.timeout,
            next_id: AtomicU16::new(self.next_id.load(Ordering::Relaxed)),
            sender: self.sender.clone(),
            datagrams: self.datagrams.clone(),
            connections: self.connections.clone(),
        }
    }
}

#[cfg(feature = "default")]
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
            sender: Sender::new(),
            datagrams: Kept::new(),
            connections: Serving::new(),
        }
    }

    /// Over TCP rather than UDP.
    #[must_use]
    pub const fn over(mut self, carrier: Carrier) -> Self {
        self.carrier = carrier;
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
        let mut update = Message::update_adding_txt(id, &zone, name, payload);
        let response = match self.carrier {
            Carrier::Udp => {
                update = update.with_edns();
                let bytes = message::encode(&update)?;
                if bytes.len() > UDP_EDNS {
                    return Err(protocol_error(
                        "an update over what a UDP datagram carries; use TCP",
                    ));
                }
                self.sender.exchange(address, |socket, peer| {
                    socket
                        .set_read_timeout(self.timeout)
                        .map_err(|e| classify("setting the answer timeout", &e))?;
                    socket
                        .send_to(&bytes, peer)
                        .map_err(|e| classify("sending the update", &e))?;
                    let mut buffer = vec![0u8; UDP_EDNS];
                    let read = socket
                        .recv(&mut buffer)
                        .map_err(|e| classify("awaiting the answer", &e))?;
                    message::decode(&buffer[..read])
                })?
            }
            Carrier::Tcp => {
                let bytes = message::encode(&update)?;
                // The connect is bounded as well as the reads. It was bare
                // until 2026-09-21, and a machine out of ephemeral ports
                // waited without end.
                let mut stream = socket::connect_tcp(address, self.timeout)?;
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

    fn resolve<'a>(&'a self, target: &'a str) -> (&'a str, &'a str, String) {
        let Some(named) = Target::under(Self::SCHEMES, target) else {
            return (target, &self.name, self.zone.clone());
        };
        let zone = named
            .query_value("zone")
            .unwrap_or_else(|| self.zone.clone());
        let name = if named.path().is_empty() {
            &self.name
        } else {
            named.path()
        };
        (named.authority(), name, zone)
    }
}

/// One message with its two-byte length before it, RFC 1035 section 4.2.2.
#[cfg(feature = "default")]
fn read_framed(stream: &mut impl Read) -> Result<Message> {
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

#[cfg(feature = "default")]
fn write_framed(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
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

#[cfg(feature = "default")]
impl Transport for DnsTransport {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Unordered("each update is its own, answered by its own id")
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Waits("the socket or listener waits for an update")
    }

    /// The TCP clients turned away at their own connection
    /// (`transport::serving`); a datagram turns nobody away.
    fn turned_away(&self) -> transport::Turned {
        self.connections.turned_away()
    }

    /// One update, from the socket or listener its open bound and
    /// kept: what arrived between two receives waits there; over TCP from
    /// whichever client sends first, its connection kept for its next. Its
    /// client waits for the answer until the cycle has ended: NOERROR on
    /// accepted, REFUSED on refused, SERVFAIL on failed.
    fn receive_up_to(&self, _most: usize) -> Result<Vec<Arrived>> {
        match self.carrier {
            Carrier::Udp => {
                let socket = self.datagrams.listener()?;
                Ok(vec![self.receive_datagram(socket)?])
            }
            Carrier::Tcp => Ok(vec![self.connections.next(
                self.timeout,
                Client::kept,
                |client| self.turn(client),
            )?]),
        }
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Gathered("one DNS UPDATE message carries the whole body")
    }

    fn send_from(&self, target: &str, outgoing: transport::Outgoing<'_>) -> Result<()> {
        let bytes: &[u8] = &outgoing.gather()?;
        self.update(target, bytes).map(|_| ())
    }
}

#[cfg(feature = "default")]
impl Configured for DnsTransport {
    const SETTINGS: &'static Settings = declaration::SETTINGS;
    const SCHEMES: &'static [&'static str] = declaration::SCHEMES;

    fn timeout_kept(&mut self) -> Option<&mut dyn transport::configured::TimeoutKept> {
        Some(&mut self.timeout)
    }

    fn configured(address: &str, settings: &xcore::settings::Read) -> Result<Self> {
        let zone = settings.optional_text("zone").unwrap_or_default();
        let name = settings.optional_text("name").unwrap_or_default();
        let mut transport = Self::new(address, zone, name);
        if settings.optional_text("carrier") == Some("tcp") {
            transport = transport.over(Carrier::Tcp);
        }
        Ok(transport)
    }

    /// Each TCP client's turn on a Receive Location taking at most `turn`.
    fn turning_within(mut self, turn: Duration) -> Self {
        self.connections = self.connections.turning_within(turn);
        self
    }

    /// Each callers turn on a Receive Location counted on clock.
    fn timed_by(mut self, clock: &std::sync::Arc<dyn xcore::Clock>) -> Self {
        self.connections = self.connections.timed_by(clock);
        self
    }

    /// What every receive takes from, bound where a Receive Location
    /// listens: a datagram socket, or a listener over TCP.
    fn listening(&self) -> Result<Option<&str>> {
        match self.carrier {
            Carrier::Udp => self.datagrams.listening(|| self.bind_udp()),
            Carrier::Tcp => self.connections.bound(|| self.bind_tcp()).map(Some),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use xcore::settings::{Applies, Given};

    #[test]
    fn dns_declares_its_settings_and_reads_through_them() {
        assert_eq!(DnsTransport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("zone".to_string(), Given::Text("example.com.".to_string())),
            (
                "name".to_string(),
                Given::Text("feed.example.com.".to_string()),
            ),
            ("carrier".to_string(), Given::Text("tcp".to_string())),
        ];
        let built = DnsTransport::open("0.0.0.0:0", Applies::Send, &given).expect("built");
        assert_eq!(built.zone, "example.com.");
        assert_eq!(built.name, "feed.example.com.");
        assert_eq!(built.carrier, Carrier::Tcp);
        let built = DnsTransport::open("0.0.0.0:53", Applies::Receive, &[]).expect("built");
        assert_eq!(built.carrier, Carrier::Udp);
        let given = [("name".to_string(), Given::Text("feed.".to_string()))];
        let Err(refused) = DnsTransport::open("0.0.0.0:53", Applies::Receive, &given) else {
            panic!("name is a send setting");
        };
        assert!(refused.message.contains("\"name\""), "{}", refused.message);
    }

    fn node() -> DnsTransport {
        DnsTransport::new("127.0.0.1:0", "xmip.example.", "probe.xmip.example.")
            .timing_out_after(Duration::from_secs(2))
    }

    #[test]
    fn a_client_that_stops_partway_is_cut_at_its_turn_and_the_next_is_served() {
        // Until 2026-11-14 it held the Location for as long as a read
        // waits, two seconds here, and for good where none is set.
        let turn = Duration::from_millis(200);
        let receiver = node().over(Carrier::Tcp).turning_within(turn);
        let address = receiver
            .connections
            .bound(|| receiver.bind_tcp())
            .expect("bound")
            .to_string();
        let mut stopped = TcpStream::connect(&address).expect("connect");
        let from = stopped.local_addr().expect("its address");
        // A length promising forty octets, and three of them.
        stopped
            .write_all(&[0, 40, 0, 1, 0x28])
            .expect("half an update");
        let at = address.clone();
        let sender = std::thread::spawn(move || node().over(Carrier::Tcp).send(&at, b"after"));
        let began = std::time::Instant::now();
        let mut arrived = receiver.receive().expect("the next client");
        let took = began.elapsed();
        assert!(
            took >= turn,
            "served after {took:?}, inside the other's turn"
        );
        assert!(took < Duration::from_millis(1500), "served after {took:?}");
        let taken = arrived.remove(0).taken().expect("answered NOERROR");
        assert_eq!(taken.bytes, b"after");
        sender.join().expect("thread").expect("sent");
        let turned = receiver.turned_away();
        assert_eq!(turned.callers.len(), 1, "{turned:?}");
        assert_eq!(turned.callers[0].peer, from);
        assert!(turned.callers[0].why.message.contains("turn"), "{turned:?}");
        drop(stopped);
    }

    #[test]
    fn every_receive_takes_from_what_the_first_bound_over_either_carrier() {
        let over_udp = DnsTransport::loopback();
        over_udp
            .datagrams
            .bound(|| over_udp.bind_udp())
            .expect("bound");
        let address = over_udp.datagrams.address().expect("address");
        transport::kept::held_across_receives(&over_udp, address, 5, |at, payload| {
            DnsTransport::loopback().send(at, payload)
        });
        let over_tcp = DnsTransport::loopback().over(Carrier::Tcp);
        over_tcp
            .connections
            .bound(|| over_tcp.bind_tcp())
            .expect("bound");
        let address = over_tcp.connections.address().expect("address");
        transport::kept::held_across_receives(&over_tcp, address, 5, |at, payload| {
            DnsTransport::loopback()
                .over(Carrier::Tcp)
                .send(at, payload)
        });
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
        assert!(arrived.defers(), "the client waits for the answer");
        let arrived = arrived.taken().expect("answered NOERROR");
        assert_eq!(arrived.bytes, payload);
        assert!(
            arrived
                .origin_uri
                .contains("/order.xmip.example.?zone=xmip.example.&id=")
        );
        let empty = far_end.receive_datagram(&socket).expect("receiving");
        let empty = empty.taken().expect("answered");
        assert_eq!(empty.bytes, [] as [u8; 0]);
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
                    kind: record::TYPE_TXT,
                    class: record::CLASS_IN,
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
        assert_eq!(arrived.taken().expect("answered").bytes, payload);
        let second = far_end.receive_connection(&listener).expect("second");
        assert_eq!(second.taken().expect("answered").bytes.len(), UDP_EDNS);
        sender.join().expect("thread").expect("sending");
    }

    #[test]
    fn a_refused_update_is_answered_over_what_the_client_pipelined_after() {
        // A client may pipeline (RFC 7766). The REFUSED is written with
        // megabytes it sent after the update unread, which a bare drop
        // resets away on Windows.
        let far_end = node().over(Carrier::Tcp);
        let (listener, address) = far_end.bind_tcp().expect("binding");
        let serving = std::thread::spawn(move || {
            let arrived = far_end.receive_connection(&listener).expect("receiving");
            arrived.refused(transport::Refusal::Forbidden)
        });
        let update = Message::update_adding_txt(11, "xmip.example.", "n.", b"refused");
        let update = message::encode(&update).expect("encode");
        let mut head = u16::try_from(update.len())
            .expect("short")
            .to_be_bytes()
            .to_vec();
        head.extend(update);
        let answer = transport::unread::answered_over_unread(&address, &head, 0, read_framed);
        assert_eq!(answer.expect("the answer").rcode(), message::RCODE_REFUSED);
        serving.join().expect("the far end").expect("answered");
    }

    #[test]
    fn an_update_is_answered_refused_servfail_or_noerror_by_its_verdict() {
        for carrier in [Carrier::Udp, Carrier::Tcp] {
            let receiver = DnsTransport::loopback().over(carrier);
            let address = match carrier {
                Carrier::Udp => {
                    receiver
                        .datagrams
                        .bound(|| receiver.bind_udp())
                        .expect("udp");
                    receiver.datagrams.address()
                }
                Carrier::Tcp => {
                    receiver
                        .connections
                        .bound(|| receiver.bind_tcp())
                        .expect("tcp");
                    receiver.connections.address()
                }
            }
            .expect("address")
            .to_string();
            let sender = std::thread::spawn(move || {
                let near = DnsTransport::loopback().over(carrier);
                [b"R1", b"C1", b"C1"].map(|body| near.send(&address, body))
            });
            let mut refused = receiver.receive().expect("the first");
            refused
                .remove(0)
                .refused(transport::Refusal::Forbidden)
                .expect("answered REFUSED");
            let mut failed = receiver.receive().expect("the second");
            failed.remove(0).failed().expect("answered SERVFAIL");
            let mut accepted = receiver.receive().expect("sent again");
            assert_eq!(accepted.remove(0).taken().expect("NOERROR").bytes, b"C1");
            let [refused, failed, accepted] = sender.join().expect("thread");
            let error = refused.expect_err("REFUSED");
            assert!(
                !error.retryable && error.message.contains("rcode 5"),
                "{error}"
            );
            let error = failed.expect_err("SERVFAIL");
            assert!(
                error.retryable && error.message.contains("SERVFAIL"),
                "{error}"
            );
            accepted.expect("NOERROR");
        }
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
