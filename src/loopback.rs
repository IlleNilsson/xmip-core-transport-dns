//! DNS at both ends on this machine (ADR-0051): a server for one zone on an
//! ephemeral port, over UDP and TCP at once as a name server is, and an
//! update sent the way a resolver sends it — as a datagram while it fits,
//! as a TCP message past that (RFC 7766).
//!
//! The far end stands before the payload is known, so it cannot choose a
//! carrier; it takes whichever the near end used. The ceiling is the
//! message's own sixteen-bit length, less what the update spends on the
//! zone question, the record's name and the TXT string lengths.

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::{OnceLock, mpsc};

use transport::Arrived;
use transport::Transport;
use transport::error::{Result, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};

use crate::message::{self, MAX_MESSAGE, Message, UDP_EDNS};
use crate::{Carrier, DnsTransport};

/// The zone the loopback updates, and the name it adds under.
pub const LOOPBACK_ZONE: &str = "xmip.example.";
pub const LOOPBACK_NAME: &str = "probe.xmip.example.";

/// The most one update carries as a datagram: the largest payload whose
/// update — the zone question, one TXT record of it in strings of 255, the
/// OPT record asking for [`UDP_EDNS`] — encodes within the datagram. Found
/// through the transport's own encoder once and remembered.
#[must_use]
pub fn datagram_ceiling() -> usize {
    static CEILING: OnceLock<usize> = OnceLock::new();
    *CEILING.get_or_init(|| largest_fitting(UDP_EDNS, true))
}

/// The most one update carries at all: the largest payload whose update
/// still fits the sixteen-bit length a TCP message is prefixed with.
#[must_use]
pub fn message_ceiling() -> usize {
    static CEILING: OnceLock<usize> = OnceLock::new();
    *CEILING.get_or_init(|| largest_fitting(MAX_MESSAGE, false))
}

fn largest_fitting(limit: usize, edns: bool) -> usize {
    let fits = |bytes: usize| {
        let mut update =
            Message::update_adding_txt(0, LOOPBACK_ZONE, LOOPBACK_NAME, &vec![0; bytes]);
        if edns {
            update = update.with_edns();
        }
        message::encode(&update).is_ok_and(|wire| wire.len() <= limit)
    };
    (0..=limit).rev().find(|&bytes| fits(bytes)).unwrap_or(0)
}

impl DnsTransport {
    /// Both ends on this machine: an ephemeral local port, the loopback
    /// zone and name, the loopback timeout on every wait.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", LOOPBACK_ZONE, LOOPBACK_NAME).timing_out_after(LOOPBACK_TIMEOUT)
    }

    /// The datagram socket and the listener on one port, as a name server
    /// has them. The port is the kernel's choice for the socket; where the
    /// listener cannot follow it, another is asked for.
    fn bind_both(&self) -> Result<(UdpSocket, TcpListener, String)> {
        for _ in 0..16 {
            let (socket, address) = self.bind_udp()?;
            if let Ok(listener) = TcpListener::bind(&address) {
                return Ok((socket, listener, address));
            }
        }
        Err(protocol_error(
            "no port was free for the datagram socket and the listener at once",
        ))
    }
}

/// A server on one port over both carriers, waiting for its one update.
struct Serving {
    transport: DnsTransport,
    socket: UdpSocket,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Serving {
    fn address(&self) -> &str {
        &self.address
    }

    /// Each carrier waits on its own thread; the first to take an update
    /// answers for the round, and the other is woken with bytes that are
    /// not DNS so the far end is gone when the round is judged rather than
    /// a timeout later.
    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let Self {
            transport,
            socket,
            listener,
            address,
        } = *self;
        let (tell, told) = mpsc::channel();
        let over_udp = {
            let tell = tell.clone();
            let transport = transport.clone();
            std::thread::spawn(move || drop(tell.send(transport.receive_datagram(&socket))))
        };
        let over_tcp =
            std::thread::spawn(move || drop(tell.send(transport.receive_connection(&listener))));
        let first = told
            .recv()
            .map_err(|_| protocol_error("neither carrier took an update"))?;
        wake(&address);
        drop(over_udp.join());
        drop(over_tcp.join());
        first
    }
}

/// Reach the carrier still waiting: a byte that is not a message on the
/// socket, a connection with nothing in it on the listener. The one that
/// already answered ignores both.
fn wake(address: &str) {
    if let Ok(poke) = UdpSocket::bind("127.0.0.1:0") {
        drop(poke.send_to(&[0], address));
    }
    drop(TcpStream::connect(address));
}

impl Loopback for DnsTransport {
    fn ceiling(&self) -> Option<usize> {
        Some(message_ceiling())
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (socket, listener, address) = self.bind_both()?;
        Ok(Box::new(Serving {
            transport: self.clone(),
            socket,
            listener,
            address,
        }))
    }

    /// Under the datagram ceiling the update goes as UDP with EDNS; above
    /// it, as TCP with a length prefix; past the message ceiling nothing
    /// goes, and the refusal says so before anything is sent.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        if payload.len() > message_ceiling() {
            return Err(protocol_error(format!(
                "{} bytes is over the {} one update carries in a message",
                payload.len(),
                message_ceiling()
            )));
        }
        let carrier = if payload.len() <= datagram_ceiling() {
            Carrier::Udp
        } else {
            Carrier::Tcp
        };
        self.clone().over(carrier).send(address, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::payload::{edge_payloads, patterned};

    #[test]
    fn the_loopback_sends_one_update_and_takes_its_payload() {
        let arrived = DnsTransport::loopback().round(b"txt").expect("round");
        assert_eq!(arrived.bytes, b"txt");
        assert!(arrived.origin_uri.starts_with("dns://127.0.0.1:"));
        assert!(
            arrived
                .origin_uri
                .contains("/probe.xmip.example.?zone=xmip.example.&id=")
        );
        let long = patterned(40_000);
        assert_eq!(
            DnsTransport::loopback().round(&long).expect("long").bytes,
            long
        );
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole_up_to_the_message() {
        let transport = DnsTransport::loopback();
        assert_eq!(transport.ceiling(), Some(message_ceiling()));
        for (name, bytes) in edge_payloads() {
            assert!(transport.refuses(&bytes).is_none(), "{name}");
            let arrived = transport
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
        // The datagram's brim goes as UDP, one byte more as TCP, and past
        // the message's own length nothing goes.
        assert!(
            (3_000..UDP_EDNS).contains(&datagram_ceiling()),
            "{}",
            datagram_ceiling()
        );
        let brim = patterned(datagram_ceiling());
        assert_eq!(transport.round(&brim).expect("datagram brim").bytes, brim);
        let over = patterned(datagram_ceiling() + 1);
        assert_eq!(transport.round(&over).expect("as tcp").bytes, over);
        let brim = patterned(message_ceiling());
        assert_eq!(transport.round(&brim).expect("message brim").bytes, brim);
        let past = vec![0u8; message_ceiling() + 1];
        let refused = transport.round(&past).expect_err("past the message");
        assert!(refused.message.starts_with("send failed:"), "{refused}");
    }
}
