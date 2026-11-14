//! An update as a Receive Location takes it, and its answer once the
//! receive cycle has ended.
//!
//! The client waits for the answer to its UPDATE, over either carrier, so
//! it is answered after the whole cycle: NOERROR on [`Verdict::Accepted`];
//! REFUSED on [`Verdict::Refused`], the server declining the operation for
//! policy (RFC 1035 section 4.1.1, among the update's rcodes in RFC 2136
//! section 2.2), which the client does not send again; SERVFAIL on
//! [`Verdict::Failed`], the server's failure, which the client sends again
//! (RFC 2136 section 4.5). A query is answered NOTIMP and an update to
//! another zone REFUSED at once; neither is a Stream.
//!
//! **Over TCP a client's connection is kept between its updates**
//! (`transport::serving::Serving`): each framed message is one turn,
//! bounded whole by the node's `[tuning] receive_turn`, so a client that
//! stops partway is turned away and the next is served (ADR-0018,
//! amendment 2026-11-14). The connection takes no next message until its
//! update is answered, and a message it pipelined meanwhile waits in its
//! socket for its own turn. Until 2026-11-14 a receive accepted one
//! connection and read it on the Location's own thread, every other client
//! waiting behind it, and closed it once answered.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};

use transport::answer::{Answer, Busy, Datagram};
use transport::deadline::Within;
use transport::error::{Result, classify, protocol_error};
use transport::serving::{Open, Turn};
use transport::socket;
use transport::{Acknowledgement, Arrived, Verdict};

use crate::message::{self, Message, UDP_EDNS};
use crate::{DnsTransport, read_framed, write_framed};

/// One TCP client's connection: read within each turn, and kept between
/// its updates where a Receive Location serves it.
pub struct Client {
    reader: BufReader<Within>,
    writer: TcpStream,
    peer: SocketAddr,
    /// An update taken and its answer not yet written.
    busy: Busy,
    /// Whether the connection is kept for the client's next message; one
    /// taken alone ends once its update is answered.
    kept: bool,
}

impl Client {
    /// A client's new connection, from `peer`, kept between its updates.
    ///
    /// # Errors
    /// Where the connection could not be cloned for its answers.
    pub fn kept(stream: Within, peer: SocketAddr) -> Result<Self> {
        let (reader, writer) = stream.split()?;
        Ok(Self {
            reader,
            writer,
            peer,
            busy: Busy::new(),
            kept: true,
        })
    }
}

impl Open for Client {
    fn socket(&self) -> &TcpStream {
        &self.writer
    }

    /// A message the last read took beside its own waits in the reader.
    fn waiting(&self) -> bool {
        !self.reader.buffer().is_empty()
    }

    fn busy(&self) -> Option<&Busy> {
        Some(&self.busy)
    }
}

impl DnsTransport {
    /// Take one update from an already-bound UDP socket, its answer waiting
    /// for the verdict. A query is answered NOTIMP and skipped, an update to
    /// another zone REFUSED.
    ///
    /// # Errors
    /// Where nothing arrived in time, what arrived is not DNS, or the socket
    /// could not be shared with the answer.
    pub fn receive_datagram(&self, socket: &UdpSocket) -> Result<Arrived> {
        let mut buffer = vec![0u8; UDP_EDNS];
        loop {
            let (read, peer) = socket
                .recv_from(&mut buffer)
                .map_err(|e| classify("receiving a datagram", &e))?;
            let message = message::decode(&buffer[..read])?;
            match self.judge(peer, &message) {
                Ok(origin) => {
                    let answering = Datagram::to(socket, peer)?;
                    let payload = message.txt_payload();
                    let acknowledgement = Acknowledgement::deferred(move |verdict| {
                        answering.send(&message::encode(&message.response(rcode_of(verdict)))?)
                    });
                    return Ok(Arrived::whole(origin, payload, acknowledgement).from_peer(peer));
                }
                Err(rcode) => {
                    let answer = message::encode(&message.response(rcode))?;
                    socket
                        .send_to(&answer, peer)
                        .map_err(|e| classify("answering", &e))?;
                }
            }
        }
    }

    /// Accept one TCP peer on an already-bound listener and take its
    /// update, as a far end does, its answer waiting for the verdict on the
    /// connection, which ends once answered.
    ///
    /// # Errors
    /// Where the connection could not be accepted, closed before its
    /// update, or what came is not DNS.
    pub fn receive_connection(&self, listener: &TcpListener) -> Result<Arrived> {
        // The wait for the connection is bounded as well as the reads. It was
        // bare until 2026-09-21, and a far end nobody reached waited for good.
        let (stream, peer) = socket::accept_tcp(listener, self.timeout)?;
        let mut client = Client {
            kept: false,
            ..Client::kept(Within::new(stream), peer)?
        };
        loop {
            match self.turn(&mut client)? {
                Turn::Taken(arrived) | Turn::Last(arrived) => return Ok(arrived),
                Turn::Nothing => {}
                Turn::Closed => {
                    return Err(protocol_error("a client that closed before its update"));
                }
            }
        }
    }

    /// One turn on a TCP client's connection: its next message, an update
    /// to this zone taken with its answer waiting for the verdict, anything
    /// else answered at once. A client that closed between messages has
    /// gone.
    ///
    /// # Errors
    /// Where the connection broke, or what came is not DNS.
    pub fn turn(&self, client: &mut Client) -> Result<Turn<Arrived>> {
        let ended = client
            .reader
            .fill_buf()
            .map_err(|e| classify("reading the length", &e))?
            .is_empty();
        if ended {
            return Ok(Turn::Closed);
        }
        let message = read_framed(&mut client.reader)?;
        let origin = match self.judge(client.peer, &message) {
            Ok(origin) => origin,
            Err(rcode) => {
                write_framed(
                    &mut client.writer,
                    &message::encode(&message.response(rcode))?,
                )?;
                return Ok(Turn::Nothing);
            }
        };
        let payload = message.txt_payload();
        let kept = client.kept;
        // Let go without a verdict, the connection is shut: the client
        // sends the update again.
        let answer = Answer::held(&client.writer)?.busy(&client.busy);
        let acknowledgement = Acknowledgement::deferred(move |verdict| {
            let bytes = message::encode(&message.response(rcode_of(verdict)))?;
            answer.with(|stream| {
                write_framed(stream, &bytes)?;
                // A client may pipeline its next message (RFC 7766 section
                // 6.2.1.1): a kept connection reads it on its next turn; one
                // taken alone reads to the client's close, since unread, its
                // close would reset this answer away.
                if kept { Ok(()) } else { socket::finish(stream) }
            })
        });
        Ok(Turn::Taken(
            Arrived::whole(origin, payload, acknowledgement).from_peer(client.peer),
        ))
    }

    /// The origin of the Stream `message` carries where it is an update to
    /// this zone, or the rcode it is answered with at once where it is not.
    fn judge(&self, peer: SocketAddr, message: &Message) -> std::result::Result<String, u16> {
        if message.opcode() != message::OPCODE_UPDATE {
            return Err(message::RCODE_NOTIMP);
        }
        let zone = message.questions.first().map_or("", |q| q.name.as_str());
        if !self.zone.is_empty() && !zone.eq_ignore_ascii_case(&self.zone) {
            return Err(message::RCODE_REFUSED);
        }
        let name = message.authority.first().map_or("", |r| r.name.as_str());
        Ok(format!("dns://{peer}/{name}?zone={zone}&id={}", message.id))
    }
}

/// The rcode an update is answered with once the receive cycle has ended:
/// NOERROR on accepted; REFUSED on refused, whatever the cause; SERVFAIL
/// on failed.
const fn rcode_of(verdict: Verdict) -> u16 {
    match verdict {
        Verdict::Accepted => message::RCODE_NOERROR,
        Verdict::Refused(_) => message::RCODE_REFUSED,
        Verdict::Failed => message::RCODE_SERVFAIL,
    }
}
