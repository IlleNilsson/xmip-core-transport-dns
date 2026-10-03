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

use std::net::{SocketAddr, TcpListener, UdpSocket};

use transport::answer::Datagram;
use transport::error::{Result, classify};
use transport::socket;
use transport::{Acknowledgement, Arrived, Verdict};

use crate::message::{self, Message, UDP_EDNS};
use crate::{DnsTransport, read_framed, write_framed};

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
                    return Ok(Arrived::whole(origin, payload, acknowledgement));
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
    /// update, its answer waiting for the verdict on the connection.
    ///
    /// # Errors
    /// Where the connection could not be accepted, or what came is not DNS.
    pub fn receive_connection(&self, listener: &TcpListener) -> Result<Arrived> {
        // The wait for the connection is bounded as well as the reads. It was
        // bare until 2026-09-21, and a far end nobody reached waited for good.
        let (mut stream, peer) = socket::accept_tcp(listener, self.timeout)?;
        loop {
            let message = read_framed(&mut stream)?;
            match self.judge(peer, &message) {
                Ok(origin) => {
                    let payload = message.txt_payload();
                    let acknowledgement = Acknowledgement::deferred(move |verdict| {
                        let answer = message::encode(&message.response(rcode_of(verdict)))?;
                        write_framed(&mut stream, &answer)
                    });
                    return Ok(Arrived::whole(origin, payload, acknowledgement));
                }
                Err(rcode) => {
                    write_framed(&mut stream, &message::encode(&message.response(rcode))?)?;
                }
            }
        }
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
