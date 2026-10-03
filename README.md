# xmip-core-transport-dns

DNS transport: one dynamic update is one Stream, its TXT payload the bytes and the zone and name the address; UDP with EDNS or TCP. RFC 1035 and RFC 2136. Its message codec is the estate's one DNS codec, which the mdns technology reads and writes through, with the label-and-pointer form a name takes on the wire (`label`), which the transport capability held until 2026-09-28. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location's request and its answer go through one socket per address family, bound on the first send and kept by the transport (`transport::sender::Sender`), whatever came late read off before the next request, so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket.

A Receive Location keeps what it binds for its carrier on the first receive (`transport::kept::Kept`), the datagram socket or the listener: what arrives between two receives waits for the next, where until 2026-09-27 each receive bound its own and what came between was lost or refused.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls, and its query is decoded there. Until 2026-09-28 this technology split the query off itself, without percent-decoding it.

## Acknowledgement

The client waits for the answer to its UPDATE, so it is answered after the
whole receive cycle, over either carrier. On Accepted the answer is NOERROR. On
Refused it is REFUSED, the server declining the operation for policy (RFC 1035
section 4.1.1, among the update's rcodes in RFC 2136 section 2.2), which the
client does not send again. On Failed it is SERVFAIL, the server's failure,
which RFC 2136 section 4.5 has the client send again (and a send of this
transport answered SERVFAIL fails as retryable, any other rcode as permanent). A query is answered NOTIMP and an update to another zone REFUSED at
once; neither is a Stream. Each update's TXT payload arrives whole.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
