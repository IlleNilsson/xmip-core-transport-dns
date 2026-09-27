# xmip-core-transport-dns

DNS transport: one dynamic update is one Stream, its TXT payload the bytes and the zone and name the address; UDP with EDNS or TCP. RFC 1035 and RFC 2136. Its message codec is the estate's one DNS codec, which the mdns technology reads and writes through. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location's request and its answer go through one socket per address family, bound on the first send and kept by the transport (`transport::sender::Sender`), whatever came late read off before the next request, so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
