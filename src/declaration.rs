//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// Every setting a Location takes beyond its address, which is where a
/// Receive Location listens for updates — `0.0.0.0:53` the standard port;
/// a Send Location updates the server its target gives.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "zone",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "The zone updates are taken for or sent to where the target names \
                      none; a Receive Location without one takes every zone.",
            applies: Applies::Both,
        },
        Setting {
            name: "name",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "The owner name an update adds its TXT record under where the target \
                      names none.",
            applies: Applies::Send,
        },
        Setting {
            name: "carrier",
            kind: Kind::Choice {
                choices: &["udp", "tcp"],
            },
            presence: Presence::Optional,
            meaning: "Whether messages travel as UDP datagrams with EDNS or over TCP with a \
                      length prefix; udp when left out.",
            applies: Applies::Both,
        },
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long an update or an answer is waited for; unbounded when left \
             out.",
        ),
    ],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["dns"];
