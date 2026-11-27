//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

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

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["dns"];
