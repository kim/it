// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use crate::cmd;

mod prune;
pub use prune::{
    prune,
    Prune,
};

mod sync;
pub use sync::{
    sync,
    Sync,
};

#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Bundles {
    Sync(Sync),
    Prune(Prune),
}

impl Bundles {
    pub fn run(self) -> cmd::Result<cmd::Output> {
        match self {
            Self::Sync(args) => sync(args).map(cmd::IntoOutput::into_output),
            Self::Prune(args) => prune(args).map(cmd::IntoOutput::into_output),
        }
    }
}
