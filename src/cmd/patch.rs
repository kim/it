// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use crate::{
    cmd,
    patches,
};

mod create;
mod prepare;

pub use create::{
    create,
    Comment,
    Common,
    Kind,
    Patch,
    Remote,
};

#[derive(Debug, clap::Subcommand)]
pub enum Cmd {
    /// Record a patch in a local drop history
    Record(Record),
    /// Submit a patch to a remote drop
    Submit(Submit),
}

impl Cmd {
    pub fn run(self) -> cmd::Result<cmd::Output> {
        match self {
            Self::Record(args) => record(args),
            Self::Submit(args) => submit(args),
        }
        .map(cmd::IntoOutput::into_output)
    }
}

#[derive(Debug, clap::Args)]
pub struct Record {
    #[clap(flatten)]
    common: Common,
    #[clap(flatten)]
    patch: Patch,
}

#[derive(Debug, clap::Args)]
pub struct Submit {
    #[clap(flatten)]
    common: Common,
    #[clap(flatten)]
    patch: Patch,
    #[clap(flatten)]
    remote: Remote,
}

pub fn record(Record { common, patch }: Record) -> cmd::Result<patches::Record> {
    create(Kind::Patch {
        common,
        remote: None,
        patch,
    })
}

pub fn submit(
    Submit {
        common,
        patch,
        remote,
    }: Submit,
) -> cmd::Result<patches::Record> {
    create(Kind::Patch {
        common,
        remote: Some(remote),
        patch,
    })
}
