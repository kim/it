// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use crate::{
    cmd::{
        self,
        patch,
    },
    patches,
};

#[derive(Debug, clap::Subcommand)]
pub enum Cmd {
    /// Record a mergepoint in a local repository
    Record(Record),
    /// Submit a mergepoint to a remote drop
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
    common: patch::Common,
    /// Allow branches to be uneven with their upstream (if any)
    #[clap(long, visible_alias = "force", value_parser)]
    ignore_upstream: bool,
}

#[derive(Debug, clap::Args)]
pub struct Submit {
    #[clap(flatten)]
    common: patch::Common,
    #[clap(flatten)]
    remote: patch::Remote,
    /// Allow branches to be uneven with their upstream (if any)
    #[clap(long, visible_alias = "force", value_parser)]
    ignore_upstream: bool,
}

pub fn record(
    Record {
        common,
        ignore_upstream,
    }: Record,
) -> cmd::Result<patches::Record> {
    patch::create(patch::Kind::Merges {
        common,
        remote: None,
        force: ignore_upstream,
    })
}

pub fn submit(
    Submit {
        common,
        remote,
        ignore_upstream,
    }: Submit,
) -> cmd::Result<patches::Record> {
    patch::create(patch::Kind::Merges {
        common,
        remote: Some(remote),
        force: ignore_upstream,
    })
}
