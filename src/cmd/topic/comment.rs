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
    /// Record the comment with a local drop history
    Record(Record),
    /// Submit the comment to a remote drop
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
    #[clap(flatten)]
    comment: patch::Comment,
}

#[derive(Debug, clap::Args)]
pub struct Submit {
    #[clap(flatten)]
    common: patch::Common,
    #[clap(flatten)]
    comment: patch::Comment,
    #[clap(flatten)]
    remote: patch::Remote,
}

pub fn record(Record { common, comment }: Record) -> cmd::Result<patches::Record> {
    patch::create(patch::Kind::Comment {
        common,
        remote: None,
        comment,
    })
}

pub fn submit(
    Submit {
        common,
        comment,
        remote,
    }: Submit,
) -> cmd::Result<patches::Record> {
    patch::create(patch::Kind::Comment {
        common,
        remote: Some(remote),
        comment,
    })
}
