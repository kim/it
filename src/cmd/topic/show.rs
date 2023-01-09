// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use super::Common;
use crate::{
    cmd,
    git,
    patches::{
        self,
        iter::Note,
        Topic,
    },
};

#[derive(Debug, clap::Args)]
pub struct Show {
    #[clap(flatten)]
    common: Common,
    /// Traverse the topic in reverse order, ie. oldest first
    #[clap(long, value_parser)]
    reverse: bool,
    #[clap(value_parser)]
    topic: Topic,
}

pub fn show(args: Show) -> cmd::Result<Vec<cmd::Result<Note>>> {
    let repo = git::repo::open(&args.common.git_dir)?;
    let iter = patches::iter::topic(&repo, &args.topic);
    if args.reverse {
        Ok(iter.rev().collect())
    } else {
        Ok(iter.collect())
    }
}
