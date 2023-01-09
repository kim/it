// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use crate::{
    git,
    patches::{
        self,
        Topic,
    },
};

use super::Common;
use crate::cmd;

#[derive(Debug, clap::Args)]
pub struct Ls {
    #[clap(flatten)]
    common: Common,
}

#[derive(serde::Serialize)]
pub struct Output {
    topic: Topic,
    subject: String,
}

pub fn ls(args: Ls) -> cmd::Result<Vec<cmd::Result<Output>>> {
    let repo = git::repo::open(&args.common.git_dir)?;
    Ok(patches::iter::unbundled::topics_with_subject(&repo)
        .map(|i| i.map(|(topic, subject)| Output { topic, subject }))
        .collect())
}
