// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::path::PathBuf;

use crate::cmd;

pub mod comment;

mod ls;
pub use ls::{
    ls,
    Ls,
};

mod show;
pub use show::{
    show,
    Show,
};

mod unbundle;
pub use unbundle::{
    unbundle,
    Unbundle,
};

#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Cmd {
    /// List the recorded topics
    Ls(Ls),
    /// Show a topic
    Show(Show),
    /// Comment on a topic
    #[clap(subcommand)]
    Comment(comment::Cmd),
    /// Unbundle a topic
    Unbundle(Unbundle),
}

impl Cmd {
    pub fn run(self) -> cmd::Result<cmd::Output> {
        match self {
            Self::Ls(args) => ls(args).map(cmd::Output::iter),
            Self::Show(args) => show(args).map(cmd::Output::iter),
            Self::Comment(cmd) => cmd.run(),
            Self::Unbundle(args) => unbundle(args).map(cmd::Output::val),
        }
    }
}

#[derive(Debug, clap::Args)]
struct Common {
    /// Path to the drop repository
    #[clap(from_global)]
    git_dir: PathBuf,
}
