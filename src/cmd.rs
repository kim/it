// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use crate::metadata::git::{
    find_parent,
    FromGit,
    GitAlternates,
    GitDrop,
    GitIdentity,
    GitMirrors,
};

mod util;
use util::args;

pub mod drop;
pub mod id;
pub mod mergepoint;
pub mod patch;
pub mod topic;
pub mod ui;

pub use crate::{
    Error,
    Result,
};

/// Error indicating that the command was cancelled at the user's request, eg.
/// by pressing ESC in an interactive prompt.
///
/// By means of [`anyhow::Error::downcast`], this allows for exiting the program
/// with a zero exit status, even though the invocation returned an `Err`.
#[derive(Debug, thiserror::Error)]
#[error("command aborted")]
pub struct Aborted;

/// Shortcut to return early from a command with an [`Aborted`] error.
macro_rules! abort {
    () => {
        return Err(crate::Error::from(Aborted))
    };
}
pub(crate) use abort;

pub enum Output {
    Val(Box<dyn erased_serde::Serialize>),
    Iter(Box<dyn Iterator<Item = Result<Box<dyn erased_serde::Serialize>>>>),
}

impl Output {
    pub fn val<T>(v: T) -> Self
    where
        T: serde::Serialize + 'static,
    {
        Self::Val(Box::new(v))
    }

    pub fn iter<T, U>(v: T) -> Self
    where
        T: IntoIterator<Item = Result<U>> + 'static,
        U: serde::Serialize + 'static,
    {
        let iter = v
            .into_iter()
            .map(|x| x.map(|i| Box::new(i) as Box<dyn erased_serde::Serialize>));

        Self::Iter(Box::new(iter))
    }
}

trait IntoOutput {
    fn into_output(self) -> Output;
}

impl<T> IntoOutput for T
where
    T: serde::Serialize + 'static,
{
    fn into_output(self) -> Output {
        Output::Val(Box::new(self))
    }
}

#[derive(Debug, clap::Subcommand)]
pub enum Cmd {
    /// Drop management
    #[clap(subcommand)]
    Drop(drop::Cmd),

    /// Identity management
    #[clap(subcommand)]
    Id(id::Cmd),

    /// Patches
    #[clap(subcommand)]
    Patch(patch::Cmd),

    /// Merge points
    #[clap(subcommand)]
    MergePoint(mergepoint::Cmd),

    /// Topics
    #[clap(subcommand)]
    Topic(topic::Cmd),
}

impl Cmd {
    pub fn run(self) -> Result<Output> {
        match self {
            Self::Drop(cmd) => cmd.run(),
            Self::Id(cmd) => cmd.run(),
            Self::Patch(cmd) => cmd.run(),
            Self::MergePoint(cmd) => cmd.run(),
            Self::Topic(cmd) => cmd.run(),
        }
    }
}
