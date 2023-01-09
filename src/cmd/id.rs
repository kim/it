// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    collections::BTreeSet,
    num::NonZeroUsize,
    path::PathBuf,
};

use anyhow::{
    anyhow,
    ensure,
};
use clap::ValueHint;
use either::{
    Either,
    Left,
    Right,
};
use url::Url;

use crate::{
    cfg,
    cmd::{
        self,
        args::Refname,
    },
    git,
    metadata::{
        self,
        git::META_FILE_ID,
        IdentityId,
    },
    paths,
};

mod edit;
pub use edit::{
    edit,
    Edit,
};

mod init;
pub use init::{
    init,
    Init,
};

mod show;
pub use show::{
    show,
    Show,
};

mod sign;
pub use sign::{
    sign,
    Sign,
};

#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Cmd {
    /// Initialise a fresh identity
    Init(Init),
    /// Display the identity docment
    Show(Show),
    /// Edit the identity document
    Edit(Edit),
    /// Sign a proposed identity document
    Sign(Sign),
}

impl Cmd {
    pub fn run(self) -> cmd::Result<cmd::Output> {
        match self {
            Self::Init(args) => init(args).map(cmd::IntoOutput::into_output),
            Self::Show(args) => show(args).map(cmd::IntoOutput::into_output),
            Self::Edit(args) => edit(args).map(cmd::IntoOutput::into_output),
            Self::Sign(args) => sign(args).map(cmd::IntoOutput::into_output),
        }
    }
}

#[derive(Clone, Debug, clap::Args)]
pub struct Common {
    /// Path to the 'keyring' repository
    // nb. not using from_global here -- current_dir doesn't make sense here as
    // the default
    #[clap(
        long,
        value_parser,
        value_name = "DIR",
        env = "GIT_DIR",
        default_value_os_t = paths::ids(),
        value_hint = ValueHint::DirPath,
    )]
    git_dir: PathBuf,
    /// Identity to operate on
    ///
    /// If not set as an option nor in the environment, the value of `it.id` in
    /// the git config is tried.
    #[clap(short = 'I', long = "identity", value_name = "ID", env = "IT_ID")]
    id: Option<IdentityId>,
}

impl Common {
    pub fn resolve(&self) -> cmd::Result<(git2::Repository, Refname)> {
        let repo = git::repo::open(&self.git_dir)?;
        let refname = identity_ref(
            match self.id {
                Some(id) => Left(id),
                None => Right(repo.config()?),
            }
            .as_ref(),
        )?;

        Ok((repo, refname))
    }
}

pub fn identity_ref(id: Either<&IdentityId, &git2::Config>) -> cmd::Result<Refname> {
    let id = id.either(
        |iid| Ok(iid.to_string()),
        |cfg| {
            cfg::git::identity(cfg)?
                .ok_or_else(|| anyhow!("'{}' not set", cfg::git::IT_ID))
                .map(|iid| iid.to_string())
        },
    )?;
    Ok(Refname::try_from(format!("refs/heads/it/ids/{id}"))?)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Editable {
    keys: metadata::KeySet<'static>,
    threshold: NonZeroUsize,
    mirrors: BTreeSet<Url>,
    expires: Option<metadata::DateTime>,
    custom: metadata::Custom,
}

impl From<metadata::Identity> for Editable {
    fn from(
        metadata::Identity {
            keys,
            threshold,
            mirrors,
            expires,
            custom,
            ..
        }: metadata::Identity,
    ) -> Self {
        Self {
            keys,
            threshold,
            mirrors,
            expires,
            custom,
        }
    }
}

impl TryFrom<Editable> for metadata::Identity {
    type Error = crate::Error;

    fn try_from(
        Editable {
            keys,
            threshold,
            mirrors,
            expires,
            custom,
        }: Editable,
    ) -> Result<Self, Self::Error> {
        ensure!(!keys.is_empty(), "keys cannot be empty");

        Ok(Self {
            spec_version: crate::SPEC_VERSION,
            prev: None,
            keys,
            threshold,
            mirrors,
            expires,
            custom,
        })
    }
}
