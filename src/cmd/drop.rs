// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    ops::Deref,
    path::PathBuf,
};

use anyhow::{
    ensure,
    Context,
};
use clap::ValueHint;
use either::Either::Left;

use crate::{
    cmd,
    metadata::{
        self,
        git::{
            FromGit,
            META_FILE_ALTERNATES,
            META_FILE_MIRRORS,
        },
        IdentityId,
        Signed,
    },
    patches::REF_HEADS_PATCHES,
};

mod bundles;
pub use bundles::{
    sync,
    Bundles,
    Sync,
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

mod serve;
pub use serve::{
    serve,
    Serve,
};

mod snapshot;
pub use snapshot::{
    snapshot,
    Snapshot,
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
    /// Initialise a drop
    Init(Init),
    /// Display the drop metadata
    Show(Show),
    /// Serve bundles and patch submission over HTTP
    Serve(Serve),
    /// Edit the drop metadata
    Edit(Edit),
    /// Manage patch bundles
    #[clap(subcommand)]
    Bundles(Bundles),
    /// Take a snapshot of the patches received so far
    Snapshot(Snapshot),
    /// Unbundle the entire drop history
    Unbundle(Unbundle),
}

impl Cmd {
    pub fn run(self) -> cmd::Result<cmd::Output> {
        match self {
            Self::Init(args) => init(args).map(cmd::IntoOutput::into_output),
            Self::Show(args) => show(args).map(cmd::IntoOutput::into_output),
            Self::Serve(args) => serve(args).map(cmd::IntoOutput::into_output),
            Self::Edit(args) => edit(args).map(cmd::IntoOutput::into_output),
            Self::Bundles(cmd) => cmd.run(),
            Self::Snapshot(args) => snapshot(args).map(cmd::IntoOutput::into_output),
            Self::Unbundle(args) => unbundle(args).map(cmd::IntoOutput::into_output),
        }
    }
}

#[derive(Debug, clap::Args)]
struct Common {
    /// Path to the drop repository
    #[clap(from_global)]
    git_dir: PathBuf,
    /// A list of paths to search for identity repositories
    #[clap(
        long,
        value_parser,
        value_name = "PATH",
        env = "IT_ID_PATH",
        default_value_t,
        value_hint = ValueHint::DirPath,
    )]
    id_path: cmd::util::args::IdSearchPath,
}

fn find_id(
    repo: &git2::Repository,
    id_path: &[git2::Repository],
    id: &IdentityId,
) -> cmd::Result<Signed<metadata::Identity>> {
    let signed = metadata::Identity::from_search_path(id_path, cmd::id::identity_ref(Left(id))?)?
        .meta
        .signed;

    let verified_id = signed
        .verify(cmd::find_parent(repo))
        .with_context(|| format!("invalid identity {id}"))?;
    ensure!(
        &verified_id == id,
        "ids do not match after verification: expected {id}, found {verified_id}",
    );

    Ok(signed)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Editable {
    description: metadata::drop::Description,
    roles: metadata::drop::Roles,
    custom: metadata::Custom,
}

impl From<metadata::Drop> for Editable {
    fn from(
        metadata::Drop {
            description,
            roles,
            custom,
            ..
        }: metadata::Drop,
    ) -> Self {
        Self {
            description,
            roles,
            custom,
        }
    }
}

impl TryFrom<Editable> for metadata::Drop {
    type Error = crate::Error;

    fn try_from(
        Editable {
            description,
            roles,
            custom,
        }: Editable,
    ) -> Result<Self, Self::Error> {
        ensure!(!roles.root.ids.is_empty(), "drop role cannot be empty");
        ensure!(
            !roles.snapshot.ids.is_empty(),
            "snapshot roles cannot be empty"
        );
        ensure!(
            !roles.branches.is_empty(),
            "at least one branch role is required"
        );
        for (name, ann) in &roles.branches {
            ensure!(
                !ann.role.ids.is_empty(),
                "branch role {name} cannot be empty"
            );
            ensure!(name.starts_with("refs/heads/"), "not a branch {name}");
            ensure!(name.deref() != REF_HEADS_PATCHES, "reserved branch {name}");
        }

        Ok(Self {
            fmt_version: Default::default(),
            description,
            prev: None,
            roles,
            custom,
        })
    }
}
