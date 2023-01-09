// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::path::PathBuf;

use super::Common;
use crate::{
    cmd::{
        self,
        args::Refname,
        FromGit as _,
        GitIdentity,
    },
    metadata::{
        self,
        ContentHash,
    },
};

#[derive(Debug, clap::Args)]
pub struct Show {
    #[clap(flatten)]
    common: Common,
    /// Blob hash to show
    ///
    /// Instead of looking for an id.json in the tree --ref points to, load a
    /// particular id.json by hash. If given, --ref is ignored.
    #[clap(long = "hash", value_parser, value_name = "OID")]
    blob_hash: Option<git2::Oid>,
}

#[derive(serde::Serialize)]
pub struct Output {
    repo: PathBuf,
    #[serde(rename = "ref")]
    refname: Refname,
    hash: ContentHash,
    status: Status,
    data: metadata::Signed<metadata::Identity>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Verified {
        id: metadata::IdentityId,
    },
    #[serde(with = "crate::serde::display")]
    Invalid(metadata::error::Verification),
}

impl From<Result<metadata::IdentityId, metadata::error::Verification>> for Status {
    fn from(r: Result<metadata::IdentityId, metadata::error::Verification>) -> Self {
        r.map(|id| Self::Verified { id })
            .unwrap_or_else(Self::Invalid)
    }
}

pub fn show(args: Show) -> cmd::Result<Output> {
    let (repo, refname) = args.common.resolve()?;

    let GitIdentity { hash, signed } = match args.blob_hash {
        None => metadata::Identity::from_tip(&repo, &refname)?,
        Some(oid) => metadata::Identity::from_blob(&repo.find_blob(oid)?)?,
    };
    let status = signed.verify(cmd::find_parent(&repo)).into();

    Ok(Output {
        repo: repo.path().to_owned(),
        refname,
        hash,
        status,
        data: signed,
    })
}
