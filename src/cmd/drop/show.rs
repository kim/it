// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    collections::BTreeMap,
    io,
    path::PathBuf,
};

use anyhow::Context;

use super::{
    Common,
    META_FILE_ALTERNATES,
    META_FILE_MIRRORS,
};
use crate::{
    cmd::{
        self,
        util::args::Refname,
        FromGit as _,
        GitAlternates,
        GitDrop,
        GitMirrors,
    },
    git,
    metadata::{
        self,
        ContentHash,
        IdentityId,
        KeySet,
    },
    patches::REF_IT_PATCHES,
};

#[derive(Debug, clap::Args)]
pub struct Show {
    #[clap(flatten)]
    common: Common,
    /// Name of the git ref holding the drop metadata history
    #[clap(
        long = "drop",
        value_parser,
        value_name = "REF",
        default_value_t = REF_IT_PATCHES.parse().unwrap(),
    )]
    drop_ref: Refname,
}

#[derive(serde::Serialize)]
pub struct Output {
    repo: PathBuf,
    refname: Refname,
    drop: Data<metadata::Drop>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mirrors: Option<Data<metadata::Mirrors>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alternates: Option<Data<metadata::Alternates>>,
}

#[derive(serde::Serialize)]
pub struct Data<T> {
    hash: ContentHash,
    status: Status,
    json: T,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    Verified,
    #[serde(with = "crate::serde::display")]
    Invalid(metadata::error::Verification),
}

impl From<Result<(), metadata::error::Verification>> for Status {
    fn from(r: Result<(), metadata::error::Verification>) -> Self {
        r.map(|()| Self::Verified).unwrap_or_else(Self::Invalid)
    }
}

pub fn show(args: Show) -> cmd::Result<Output> {
    let Common { git_dir, .. } = args.common;
    let drop_ref = args.drop_ref;

    let repo = git::repo::open(git_dir)?;

    let GitDrop {
        hash,
        signed: metadata::Signed {
            signed: drop,
            signatures,
        },
    } = metadata::Drop::from_tip(&repo, &drop_ref)?;

    let mut signer_cache = SignerCache::new(&repo, &drop_ref)?;
    let status = drop
        .verify(
            &signatures,
            cmd::find_parent(&repo),
            find_signer(&mut signer_cache),
        )
        .into();

    let mut mirrors = None;
    let mut alternates = None;

    let tree = repo.find_reference(&drop_ref)?.peel_to_commit()?.tree()?;
    if let Some(entry) = tree.get_name(META_FILE_MIRRORS) {
        let blob = entry.to_object(&repo)?.peel_to_blob()?;
        let GitMirrors { hash, signed } = metadata::Mirrors::from_blob(&blob)?;
        let status = drop
            .verify_mirrors(&signed, find_signer(&mut signer_cache))
            .into();

        mirrors = Some(Data {
            hash,
            status,
            json: signed.signed,
        });
    }

    if let Some(entry) = tree.get_name(META_FILE_ALTERNATES) {
        let blob = entry.to_object(&repo)?.peel_to_blob()?;
        let GitAlternates { hash, signed } = metadata::Alternates::from_blob(&blob)?;
        let status = drop
            .verify_alternates(&signed, find_signer(&mut signer_cache))
            .into();

        alternates = Some(Data {
            hash,
            status,
            json: signed.signed,
        });
    }

    Ok(Output {
        repo: repo.path().to_owned(),
        refname: drop_ref,
        drop: Data {
            hash,
            status,
            json: drop,
        },
        mirrors,
        alternates,
    })
}

struct SignerCache<'a> {
    repo: &'a git2::Repository,
    root: git2::Tree<'a>,
    keys: BTreeMap<IdentityId, KeySet<'static>>,
}

impl<'a> SignerCache<'a> {
    pub(self) fn new(repo: &'a git2::Repository, refname: &Refname) -> git::Result<Self> {
        let root = {
            let id = repo
                .find_reference(refname)?
                .peel_to_tree()?
                .get_name("ids")
                .ok_or_else(|| {
                    git2::Error::new(
                        git2::ErrorCode::NotFound,
                        git2::ErrorClass::Tree,
                        "'ids' tree not found",
                    )
                })?
                .id();
            repo.find_tree(id)?
        };
        let keys = BTreeMap::new();

        Ok(Self { repo, root, keys })
    }
}

fn find_signer<'a>(
    cache: &'a mut SignerCache,
) -> impl FnMut(&IdentityId) -> io::Result<KeySet<'static>> + 'a {
    fn go(
        repo: &git2::Repository,
        root: &git2::Tree,
        keys: &mut BTreeMap<IdentityId, KeySet<'static>>,
        id: &IdentityId,
    ) -> cmd::Result<KeySet<'static>> {
        match keys.get(id) {
            Some(keys) => Ok(keys.clone()),
            None => {
                let (id, verified) = metadata::identity::find_in_tree(repo, root, id)
                    .with_context(|| format!("identity {id} failed to verify"))?
                    .into_parts();
                keys.insert(id, verified.keys.clone());
                Ok(verified.keys)
            },
        }
    }

    |id| go(cache.repo, &cache.root, &mut cache.keys, id).map_err(as_io)
}

fn as_io<E>(e: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, e)
}
