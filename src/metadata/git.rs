// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    borrow::Cow,
    io,
};

use anyhow::anyhow;

use super::{
    drop,
    identity,
    Alternates,
    ContentHash,
    Drop,
    Identity,
    IdentityId,
    KeySet,
    Metadata,
    Mirrors,
    Signed,
};
use crate::{
    cmd,
    git::if_not_found_none,
    json,
};

pub const META_FILE_ALTERNATES: &str = "alternates.json";
pub const META_FILE_DROP: &str = "drop.json";
pub const META_FILE_ID: &str = "id.json";
pub const META_FILE_MIRRORS: &str = "mirrors.json";

pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    #[error("unexpected metadata type")]
    pub struct TypeMismatch;

    #[derive(Debug, Error)]
    #[error("{file} not found in tree")]
    pub struct FileNotFound {
        pub file: &'static str,
    }
}

pub struct GitMeta<T> {
    pub hash: ContentHash,
    pub signed: Signed<T>,
}

pub type GitIdentity = GitMeta<Identity>;
pub type GitDrop = GitMeta<Drop>;
pub type GitMirrors = GitMeta<Mirrors>;
pub type GitAlternates = GitMeta<Alternates>;

impl GitMeta<Drop> {
    pub fn verified<'a, F, G>(
        self,
        find_prev: F,
        find_signer: G,
    ) -> Result<drop::Verified, super::error::Verification>
    where
        F: FnMut(&ContentHash) -> io::Result<Signed<Drop>>,
        G: FnMut(&IdentityId) -> io::Result<KeySet<'a>>,
    {
        self.signed.verified(find_prev, find_signer)
    }
}

impl GitMeta<Identity> {
    pub fn verified<F>(self, find_prev: F) -> Result<identity::Verified, super::error::Verification>
    where
        F: FnMut(&ContentHash) -> io::Result<Signed<Identity>>,
    {
        self.signed.verified(find_prev)
    }
}

pub struct FromSearchPath<'a, T> {
    /// The repository (from the search path) the object was found in
    pub repo: &'a git2::Repository,
    pub meta: GitMeta<T>,
}

pub trait FromGit: Sized + Clone
where
    for<'a> Cow<'a, Self>: TryFrom<Metadata<'a>>,
{
    const METADATA_JSON: &'static str;

    fn from_blob(blob: &git2::Blob) -> crate::Result<GitMeta<Self>> {
        let hash = ContentHash::from(blob);
        let signed = json::from_blob::<Signed<Metadata>>(blob)?
            .fmap(Cow::<Self>::try_from)
            .transpose()
            .map_err(|_| error::TypeMismatch)?
            .fmap(Cow::into_owned);

        Ok(GitMeta { hash, signed })
    }

    fn from_tip<R: AsRef<str>>(
        repo: &git2::Repository,
        refname: R,
    ) -> crate::Result<GitMeta<Self>> {
        Self::from_reference(repo, &repo.find_reference(refname.as_ref())?)
    }

    fn from_reference(
        repo: &git2::Repository,
        reference: &git2::Reference,
    ) -> crate::Result<GitMeta<Self>> {
        Self::from_commit(repo, &reference.peel_to_commit()?)
    }

    fn from_commit(repo: &git2::Repository, commit: &git2::Commit) -> crate::Result<GitMeta<Self>> {
        Self::from_tree(repo, &commit.tree()?)
    }

    fn from_tree(repo: &git2::Repository, tree: &git2::Tree) -> crate::Result<GitMeta<Self>> {
        let entry = tree
            .get_name(Self::METADATA_JSON)
            .ok_or(error::FileNotFound {
                file: Self::METADATA_JSON,
            })?;
        let blob = entry.to_object(repo)?.peel_to_blob()?;

        Self::from_blob(&blob)
    }

    fn from_content_hash(
        repo: &git2::Repository,
        hash: &ContentHash,
    ) -> crate::Result<GitMeta<Self>> {
        let blob = repo.find_blob(hash.into())?;
        Self::from_blob(&blob)
    }

    fn from_search_path<R: AsRef<str>>(
        search_path: &[git2::Repository],
        refname: R,
    ) -> crate::Result<FromSearchPath<Self>> {
        let (repo, reference) = find_ref_in_path(search_path, refname.as_ref())?
            .ok_or_else(|| anyhow!("{} not found in search path", refname.as_ref()))?;
        Self::from_reference(repo, &reference).map(|meta| FromSearchPath { repo, meta })
    }
}

impl FromGit for Identity {
    const METADATA_JSON: &'static str = META_FILE_ID;
}

impl FromGit for Drop {
    const METADATA_JSON: &'static str = META_FILE_DROP;
}

impl FromGit for Mirrors {
    const METADATA_JSON: &'static str = META_FILE_MIRRORS;
}

impl FromGit for Alternates {
    const METADATA_JSON: &'static str = META_FILE_ALTERNATES;
}

pub fn find_parent<T>(
    repo: &git2::Repository,
) -> impl Fn(&ContentHash) -> io::Result<Signed<T>> + '_
where
    T: FromGit,
    for<'a> Cow<'a, T>: TryFrom<Metadata<'a>>,
{
    |hash| {
        T::from_content_hash(repo, hash)
            .map_err(as_io)
            .map(|meta| meta.signed)
    }
}

pub fn find_parent_in_tree<'a, T>(
    repo: &'a git2::Repository,
    tree: &'a git2::Tree<'a>,
) -> impl Fn(&ContentHash) -> io::Result<Signed<T>> + 'a
where
    T: FromGit,
    for<'b> Cow<'b, T>: TryFrom<Metadata<'b>>,
{
    fn go<T>(
        repo: &git2::Repository,
        tree: &git2::Tree,
        hash: &ContentHash,
    ) -> crate::Result<Signed<T>>
    where
        T: FromGit,
        for<'b> Cow<'b, T>: TryFrom<Metadata<'b>>,
    {
        let oid = git2::Oid::from(hash);
        let blob = tree
            .get_id(oid)
            .ok_or_else(|| anyhow!("parent {} not found in tree {}", oid, tree.id()))?
            .to_object(repo)?
            .into_blob()
            .map_err(|_| anyhow!("parent {} is not a file", oid))?;

        T::from_blob(&blob).map(|meta| meta.signed)
    }

    move |hash| go(repo, tree, hash).map_err(as_io)
}

pub fn find_ref_in_path<'a>(
    search_path: &'a [git2::Repository],
    name: &str,
) -> cmd::Result<Option<(&'a git2::Repository, git2::Reference<'a>)>> {
    for repo in search_path {
        let have_ref = if_not_found_none(repo.resolve_reference_from_short_name(name))?;
        if let Some(r) = have_ref {
            return Ok(Some((repo, r)));
        }
    }

    Ok(None)
}

fn as_io<E>(e: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, e)
}
