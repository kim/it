// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    io,
    path::{
        Path,
        PathBuf,
    },
};

use super::error;
use crate::git::{
    self,
    if_not_found_none,
};

pub trait BlobData: Sized {
    type Error;

    const MAX_BYTES: usize;

    fn from_blob(data: &[u8]) -> Result<Self, Self::Error>;
    fn write_blob<W: io::Write>(&self, writer: W) -> io::Result<()>;
}

pub trait TreeData: BlobData {
    const BLOB_NAME: &'static str;
}

pub struct Blob<T> {
    pub oid: git2::Oid,
    pub content: T,
}

impl<T> Blob<T>
where
    T: TreeData,
    T::Error: Into<crate::Error>,
{
    pub fn from_tree<'a>(
        repo: &'a git2::Repository,
        tree: &git2::Tree<'a>,
    ) -> Result<Blob<T>, error::FromTree> {
        use error::FromTree::NotFound;

        let entry = tree
            .get_name(T::BLOB_NAME)
            .ok_or(NotFound { name: T::BLOB_NAME })?;
        Self::from_entry(repo, entry)
    }

    pub fn from_entry<'a>(
        repo: &'a git2::Repository,
        entry: git2::TreeEntry<'a>,
    ) -> Result<Self, error::FromTree> {
        use error::FromTree::{
            BlobSize,
            TypeConversion,
            TypeMismatch,
        };

        let blob = entry
            .to_object(repo)?
            .into_blob()
            .map_err(|obj| TypeMismatch {
                name: T::BLOB_NAME,
                kind: obj.kind(),
            })?;
        let sz = blob.size();
        if sz > T::MAX_BYTES {
            return Err(BlobSize {
                max: T::MAX_BYTES,
                found: sz,
            });
        }
        let content = T::from_blob(blob.content())
            .map_err(Into::into)
            .map_err(TypeConversion)?;

        Ok(Self {
            oid: entry.id(),
            content,
        })
    }
}

pub trait Foldable {
    fn folded_name(&self) -> String;
}

pub trait Seen {
    fn in_odb(&self, odb: &git2::Odb) -> git::Result<bool>;
    fn in_tree(&self, tree: &git2::Tree) -> git::Result<bool>;
}

impl<T> Seen for T
where
    T: BlobData + Foldable,
{
    fn in_odb(&self, odb: &git2::Odb) -> git::Result<bool> {
        let hash = blob_hash(self)?;
        Ok(odb.exists(hash))
    }

    fn in_tree(&self, tree: &git2::Tree) -> git::Result<bool> {
        let path = shard_path(&self.folded_name());
        Ok(if_not_found_none(tree.get_path(&path))?.is_some())
    }
}

pub fn to_tree<T: TreeData>(
    repo: &git2::Repository,
    tree: &mut git2::TreeBuilder,
    data: &T,
) -> git::Result<()> {
    tree.insert(
        T::BLOB_NAME,
        to_blob(repo, data)?,
        git2::FileMode::Blob.into(),
    )?;
    Ok(())
}

pub fn to_blob<T: BlobData>(repo: &git2::Repository, data: &T) -> git::Result<git2::Oid> {
    let mut writer = repo.blob_writer(None)?;
    data.write_blob(&mut writer).map_err(|e| {
        git2::Error::new(
            git2::ErrorCode::GenericError,
            git2::ErrorClass::Object,
            e.to_string(),
        )
    })?;
    writer.commit()
}

pub fn blob_hash<T: BlobData>(data: &T) -> git::Result<git2::Oid> {
    let mut buf = Vec::new();
    data.write_blob(&mut buf).unwrap();
    git::blob_hash(&buf)
}

pub fn write_sharded<F: Foldable>(
    repo: &git2::Repository,
    root: &mut git2::TreeBuilder,
    item: &F,
    blob: git2::Oid,
) -> git::Result<()> {
    let name = item.folded_name();
    let (pre, suf) = name.split_at(2);
    let shard = root
        .get(pre)?
        .map(|entry| entry.to_object(repo))
        .transpose()?;
    let mut sub = repo.treebuilder(shard.as_ref().and_then(git2::Object::as_tree))?;
    sub.insert(suf, blob, git2::FileMode::Blob.into())?;
    root.insert(pre, sub.write()?, git2::FileMode::Tree.into())?;

    Ok(())
}

pub fn shard_path(name: &str) -> PathBuf {
    let (pre, suf) = name.split_at(2);
    Path::new(pre).join(suf)
}
