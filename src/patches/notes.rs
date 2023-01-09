// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    cmp,
    collections::BTreeMap,
    convert::Infallible,
    io,
    ops::Range,
};

use super::{
    error,
    traits::{
        Blob,
        BlobData,
        TreeData,
    },
};
use crate::{
    bundle::ObjectId,
    git::Refname,
};

#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum Note {
    Simple(Simple),
    Automerge(Automerge),
}

impl Note {
    pub fn from_tree<'a>(repo: &'a git2::Repository, tree: &git2::Tree<'a>) -> crate::Result<Self> {
        Blob::<Simple>::from_tree(repo, tree)
            .map(|Blob { content, .. }| Self::Simple(content))
            .or_else(|e| match e {
                error::FromTree::NotFound { .. } => {
                    let Blob { content, .. } = Blob::<Automerge>::from_tree(repo, tree)?;
                    Ok(Self::Automerge(content))
                },
                x => Err(x.into()),
            })
    }
}

#[derive(serde::Serialize)]
pub struct Automerge(Vec<u8>);

impl BlobData for Automerge {
    type Error = Infallible;

    const MAX_BYTES: usize = 1_000_000;

    fn from_blob(data: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(data.to_vec()))
    }

    fn write_blob<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl TreeData for Automerge {
    const BLOB_NAME: &'static str = "c";
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Simple {
    Known(Predef),
    Unknown(serde_json::Map<String, serde_json::Value>),
}

impl Simple {
    pub fn new(message: String) -> Self {
        Self::basic(message)
    }

    pub fn basic(message: String) -> Self {
        Self::Known(Predef::Basic { message })
    }

    pub fn checkpoint(
        kind: CheckpointKind,
        refs: BTreeMap<Refname, ObjectId>,
        message: Option<String>,
    ) -> Self {
        Self::Known(Predef::Checkpoint {
            kind,
            refs,
            message,
        })
    }

    pub fn from_commit(repo: &git2::Repository, commit: &git2::Commit) -> crate::Result<Self> {
        let tree = commit.tree()?;
        let blob = Blob::from_tree(repo, &tree)?;

        Ok(blob.content)
    }

    pub fn subject(&self) -> Option<&str> {
        match self {
            Self::Known(k) => k.subject(),
            _ => None,
        }
    }

    pub fn is_checkpoint(&self) -> bool {
        matches!(self, Self::Known(Predef::Checkpoint { .. }))
    }

    pub fn checkpoint_kind(&self) -> Option<&CheckpointKind> {
        match self {
            Self::Known(Predef::Checkpoint { kind, .. }) => Some(kind),
            _ => None,
        }
    }
}

impl BlobData for Simple {
    type Error = serde_json::Error;

    const MAX_BYTES: usize = 1_000_000;

    fn from_blob(data: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(data)
    }

    fn write_blob<W: io::Write>(&self, writer: W) -> io::Result<()> {
        serde_json::to_writer_pretty(writer, self).map_err(Into::into)
    }
}

impl TreeData for Simple {
    const BLOB_NAME: &'static str = "m";
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "_type")]
pub enum Predef {
    #[serde(rename = "eagain.io/it/notes/basic")]
    Basic { message: String },
    #[serde(rename = "eagain.io/it/notes/code-comment")]
    CodeComment { loc: SourceLoc, message: String },
    #[serde(rename = "eagain.io/it/notes/checkpoint")]
    Checkpoint {
        kind: CheckpointKind,
        refs: BTreeMap<Refname, ObjectId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
}

impl Predef {
    pub fn subject(&self) -> Option<&str> {
        let msg = match self {
            Self::Basic { message } | Self::CodeComment { message, .. } => Some(message),
            Self::Checkpoint { message, .. } => message.as_ref(),
        }?;
        let line = msg.lines().next()?;
        let subj = &line[..cmp::min(72, line.len())];

        (!subj.is_empty()).then_some(subj)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SourceLoc {
    #[serde(with = "crate::git::serde::oid")]
    pub file: git2::Oid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<Range<usize>>,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckpointKind {
    Merge,
    Snapshot,
}
