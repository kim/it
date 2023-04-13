// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use core::{
    fmt,
    ops::Deref,
};
use std::{
    io::BufRead,
    str::FromStr,
};

use anyhow::{
    anyhow,
    bail,
};

use digest::{
    generic_array::GenericArray,
    typenum::U32,
    Digest,
};
use hex::FromHex;
use once_cell::sync::Lazy;
use sha2::Sha256;

use crate::{
    git::Refname,
    iter::IteratorExt,
};

mod traits;
pub use traits::{
    to_blob,
    to_tree,
    Seen,
};
use traits::{
    write_sharded,
    Blob,
};

mod bundle;
pub use bundle::Bundle;

mod error;
pub use error::FromTree;

pub mod iter;
pub mod notes;

pub mod record;
pub use record::{
    Record,
    Signature,
};

mod state;
pub use state::{
    merge_notes,
    unbundle,
    unbundled_ref,
    DropHead,
};

mod submit;
pub use submit::{
    AcceptArgs,
    AcceptOptions,
    Submission,
    ALLOWED_REFS,
    GLOB_HEADS,
    GLOB_IT_BUNDLES,
    GLOB_IT_IDS,
    GLOB_IT_TOPICS,
    GLOB_NOTES,
    GLOB_TAGS,
};

pub const MAX_LEN_BUNDLE: usize = 5_000_000;

pub const HTTP_HEADER_SIGNATURE: &str = "X-it-Signature";

pub const REF_HEADS_PATCHES: &str = "refs/heads/patches";

pub const REF_IT_BRANCHES: &str = "refs/it/branches";
pub const REF_IT_BUNDLES: &str = "refs/it/bundles";
pub const REF_IT_PATCHES: &str = "refs/it/patches";
pub const REF_IT_SEEN: &str = "refs/it/seen";
pub const REF_IT_TOPICS: &str = "refs/it/topics";

pub const BLOB_HEADS: &str = "heads";
pub const BLOB_META: &str = "record.json";

pub static TOPIC_MERGES: Lazy<Topic> = Lazy::new(|| Topic::hashed("merges"));
pub static TOPIC_SNAPSHOTS: Lazy<Topic> = Lazy::new(|| Topic::hashed("snapshots"));

#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Topic(#[serde(with = "hex::serde")] [u8; 32]);

impl Topic {
    const TRAILER_PREFIX: &str = "Re:";

    pub fn hashed<T: AsRef<[u8]>>(v: T) -> Self {
        Self(Sha256::digest(v).into())
    }

    pub fn from_commit(commit: &git2::Commit) -> crate::Result<Option<Self>> {
        commit
            .message_raw_bytes()
            .lines()
            .try_find_map(|line| -> crate::Result<Option<Topic>> {
                let val = line?
                    .strip_prefix(Self::TRAILER_PREFIX)
                    .map(|v| Self::from_hex(v.trim()))
                    .transpose()?;
                Ok(val)
            })
    }

    pub fn as_trailer(&self) -> String {
        format!("{} {}", Self::TRAILER_PREFIX, self)
    }

    pub fn from_refname(name: &str) -> crate::Result<Self> {
        let last = name
            .split('/')
            .next_back()
            .ok_or_else(|| anyhow!("invalid topic ref {name}"))?;
        Ok(Self::from_hex(last)?)
    }

    pub fn as_refname(&self) -> Refname {
        let name = format!("{}/{}", REF_IT_TOPICS, self);
        Refname::try_from(name).unwrap()
    }
}

impl FromHex for Topic {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        <[u8; 32]>::from_hex(hex).map(Self)
    }
}

impl FromStr for Topic {
    type Err = <Self as FromHex>::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl From<GenericArray<u8, U32>> for Topic {
    fn from(a: GenericArray<u8, U32>) -> Self {
        Self(a.into())
    }
}

/// Maps a [`Refname`] to the [`REF_IT_BRANCHES`] namespace
///
/// The [`Refname`] must be a branch, ie. start with 'refs/heads/'.
pub struct TrackingBranch(String);

impl TrackingBranch {
    pub fn master() -> Self {
        Self([REF_IT_BRANCHES, "master"].join("/"))
    }

    pub fn main() -> Self {
        Self([REF_IT_BRANCHES, "main"].join("/"))
    }

    pub fn into_refname(self) -> Refname {
        Refname::try_from(self.0).unwrap()
    }
}

impl Deref for TrackingBranch {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&Refname> for TrackingBranch {
    type Error = crate::Error;

    fn try_from(r: &Refname) -> Result<Self, Self::Error> {
        match r.strip_prefix("refs/heads/") {
            None => bail!("not a branch: {r}"),
            Some("patches") => bail!("reserved name: {r}"),
            Some(suf) => Ok(Self([REF_IT_BRANCHES, suf].join("/"))),
        }
    }
}
