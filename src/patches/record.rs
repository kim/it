// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use core::ops::Deref;
use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    fmt,
    io::{
        self,
        BufRead,
    },
    path::{
        Path,
        PathBuf,
    },
    str::FromStr,
};

use anyhow::{
    anyhow,
    bail,
    ensure,
    Context,
};
use digest::Digest;
use hex::{
    FromHex,
    ToHex,
};
use sha2::Sha256;
use signature::{
    Signature as _,
    Verifier,
};

use super::{
    traits::{
        to_tree,
        BlobData,
        Foldable,
        TreeData,
    },
    write_sharded,
    Blob,
    Bundle,
    Topic,
    BLOB_HEADS,
    BLOB_META,
    HTTP_HEADER_SIGNATURE,
    TOPIC_MERGES,
    TOPIC_SNAPSHOTS,
};
use crate::{
    bundle,
    error::NotFound,
    git::{
        self,
        Refname,
    },
    iter::IteratorExt,
    metadata::{
        self,
        identity,
        ContentHash,
    },
};

#[derive(Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Heads(#[serde(with = "hex::serde")] [u8; 32]);

impl Heads {
    const TRAILER_PREFIX: &str = "Patch:";

    pub fn from_commit(commit: &git2::Commit) -> crate::Result<Option<Self>> {
        commit.message_raw_bytes().lines().try_find_map(|line| {
            line?
                .strip_prefix(Self::TRAILER_PREFIX)
                .map(|s| Self::from_str(s.trim()).map_err(crate::Error::from))
                .transpose()
        })
    }

    pub fn as_trailer(&self) -> String {
        format!("{} {}", Self::TRAILER_PREFIX, self)
    }
}

impl Deref for Heads {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Heads {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&bundle::Header> for Heads {
    fn from(h: &bundle::Header) -> Self {
        let tips = h.references.values().collect::<BTreeSet<_>>();
        let mut hasher = Sha256::new();
        for sha in tips {
            hasher.update(sha.as_bytes());
        }
        Self(hasher.finalize().into())
    }
}

impl TryFrom<&git2::Commit<'_>> for Heads {
    type Error = crate::Error;

    fn try_from(commit: &git2::Commit) -> Result<Self, Self::Error> {
        Self::from_commit(commit)?.ok_or_else(|| {
            anyhow!(NotFound {
                what: "patch trailer",
                whence: format!("commit {}", commit.id()),
            })
        })
    }
}

impl FromStr for Heads {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl FromHex for Heads {
    type Error = hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        <[u8; 32]>::from_hex(hex).map(Self)
    }
}

impl fmt::Display for Heads {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Heads {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl BlobData for Heads {
    type Error = <[u8; 32] as FromHex>::Error;

    const MAX_BYTES: usize = 64;

    fn from_blob(data: &[u8]) -> Result<Self, Self::Error> {
        Self::from_hex(data)
    }

    fn write_blob<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.encode_hex::<String>().as_bytes())
    }
}

impl TreeData for Heads {
    const BLOB_NAME: &'static str = BLOB_HEADS;
}

impl Foldable for Heads {
    fn folded_name(&self) -> String {
        self.encode_hex()
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Signature {
    pub signer: metadata::ContentHash,
    pub signature: metadata::Signature,
}

impl From<Signature> for tiny_http::Header {
    fn from(s: Signature) -> Self {
        let value = format!(
            "s1={}; s2={}; sd={}",
            hex::encode(s.signer.sha1),
            hex::encode(s.signer.sha2),
            hex::encode(s.signature.as_ref())
        );

        Self::from_bytes(HTTP_HEADER_SIGNATURE.as_bytes(), value).unwrap()
    }
}

impl TryFrom<&tiny_http::Header> for Signature {
    type Error = crate::Error;

    fn try_from(hdr: &tiny_http::Header) -> Result<Self, Self::Error> {
        ensure!(
            hdr.field.equiv(HTTP_HEADER_SIGNATURE),
            "not a {HTTP_HEADER_SIGNATURE} header"
        );

        let mut sha1: Option<[u8; 20]> = None;
        let mut sha2: Option<[u8; 32]> = None;
        let mut signature = None;
        for part in hdr.value.as_str().split(';') {
            match part.trim().split_at(2) {
                ("s1", val) => {
                    let bytes = <[u8; 20]>::from_hex(val)?;
                    sha1 = Some(bytes);
                },
                ("s2", val) => {
                    let bytes = <[u8; 32]>::from_hex(val)?;
                    sha2 = Some(bytes);
                },
                ("sd", val) => {
                    let bytes = hex::decode(val)?;
                    signature = Some(metadata::Signature::from_bytes(&bytes)?);
                },

                _ => continue,
            }
        }

        let sha1 = sha1.ok_or_else(|| anyhow!("missing sha1 identity content hash"))?;
        let sha2 = sha2.ok_or_else(|| anyhow!("missing sha2 identity content hash"))?;
        let signature = signature.ok_or_else(|| anyhow!("missing signature bytes"))?;

        Ok(Self {
            signer: metadata::ContentHash { sha1, sha2 },
            signature,
        })
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Meta {
    pub bundle: BundleInfo,
    pub signature: Signature,
}

impl BlobData for Meta {
    type Error = serde_json::Error;

    const MAX_BYTES: usize = 100_000;

    fn from_blob(data: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(data)
    }

    fn write_blob<W: io::Write>(&self, writer: W) -> io::Result<()> {
        serde_json::to_writer_pretty(writer, self).map_err(Into::into)
    }
}

impl TreeData for Meta {
    const BLOB_NAME: &'static str = BLOB_META;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encryption {
    Age,
    Gpg,
}

impl Encryption {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Age => "age",
            Self::Gpg => "gpg",
        }
    }
}

impl FromStr for Encryption {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BundleInfo {
    #[serde(flatten)]
    pub info: bundle::Info,
    pub prerequisites: BTreeSet<bundle::ObjectId>,
    pub references: BTreeMap<Refname, bundle::ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Encryption>,
}

impl BundleInfo {
    pub fn as_expect(&self) -> bundle::Expect {
        bundle::Expect::from(&self.info)
    }
}

impl From<&Bundle> for BundleInfo {
    fn from(bundle: &Bundle) -> Self {
        let (prerequisites, references) = {
            let h = bundle.header();
            (h.prerequisites.clone(), h.references.clone())
        };
        Self {
            info: bundle.info().clone(),
            prerequisites,
            references,
            encryption: bundle.encryption(),
        }
    }
}

/// Log record of a patch submission
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Record {
    pub topic: Topic,
    pub heads: Heads,
    pub meta: Meta,
}

impl Record {
    pub fn from_commit<'a>(
        repo: &'a git2::Repository,
        commit: &git2::Commit<'a>,
    ) -> crate::Result<Self> {
        let topic = Topic::from_commit(commit)?.ok_or_else(|| crate::error::NotFound {
            what: "topic",
            whence: format!("message of commit {}", commit.id()),
        })?;

        let tree = commit.tree()?;

        let mut heads: Option<Heads> = None;
        let mut meta: Option<Meta> = None;

        for entry in &tree {
            match entry.name() {
                Some(BLOB_HEADS) => {
                    heads = Some(Blob::<Heads>::from_entry(repo, entry)?.content);
                },
                Some(BLOB_META) => {
                    meta = Some(Blob::<Meta>::from_entry(repo, entry)?.content);
                },

                None | Some(_) => continue,
            }
        }

        let whence = || format!("tree {}", tree.id());
        let heads = heads.ok_or_else(|| crate::error::NotFound {
            what: BLOB_HEADS,
            whence: whence(),
        })?;
        let meta = meta.ok_or_else(|| crate::error::NotFound {
            what: BLOB_META,
            whence: whence(),
        })?;

        Ok(Self { topic, heads, meta })
    }

    pub fn commit<S>(
        &self,
        signer: &mut S,
        repo: &git2::Repository,
        ids: &git2::Tree,
        parent: Option<&git2::Commit>,
        seen: Option<&mut git2::TreeBuilder>,
    ) -> crate::Result<git2::Oid>
    where
        S: crate::keys::Signer,
    {
        let tree = {
            let mut tb = repo.treebuilder(parent.map(|p| p.tree()).transpose()?.as_ref())?;
            tb.insert("ids", ids.id(), git2::FileMode::Tree.into())?;
            to_tree(repo, &mut tb, &self.heads)?;
            to_tree(repo, &mut tb, &self.meta)?;
            repo.find_tree(tb.write()?)?
        };
        let oid = git::commit_signed(
            signer,
            repo,
            self.topic.as_trailer(),
            &tree,
            &parent.into_iter().collect::<Vec<_>>(),
        )?;

        if let Some(seen) = seen {
            write_sharded(
                repo,
                seen,
                &self.heads,
                tree.get_name(Heads::BLOB_NAME)
                    .expect("heads blob written above")
                    .id(),
            )?;
        }

        Ok(oid)
    }

    pub fn signed_part(&self) -> [u8; 32] {
        *self.heads
    }

    pub fn verify_signature<F>(&self, mut find_id: F) -> crate::Result<()>
    where
        F: FnMut(&ContentHash) -> crate::Result<identity::Verified>,
    {
        let signed_data = self.signed_part();
        let addr = &self.meta.signature.signer;
        let signature = &self.meta.signature.signature;
        let id =
            find_id(addr).with_context(|| format!("invalid or non-existent id at {:?}", addr))?;
        for key in id.identity().keys.values() {
            if key.verify(&signed_data, signature).is_ok() {
                return Ok(());
            }
        }
        bail!("signature key not in id at {:?}", addr);
    }

    pub fn bundle_info(&self) -> &BundleInfo {
        &self.meta.bundle
    }

    pub fn bundle_hash(&self) -> &bundle::Hash {
        &self.meta.bundle.info.hash
    }

    pub fn bundle_path(&self, prefix: &Path) -> PathBuf {
        let mut p = prefix.join(self.bundle_hash().to_string());
        p.set_extension(bundle::FILE_EXTENSION);
        p
    }

    pub fn is_encrypted(&self) -> bool {
        self.meta.bundle.encryption.is_some()
    }

    pub fn is_snapshot(&self) -> bool {
        self.topic == *TOPIC_SNAPSHOTS
    }

    pub fn is_mergepoint(&self) -> bool {
        self.topic == *TOPIC_MERGES
    }

    /// Remove traces of a record from the given tree
    pub(crate) fn remove_from(tree: &mut git2::TreeBuilder) -> crate::Result<()> {
        if tree.get(Heads::BLOB_NAME)?.is_some() {
            tree.remove(Heads::BLOB_NAME)?;
        }
        if tree.get(Meta::BLOB_NAME)?.is_some() {
            tree.remove(Meta::BLOB_NAME)?;
        }

        Ok(())
    }
}
