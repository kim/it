// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    borrow::Cow,
    collections::{
        BTreeMap,
        BTreeSet,
    },
    fmt,
    io,
    marker::PhantomData,
    num::NonZeroUsize,
    path::PathBuf,
    str::FromStr,
};

use anyhow::{
    anyhow,
    ensure,
};
use hex::FromHex;
use log::warn;
use sha2::{
    Digest,
    Sha256,
    Sha512,
};
use signature::Verifier;
use url::Url;

use super::{
    error,
    git::{
        find_parent_in_tree,
        FromGit,
        META_FILE_ID,
    },
    Ancestors,
    ContentHash,
    Custom,
    DateTime,
    Key,
    KeyId,
    KeySet,
    Metadata,
    Signature,
    Signed,
    SpecVersion,
};
use crate::{
    json::{
        self,
        canonical,
    },
    metadata::git::find_parent,
};

#[derive(
    Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct IdentityId(#[serde(with = "hex::serde")] [u8; 32]);

impl TryFrom<&Identity> for IdentityId {
    type Error = error::SigId;

    fn try_from(id: &Identity) -> Result<Self, Self::Error> {
        if id.prev.is_some() {
            return Err(error::SigId::NotRoot);
        }
        let digest = Sha256::digest(id.canonicalise()?);
        Ok(Self(digest.into()))
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl FromStr for IdentityId {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FromHex::from_hex(s).map(Self)
    }
}

impl TryFrom<String> for IdentityId {
    type Error = hex::FromHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        FromHex::from_hex(value).map(Self)
    }
}

pub struct Verified {
    id: IdentityId,
    cur: Identity,
}

impl Verified {
    pub fn id(&self) -> &IdentityId {
        &self.id
    }

    pub fn identity(&self) -> &Identity {
        &self.cur
    }

    pub fn into_parts(self) -> (IdentityId, Identity) {
        (self.id, self.cur)
    }

    /// `true` if signature is valid over message for any of the signer's
    /// _current_ set of keys
    pub fn did_sign<T: AsRef<[u8]>>(&self, msg: T, sig: &Signature) -> bool {
        self.cur
            .keys
            .values()
            .any(|key| key.verify(msg.as_ref(), sig).is_ok())
    }
}

impl AsRef<Identity> for Verified {
    fn as_ref(&self) -> &Identity {
        self.identity()
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Identity {
    pub spec_version: SpecVersion,
    pub prev: Option<ContentHash>,
    pub keys: KeySet<'static>,
    pub threshold: NonZeroUsize,
    pub mirrors: BTreeSet<Url>,
    pub expires: Option<DateTime>,
    #[serde(default)]
    pub custom: Custom,
}

impl Identity {
    pub fn verified<F>(
        self,
        signatures: &BTreeMap<KeyId, Signature>,
        find_prev: F,
    ) -> Result<Verified, error::Verification>
    where
        F: FnMut(&ContentHash) -> io::Result<Signed<Self>>,
    {
        let id = self.verify(signatures, find_prev)?;
        Ok(Verified { id, cur: self })
    }

    pub fn verify<F>(
        &self,
        signatures: &BTreeMap<KeyId, Signature>,
        find_prev: F,
    ) -> Result<IdentityId, error::Verification>
    where
        F: FnMut(&ContentHash) -> io::Result<Signed<Self>>,
    {
        use error::Verification::Expired;

        if let Some(deadline) = &self.expires {
            if deadline < &DateTime::now() {
                return Err(Expired);
            }
        }
        self.verify_tail(Cow::Borrowed(signatures), find_prev)
    }

    fn verify_tail<F>(
        &self,
        signatures: Cow<BTreeMap<KeyId, Signature>>,
        mut find_prev: F,
    ) -> Result<IdentityId, error::Verification>
    where
        F: FnMut(&ContentHash) -> io::Result<Signed<Self>>,
    {
        use error::Verification::IncompatibleSpecVersion;

        if !crate::SPEC_VERSION.is_compatible(&self.spec_version) {
            return Err(IncompatibleSpecVersion);
        }

        let canonical = self.canonicalise()?;
        let signed = Sha512::digest(&canonical);
        verify_signatures(&signed, self.threshold, signatures.iter(), &self.keys)?;
        if let Some(prev) = self.prev.as_ref().map(&mut find_prev).transpose()? {
            verify_signatures(
                &signed,
                prev.signed.threshold,
                signatures.iter(),
                &prev.signed.keys,
            )?;
            return prev
                .signed
                .verify_tail(Cow::Owned(prev.signatures), find_prev);
        }

        Ok(IdentityId(Sha256::digest(canonical).into()))
    }

    pub fn canonicalise(&self) -> Result<Vec<u8>, canonical::error::Canonicalise> {
        canonical::to_vec(Metadata::identity(self))
    }

    pub fn ancestors<F>(&self, find_prev: F) -> impl Iterator<Item = io::Result<Signed<Self>>>
    where
        F: FnMut(&ContentHash) -> io::Result<Signed<Self>>,
    {
        Ancestors {
            prev: self.prev.clone(),
            find_prev,
            _marker: PhantomData,
        }
    }

    pub fn has_ancestor<F>(&self, ancestor: &ContentHash, find_prev: F) -> io::Result<bool>
    where
        F: FnMut(&ContentHash) -> io::Result<Signed<Self>>,
    {
        match &self.prev {
            None => Ok(false),
            Some(parent) if parent == ancestor => Ok(true),
            Some(_) => {
                for prev in self.ancestors(find_prev) {
                    match &prev?.signed.prev {
                        None => return Ok(false),
                        Some(parent) if parent == ancestor => return Ok(true),
                        _ => continue,
                    }
                }

                Ok(false)
            },
        }
    }
}

impl From<Identity> for Cow<'static, Identity> {
    fn from(s: Identity) -> Self {
        Self::Owned(s)
    }
}

impl<'a> From<&'a Identity> for Cow<'a, Identity> {
    fn from(s: &'a Identity) -> Self {
        Self::Borrowed(s)
    }
}

fn verify_signatures<'a, S>(
    payload: &[u8],
    threshold: NonZeroUsize,
    signatures: S,
    keys: &BTreeMap<KeyId, Key>,
) -> Result<(), error::Verification>
where
    S: IntoIterator<Item = (&'a KeyId, &'a Signature)>,
{
    use error::Verification::SignatureThreshold;

    let mut need_signatures = threshold.get();
    for (key_id, signature) in signatures {
        if let Some(key) = keys.get(key_id) {
            if key.verify(payload, signature).is_ok() {
                need_signatures -= 1;
            } else {
                warn!("Bad signature by {key_id}");
            }

            if need_signatures == 0 {
                break;
            }
        }
    }
    if need_signatures > 0 {
        return Err(SignatureThreshold);
    }

    Ok(())
}

const FOLDED_HISTORY: &str = ".history";

pub fn fold_to_tree<'a>(
    repo: &'a git2::Repository,
    tree: &mut git2::TreeBuilder<'a>,
    Signed { signed, signatures }: Signed<Identity>,
) -> crate::Result<()> {
    use git2::FileMode::{
        Blob,
        Tree,
    };

    let meta = Signed {
        signed: Metadata::from(&signed),
        signatures,
    };
    tree.insert(META_FILE_ID, json::to_blob(repo, &meta)?, Blob.into())?;

    let mut history = {
        let existing = tree
            .get(FOLDED_HISTORY)?
            .map(|t| t.to_object(repo))
            .transpose()?;
        repo.treebuilder(existing.as_ref().and_then(git2::Object::as_tree))?
    };
    let mut parents = Vec::new();
    for parent in signed.ancestors(find_parent(repo)) {
        let meta = parent?.fmap(Metadata::from);
        let blob = json::to_blob(repo, &meta)?;
        parents.push(blob);
    }
    for (n, oid) in parents.into_iter().rev().enumerate() {
        history.insert(&format!("{n}.json"), oid, Blob.into())?;
    }
    tree.insert(FOLDED_HISTORY, history.write()?, Tree.into())?;

    Ok(())
}

pub fn find_in_tree(
    repo: &git2::Repository,
    root: &git2::Tree,
    id: &IdentityId,
) -> crate::Result<Verified> {
    let (id_path, hist_path) = {
        let base = PathBuf::from(id.to_string());
        (base.join(META_FILE_ID), base.join(FOLDED_HISTORY))
    };

    let blob = root
        .get_path(&id_path)?
        .to_object(repo)?
        .into_blob()
        .map_err(|_| anyhow!("{} is not a file", id_path.display()))?;
    let meta = Identity::from_blob(&blob)?.signed;
    let hist = root
        .get_path(&hist_path)?
        .to_object(repo)?
        .into_tree()
        .map_err(|_| anyhow!("{} is not a directory", hist_path.display()))?;

    let verified = meta
        .signed
        .verified(&meta.signatures, find_parent_in_tree(repo, &hist))?;
    ensure!(
        verified.id() == id,
        "ids don't match after verification: expected {} found {}",
        id,
        verified.id()
    );

    Ok(verified)
}
