// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    borrow::Cow,
    collections::{
        BTreeMap,
        BTreeSet,
        HashMap,
    },
    io,
    num::NonZeroUsize,
    ops::Deref,
};

use digest::Digest;
use log::warn;
use sha2::Sha512;
use signature::Verifier;

use super::{
    error,
    Alternates,
    ContentHash,
    Custom,
    DateTime,
    IdentityId,
    KeyId,
    KeySet,
    Metadata,
    Mirrors,
    Signature,
    Signed,
};
use crate::{
    git::Refname,
    json::canonical,
    str::Varchar,
};

pub const FMT_VERSION: FmtVersion = FmtVersion(super::FmtVersion::new(0, 2, 0));

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
pub struct FmtVersion(super::FmtVersion);

impl Deref for FmtVersion {
    type Target = super::FmtVersion;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for FmtVersion {
    fn default() -> Self {
        FMT_VERSION
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Roles {
    pub root: Role,
    pub snapshot: Role,
    pub mirrors: Role,
    pub branches: HashMap<Refname, Annotated>,
}

impl Roles {
    pub(crate) fn ids(&self) -> BTreeSet<IdentityId> {
        let Self {
            root: Role { ids: root, .. },
            snapshot: Role { ids: snapshot, .. },
            mirrors: Role { ids: mirrors, .. },
            branches,
        } = self;

        let mut ids = BTreeSet::new();
        ids.extend(root);
        ids.extend(snapshot);
        ids.extend(mirrors);
        ids.extend(branches.values().flat_map(|a| &a.role.ids));
        ids
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Role {
    pub ids: BTreeSet<IdentityId>,
    pub threshold: NonZeroUsize,
}

pub type Description = Varchar<String, 128>;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Annotated {
    #[serde(flatten)]
    pub role: Role,
    pub description: Description,
}

pub type Verified = super::Verified<Drop>;

#[derive(Clone, serde::Deserialize)]
pub struct Drop {
    #[serde(alias = "spec_version")]
    pub fmt_version: FmtVersion,
    #[serde(default = "Description::new")]
    pub description: Description,
    pub prev: Option<ContentHash>,
    pub roles: Roles,
    #[serde(default)]
    pub custom: Custom,
}

impl Drop {
    pub fn verified<'a, F, G>(
        self,
        signatures: &BTreeMap<KeyId, Signature>,
        find_prev: F,
        find_signer: G,
    ) -> Result<Verified, error::Verification>
    where
        F: FnMut(&ContentHash) -> io::Result<Signed<Self>>,
        G: FnMut(&IdentityId) -> io::Result<KeySet<'a>>,
    {
        self.verify(signatures, find_prev, find_signer)?;
        Ok(super::Verified(self))
    }

    pub fn verify<'a, F, G>(
        &self,
        signatures: &BTreeMap<KeyId, Signature>,
        mut find_prev: F,
        mut find_signer: G,
    ) -> Result<(), error::Verification>
    where
        F: FnMut(&ContentHash) -> io::Result<Signed<Self>>,
        G: FnMut(&IdentityId) -> io::Result<KeySet<'a>>,
    {
        use error::Verification::*;

        if !FMT_VERSION.is_compatible(&self.fmt_version) {
            return Err(IncompatibleVersion);
        }

        let canonical = self.canonicalise()?;
        let payload = Sha512::digest(&canonical);
        verify::AuthorisedSigners::from_ids(&self.roles.root.ids, &mut find_signer)?
            .verify_signatures(&payload, self.roles.root.threshold, signatures)?;
        if let Some(prev) = self.prev.as_ref().map(&mut find_prev).transpose()? {
            verify::AuthorisedSigners::from_ids(&prev.signed.roles.root.ids, &mut find_signer)?
                .verify_signatures(&payload, prev.signed.roles.root.threshold, signatures)?;
            return prev.signed.verify(&prev.signatures, find_prev, find_signer);
        }

        Ok(())
    }

    pub fn verify_mirrors<'a, F>(
        &self,
        mirrors: &Signed<Mirrors>,
        find_signer: F,
    ) -> Result<(), error::Verification>
    where
        F: FnMut(&IdentityId) -> io::Result<KeySet<'a>>,
    {
        use error::Verification::*;

        if let Some(deadline) = &mirrors.signed.expires {
            if deadline < &DateTime::now() {
                return Err(Expired);
            }
        }
        if !FMT_VERSION.is_compatible(&mirrors.signed.fmt_version) {
            return Err(IncompatibleVersion);
        }

        let payload = Sha512::digest(mirrors.signed.canonicalise()?);
        verify::AuthorisedSigners::from_ids(&self.roles.mirrors.ids, find_signer)?
            .verify_signatures(&payload, self.roles.mirrors.threshold, &mirrors.signatures)
    }

    pub fn verify_alternates<'a, F>(
        &self,
        alt: &Signed<Alternates>,
        find_signer: F,
    ) -> Result<(), error::Verification>
    where
        F: FnMut(&IdentityId) -> io::Result<KeySet<'a>>,
    {
        use error::Verification::*;

        if let Some(deadline) = &alt.signed.expires {
            if deadline < &DateTime::now() {
                return Err(Expired);
            }
        }
        if !FMT_VERSION.is_compatible(&alt.signed.fmt_version) {
            return Err(IncompatibleVersion);
        }

        let payload = Sha512::digest(alt.signed.canonicalise()?);
        verify::AuthorisedSigners::from_ids(&self.roles.mirrors.ids, find_signer)?
            .verify_signatures(&payload, self.roles.mirrors.threshold, &alt.signatures)
    }

    pub fn canonicalise(&self) -> Result<Vec<u8>, canonical::error::Canonicalise> {
        canonical::to_vec(Metadata::drop(self))
    }
}

impl From<Drop> for Cow<'static, Drop> {
    fn from(d: Drop) -> Self {
        Self::Owned(d)
    }
}

impl<'a> From<&'a Drop> for Cow<'a, Drop> {
    fn from(d: &'a Drop) -> Self {
        Self::Borrowed(d)
    }
}

impl serde::Serialize for Drop {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut s = serializer.serialize_struct("Drop", 5)?;
        let version_field = if self.fmt_version < FMT_VERSION {
            "spec_version"
        } else {
            "fmt_version"
        };
        s.serialize_field(version_field, &self.fmt_version)?;
        s.serialize_field("description", &self.description)?;
        s.serialize_field("prev", &self.prev)?;
        s.serialize_field("roles", &self.roles)?;
        s.serialize_field("custom", &self.custom)?;
        s.end()
    }
}

mod verify {
    use super::*;

    pub struct AuthorisedSigners<'a, 'b>(BTreeMap<&'a IdentityId, KeySet<'b>>);

    impl<'a, 'b> AuthorisedSigners<'a, 'b> {
        pub fn from_ids<F>(
            ids: &'a BTreeSet<IdentityId>,
            mut find_signer: F,
        ) -> Result<AuthorisedSigners<'a, 'b>, error::Verification>
        where
            F: FnMut(&IdentityId) -> io::Result<KeySet<'b>>,
        {
            let mut signers = BTreeMap::new();
            for id in ids {
                signers.insert(id, find_signer(id)?);
            }
            signers
                .values()
                .try_fold(BTreeSet::new(), |mut all_keys, keys| {
                    for key in keys.keys() {
                        if !all_keys.insert(key) {
                            return Err(error::Verification::DuplicateKey(*key));
                        }
                    }

                    Ok(all_keys)
                })?;

            Ok(Self(signers))
        }

        pub fn verify_signatures<'c, S>(
            &mut self,
            payload: &[u8],
            threshold: NonZeroUsize,
            signatures: S,
        ) -> Result<(), error::Verification>
        where
            S: IntoIterator<Item = (&'c KeyId, &'c Signature)>,
        {
            use error::Verification::SignatureThreshold;

            let mut need_signatures = threshold.get();
            for (key_id, signature) in signatures {
                if let Some(sig_id) = self.0.iter().find_map(|(id, keys)| {
                    #[allow(clippy::unnecessary_lazy_evaluations)]
                    keys.contains_key(key_id).then(|| *id)
                }) {
                    let key = self.0.remove(sig_id).unwrap().remove(key_id).unwrap();
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
    }
}
