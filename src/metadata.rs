// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use core::{
    convert::TryFrom,
    fmt,
    ops::Deref,
    str::FromStr,
};
use std::{
    borrow::Cow,
    collections::BTreeMap,
    io,
    marker::PhantomData,
    ops::DerefMut,
};

use digest::Digest;
use serde::ser::SerializeSeq;
use sha2::Sha512;
use time::{
    Duration,
    OffsetDateTime,
    UtcOffset,
};
use versions::SemVer;

use crate::{
    git::blob_hash_sha2,
    json::canonical,
    keys::{
        Signer,
        VerificationKey,
    },
    ssh,
};

pub mod drop;
pub use drop::Drop;

pub mod error;
pub mod git;

mod mirrors;
pub use mirrors::{
    Alternates,
    Mirrors,
};

pub mod identity;
pub use identity::{
    Identity,
    IdentityId,
};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct FmtVersion(SemVer);

impl FmtVersion {
    const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self(SemVer {
            major,
            minor,
            patch,
            pre_rel: None,
            meta: None,
        })
    }

    /// This spec version is compatible if its major version is greater than or
    /// equal to `other`'s
    pub fn is_compatible(&self, other: &Self) -> bool {
        self.0.major >= other.major()
    }

    pub fn major(&self) -> u32 {
        self.0.major
    }

    pub fn minor(&self) -> u32 {
        self.0.minor
    }

    pub fn patch(&self) -> u32 {
        self.0.patch
    }
}

impl fmt::Display for FmtVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for FmtVersion {
    type Err = <SemVer as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SemVer::from_str(s).map(Self)
    }
}

impl<'a> TryFrom<&'a str> for FmtVersion {
    type Error = <SemVer as TryFrom<&'a str>>::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        SemVer::try_from(value).map(Self)
    }
}

impl AsRef<SemVer> for FmtVersion {
    fn as_ref(&self) -> &SemVer {
        &self.0
    }
}

impl serde::Serialize for FmtVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for FmtVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;
        Self::try_from(s).map_err(|_| serde::de::Error::custom("invalid version string"))
    }
}

pub type Custom = serde_json::Map<String, serde_json::Value>;

#[derive(
    Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct KeyId(#[serde(with = "hex::serde")] [u8; 32]);

impl KeyId {
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&Key<'_>> for KeyId {
    fn from(key: &Key<'_>) -> Self {
        Self::from(&key.0)
    }
}

impl From<Key<'_>> for KeyId {
    fn from(key: Key<'_>) -> Self {
        Self::from(key.0)
    }
}

impl From<&VerificationKey<'_>> for KeyId {
    fn from(key: &VerificationKey<'_>) -> Self {
        Self(key.sha256())
    }
}

impl From<VerificationKey<'_>> for KeyId {
    fn from(key: VerificationKey<'_>) -> Self {
        Self(key.sha256())
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyId").field(&hex::encode(self.0)).finish()
    }
}

#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ContentHash {
    #[serde(with = "hex::serde")]
    pub sha1: [u8; 20],
    #[serde(with = "hex::serde")]
    pub sha2: [u8; 32],
}

impl ContentHash {
    pub fn as_oid(&self) -> git2::Oid {
        self.into()
    }
}

impl From<&git2::Blob<'_>> for ContentHash {
    fn from(blob: &git2::Blob) -> Self {
        let sha1 = blob
            .id()
            .as_bytes()
            .try_into()
            .expect("libgit2 to support only sha1 oids");
        let sha2 = blob_hash_sha2(blob.content());

        Self { sha1, sha2 }
    }
}

impl From<&ContentHash> for git2::Oid {
    fn from(ContentHash { sha1, .. }: &ContentHash) -> Self {
        Self::from_bytes(sha1).expect("20 bytes are a valid git2::Oid")
    }
}

impl PartialEq<git2::Oid> for ContentHash {
    fn eq(&self, other: &git2::Oid) -> bool {
        self.sha1.as_slice() == other.as_bytes()
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ContentHash")
            .field("sha1", &hex::encode(self.sha1))
            .field("sha2", &hex::encode(self.sha2))
            .finish()
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&hex::encode(self.sha1))
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
pub struct DateTime(#[serde(with = "time::serde::rfc3339")] OffsetDateTime);

impl DateTime {
    pub fn now() -> Self {
        Self(time::OffsetDateTime::now_utc())
    }

    pub const fn checked_add(self, duration: Duration) -> Option<Self> {
        // `map` is not const yet
        match self.0.checked_add(duration) {
            None => None,
            Some(x) => Some(Self(x)),
        }
    }
}

impl FromStr for DateTime {
    type Err = time::error::Parse;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map(|dt| dt.to_offset(UtcOffset::UTC))
            .map(Self)
    }
}

impl Deref for DateTime {
    type Target = time::OffsetDateTime;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "_type")]
pub enum Metadata<'a> {
    #[serde(rename = "eagain.io/it/identity")]
    Identity(Cow<'a, Identity>),
    #[serde(rename = "eagain.io/it/drop")]
    Drop(Cow<'a, Drop>),
    #[serde(rename = "eagain.io/it/mirrors")]
    Mirrors(Cow<'a, Mirrors>),
    #[serde(rename = "eagain.io/it/alternates")]
    Alternates(Cow<'a, Alternates>),
}

impl<'a> Metadata<'a> {
    pub fn identity<T>(s: T) -> Self
    where
        T: Into<Cow<'a, Identity>>,
    {
        Self::Identity(s.into())
    }

    pub fn drop<T>(d: T) -> Self
    where
        T: Into<Cow<'a, Drop>>,
    {
        Self::Drop(d.into())
    }

    pub fn mirrors<T>(a: T) -> Self
    where
        T: Into<Cow<'a, Mirrors>>,
    {
        Self::Mirrors(a.into())
    }

    pub fn alternates<T>(a: T) -> Self
    where
        T: Into<Cow<'a, Alternates>>,
    {
        Self::Alternates(a.into())
    }

    pub fn sign<'b, I, S>(self, keys: I) -> crate::Result<Signed<Self>>
    where
        I: IntoIterator<Item = &'b mut S>,
        S: Signer + ?Sized + 'b,
    {
        let payload = Sha512::digest(canonical::to_vec(&self)?);
        let signatures = keys
            .into_iter()
            .map(|signer| {
                let keyid = KeyId::from(signer.ident());
                let sig = signer.sign(&payload)?;
                Ok::<_, crate::Error>((keyid, Signature::from(sig)))
            })
            .collect::<Result<_, _>>()?;

        Ok(Signed {
            signed: self,
            signatures,
        })
    }
}

impl From<Identity> for Metadata<'static> {
    fn from(s: Identity) -> Self {
        Self::identity(s)
    }
}

impl<'a> From<&'a Identity> for Metadata<'a> {
    fn from(s: &'a Identity) -> Self {
        Self::identity(s)
    }
}

impl From<Drop> for Metadata<'static> {
    fn from(d: Drop) -> Self {
        Self::drop(d)
    }
}

impl<'a> From<&'a Drop> for Metadata<'a> {
    fn from(d: &'a Drop) -> Self {
        Self::drop(d)
    }
}

impl From<Mirrors> for Metadata<'static> {
    fn from(m: Mirrors) -> Self {
        Self::mirrors(m)
    }
}

impl<'a> From<&'a Mirrors> for Metadata<'a> {
    fn from(m: &'a Mirrors) -> Self {
        Self::mirrors(m)
    }
}

impl From<Alternates> for Metadata<'static> {
    fn from(a: Alternates) -> Self {
        Self::alternates(a)
    }
}

impl<'a> From<&'a Alternates> for Metadata<'a> {
    fn from(a: &'a Alternates) -> Self {
        Self::alternates(a)
    }
}

impl<'a> TryFrom<Metadata<'a>> for Cow<'a, Identity> {
    type Error = Metadata<'a>;

    fn try_from(value: Metadata<'a>) -> Result<Self, Self::Error> {
        match value {
            Metadata::Identity(inner) => Ok(inner),
            _ => Err(value),
        }
    }
}

impl<'a> TryFrom<Metadata<'a>> for Cow<'a, Drop> {
    type Error = Metadata<'a>;

    fn try_from(value: Metadata<'a>) -> Result<Self, Self::Error> {
        match value {
            Metadata::Drop(inner) => Ok(inner),
            _ => Err(value),
        }
    }
}

impl<'a> TryFrom<Metadata<'a>> for Cow<'a, Mirrors> {
    type Error = Metadata<'a>;

    fn try_from(value: Metadata<'a>) -> Result<Self, Self::Error> {
        match value {
            Metadata::Mirrors(inner) => Ok(inner),
            _ => Err(value),
        }
    }
}

impl<'a> TryFrom<Metadata<'a>> for Cow<'a, Alternates> {
    type Error = Metadata<'a>;

    fn try_from(value: Metadata<'a>) -> Result<Self, Self::Error> {
        match value {
            Metadata::Alternates(inner) => Ok(inner),
            _ => Err(value),
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Signed<T> {
    pub signed: T,
    pub signatures: BTreeMap<KeyId, Signature>,
}

impl<T> Signed<T> {
    pub fn fmap<U, F>(self, f: F) -> Signed<U>
    where
        F: FnOnce(T) -> U,
    {
        Signed {
            signed: f(self.signed),
            signatures: self.signatures,
        }
    }
}

impl<T, E> Signed<Result<T, E>> {
    pub fn transpose(self) -> Result<Signed<T>, E> {
        let Self { signed, signatures } = self;
        signed.map(|signed| Signed { signed, signatures })
    }
}

impl<T: HasPrev> Signed<T> {
    pub fn ancestors<F>(&self, find_prev: F) -> impl Iterator<Item = io::Result<Self>>
    where
        F: FnMut(&ContentHash) -> io::Result<Self>,
    {
        Ancestors {
            prev: self.signed.prev().cloned(),
            find_prev,
            _marker: PhantomData,
        }
    }

    pub fn has_ancestor<F>(&self, ancestor: &ContentHash, find_prev: F) -> io::Result<bool>
    where
        F: FnMut(&ContentHash) -> io::Result<Self>,
    {
        match self.signed.prev() {
            None => Ok(false),
            Some(parent) if parent == ancestor => Ok(true),
            Some(_) => {
                for prev in self.ancestors(find_prev) {
                    match prev?.signed.prev() {
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

impl Signed<Drop> {
    pub fn verified<'a, F, G>(
        self,
        find_prev: F,
        find_signer: G,
    ) -> Result<drop::Verified, error::Verification>
    where
        F: FnMut(&ContentHash) -> io::Result<Self>,
        G: FnMut(&IdentityId) -> io::Result<KeySet<'a>>,
    {
        self.signed
            .verified(&self.signatures, find_prev, find_signer)
    }
}

impl Signed<Identity> {
    pub fn verified<F>(self, find_prev: F) -> Result<identity::Verified, error::Verification>
    where
        F: FnMut(&ContentHash) -> io::Result<Self>,
    {
        self.signed.verified(&self.signatures, find_prev)
    }

    pub fn verify<F>(&self, find_prev: F) -> Result<IdentityId, error::Verification>
    where
        F: FnMut(&ContentHash) -> io::Result<Self>,
    {
        self.signed.verify(&self.signatures, find_prev)
    }
}

impl<T> AsRef<T> for Signed<T> {
    fn as_ref(&self) -> &T {
        &self.signed
    }
}

struct Ancestors<T, F> {
    prev: Option<ContentHash>,
    find_prev: F,
    _marker: PhantomData<T>,
}

impl<T, F> Iterator for Ancestors<T, F>
where
    T: HasPrev,
    F: FnMut(&ContentHash) -> io::Result<Signed<T>>,
{
    type Item = io::Result<Signed<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        let prev = self.prev.take()?;
        (self.find_prev)(&prev)
            .map(|parent| {
                self.prev = parent.signed.prev().cloned();
                Some(parent)
            })
            .transpose()
    }
}

pub trait HasPrev {
    fn prev(&self) -> Option<&ContentHash>;
}

impl HasPrev for Identity {
    fn prev(&self) -> Option<&ContentHash> {
        self.prev.as_ref()
    }
}

impl HasPrev for Drop {
    fn prev(&self) -> Option<&ContentHash> {
        self.prev.as_ref()
    }
}

#[derive(Clone)]
pub struct Key<'a>(VerificationKey<'a>);

impl Key<'_> {
    pub fn id(&self) -> KeyId {
        self.into()
    }
}

impl fmt::Debug for Key<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Key").field(&self.0.to_string()).finish()
    }
}

impl<'a> From<VerificationKey<'a>> for Key<'a> {
    fn from(vk: VerificationKey<'a>) -> Self {
        Self(vk.without_comment())
    }
}

impl signature::Verifier<Signature> for Key<'_> {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        let ssh = ssh::Signature::new(self.0.algorithm(), signature.as_ref())?;
        self.0.verify(msg, &ssh)
    }
}

impl serde::Serialize for Key<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_openssh().map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> serde::Deserialize<'de> for Key<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;
        VerificationKey::from_openssh(s)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl FromStr for Key<'_> {
    type Err = ssh_key::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        VerificationKey::from_openssh(s).map(Self)
    }
}

#[derive(Clone, Default)]
pub struct KeySet<'a>(BTreeMap<KeyId, Key<'a>>);

impl<'a> Deref for KeySet<'a> {
    type Target = BTreeMap<KeyId, Key<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for KeySet<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> FromIterator<Key<'a>> for KeySet<'a> {
    fn from_iter<T: IntoIterator<Item = Key<'a>>>(iter: T) -> Self {
        let mut kv = BTreeMap::new();
        for key in iter {
            kv.insert(KeyId::from(&key), key);
        }
        Self(kv)
    }
}

impl serde::Serialize for KeySet<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for key in self.0.values() {
            seq.serialize_element(key)?;
        }
        seq.end()
    }
}

impl<'de> serde::Deserialize<'de> for KeySet<'static> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = KeySet<'static>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a sequence of keys")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut kv = BTreeMap::new();
                while let Some(key) = seq.next_element()? {
                    kv.insert(KeyId::from(&key), key);
                }

                Ok(KeySet(kv))
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Signature(#[serde(with = "hex::serde")] Vec<u8>);

impl From<ssh::Signature> for Signature {
    fn from(sig: ssh::Signature) -> Self {
        Self(sig.as_bytes().to_vec())
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(Self(bytes.to_vec()))
    }
}

pub struct Verified<T>(T);

impl<T> Verified<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Verified<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
