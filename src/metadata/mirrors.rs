// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    borrow::Cow,
    collections::BTreeSet,
    ops::Deref,
};

use url::Url;

use super::{
    Custom,
    DateTime,
    Metadata,
};
use crate::{
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
pub struct Mirror {
    pub url: Url,
    #[serde(default)]
    pub kind: Kind,
    #[serde(default)]
    pub custom: Custom,
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Can fetch bundles
    Bundled,
    /// Can fetch packs via git-protocol
    #[default]
    Packed,
    /// Not serving bundles at all
    Sparse,
    /// Unknown kind
    Unknown(Varchar<String, 16>),
}

#[derive(Clone, Default, serde::Deserialize)]
pub struct Mirrors {
    #[serde(alias = "spec_version")]
    pub fmt_version: FmtVersion,
    pub mirrors: Vec<Mirror>,
    pub expires: Option<DateTime>,
}

impl Mirrors {
    pub fn canonicalise(&self) -> Result<Vec<u8>, canonical::error::Canonicalise> {
        canonical::to_vec(Metadata::mirrors(self))
    }
}

impl From<Mirrors> for Cow<'static, Mirrors> {
    fn from(m: Mirrors) -> Self {
        Self::Owned(m)
    }
}

impl<'a> From<&'a Mirrors> for Cow<'a, Mirrors> {
    fn from(m: &'a Mirrors) -> Self {
        Self::Borrowed(m)
    }
}

impl serde::Serialize for Mirrors {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut s = serializer.serialize_struct("Mirrors", 3)?;
        let version_field = if self.fmt_version < FMT_VERSION {
            "spec_version"
        } else {
            "fmt_version"
        };
        s.serialize_field(version_field, &self.fmt_version)?;
        s.serialize_field("mirrors", &self.mirrors)?;
        s.serialize_field("expires", &self.expires)?;
        s.end()
    }
}

#[derive(Clone, Default, serde::Deserialize)]
pub struct Alternates {
    #[serde(alias = "spec_version")]
    pub fmt_version: FmtVersion,
    pub alternates: BTreeSet<Url>,
    #[serde(default)]
    pub custom: Custom,
    pub expires: Option<DateTime>,
}

impl Alternates {
    pub fn canonicalise(&self) -> Result<Vec<u8>, canonical::error::Canonicalise> {
        canonical::to_vec(Metadata::alternates(self))
    }
}

impl From<Alternates> for Cow<'static, Alternates> {
    fn from(a: Alternates) -> Self {
        Self::Owned(a)
    }
}

impl<'a> From<&'a Alternates> for Cow<'a, Alternates> {
    fn from(a: &'a Alternates) -> Self {
        Self::Borrowed(a)
    }
}

impl serde::Serialize for Alternates {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut s = serializer.serialize_struct("Alternates", 4)?;
        let version_field = if self.fmt_version < FMT_VERSION {
            "spec_version"
        } else {
            "fmt_version"
        };
        s.serialize_field(version_field, &self.fmt_version)?;
        s.serialize_field("alternates", &self.alternates)?;
        s.serialize_field("custom", &self.custom)?;
        s.serialize_field("expires", &self.expires)?;
        s.end()
    }
}
