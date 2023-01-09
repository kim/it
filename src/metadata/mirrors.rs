// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    borrow::Cow,
    collections::BTreeSet,
};

use url::Url;

use super::{
    Custom,
    DateTime,
    Metadata,
    SpecVersion,
};
use crate::{
    json::canonical,
    str::Varchar,
};

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

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Mirrors {
    pub spec_version: SpecVersion,
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

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Alternates {
    pub spec_version: SpecVersion,
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
