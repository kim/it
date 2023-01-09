// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use core::fmt;
use std::{
    ops::Deref,
    str::FromStr,
};

use anyhow::ensure;

// A variable-length string type with a maximum length `N`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub struct Varchar<T, const N: usize>(T);

impl<T, const N: usize> Varchar<T, N>
where
    T: AsRef<str>,
{
    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }

    fn try_from_t(t: T) -> crate::Result<Self> {
        let len = t.as_ref().len();
        ensure!(len <= N, "string length exceeds {N}: {len}");
        Ok(Self(t))
    }
}

impl<const N: usize> Varchar<String, N> {
    pub const fn new() -> Self {
        Self(String::new())
    }
}

impl<const N: usize> TryFrom<String> for Varchar<String, N> {
    type Error = crate::Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from_t(s)
    }
}

impl<const N: usize> FromStr for Varchar<String, N> {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl<'a, const N: usize> TryFrom<&'a str> for Varchar<&'a str, N> {
    type Error = crate::Error;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Self::try_from_t(s)
    }
}

impl<T, const N: usize> Deref for Varchar<T, N> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const N: usize> fmt::Display for Varchar<T, N>
where
    T: AsRef<str>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_ref())
    }
}

impl<'de, T, const N: usize> serde::Deserialize<'de> for Varchar<T, N>
where
    T: serde::Deserialize<'de> + TryInto<Self>,
    <T as TryInto<Self>>::Error: fmt::Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let t = T::deserialize(deserializer)?;
        t.try_into().map_err(serde::de::Error::custom)
    }
}
