// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use core::{
    fmt,
    slice,
    str::FromStr,
};
use std::{
    borrow::Borrow,
    convert::Infallible,
    env,
    path::PathBuf,
    vec,
};

pub use crate::git::Refname;
use crate::{
    cfg::paths,
    git,
};

/// Search path akin to the `PATH` environment variable.
#[derive(Clone, Debug)]
pub struct SearchPath(Vec<PathBuf>);

impl SearchPath {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Display for SearchPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        std::env::join_paths(&self.0)
            .unwrap()
            .to_string_lossy()
            .fmt(f)
    }
}

impl FromStr for SearchPath {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(env::split_paths(s).collect()))
    }
}

impl IntoIterator for SearchPath {
    type Item = PathBuf;
    type IntoIter = vec::IntoIter<PathBuf>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a SearchPath {
    type Item = &'a PathBuf;
    type IntoIter = slice::Iter<'a, PathBuf>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// A [`SearchPath`] with a [`Default`] appropriate for `it` identity
/// repositories.
#[derive(Clone, Debug)]
pub struct IdSearchPath(SearchPath);

impl IdSearchPath {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Attempt to open each path element as a git repository
    ///
    /// The repositories will be opened as bare, even if they aren't. No error
    /// is returned if a repo could not be opened (e.g. because it is not a git
    /// repository).
    pub fn open_git(&self) -> Vec<git2::Repository> {
        let mut rs = Vec::with_capacity(self.len());
        for path in self {
            if let Ok(repo) = git::repo::open_bare(path) {
                rs.push(repo);
            }
        }

        rs
    }
}

impl Default for IdSearchPath {
    fn default() -> Self {
        Self(SearchPath(vec![paths::ids()]))
    }
}

impl fmt::Display for IdSearchPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for IdSearchPath {
    type Err = <SearchPath as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

impl IntoIterator for IdSearchPath {
    type Item = <SearchPath as IntoIterator>::Item;
    type IntoIter = <SearchPath as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a IdSearchPath {
    type Item = <&'a SearchPath as IntoIterator>::Item;
    type IntoIter = <&'a SearchPath as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.borrow().into_iter()
    }
}
