// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use core::{
    fmt,
    ops::Deref,
    str::FromStr,
};
use std::{
    borrow::Cow,
    cell::Cell,
    collections::HashMap,
    path::Path,
    rc::Rc,
};

pub const MAX_FILENAME: usize = 255;

#[derive(Clone, Copy)]
pub struct Options {
    pub allow_onelevel: bool,
    pub allow_pattern: bool,
}

pub mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum RefFormat {
        #[error("empty input")]
        Empty,
        #[error("name too long")]
        NameTooLong,
        #[error("invalid character {0:?}")]
        InvalidChar(char),
        #[error("invalid character sequence {0:?}")]
        InvalidSeq(&'static str),
        #[error("must contain at least one '/'")]
        OneLevel,
        #[error("must contain at most one '*'")]
        Pattern,
    }
}

pub fn check_ref_format(opts: Options, s: &str) -> Result<(), error::RefFormat> {
    use error::RefFormat::*;

    match s {
        "" => Err(Empty),
        "@" => Err(InvalidChar('@')),
        "." => Err(InvalidChar('.')),
        _ => {
            let mut globs = 0;
            let mut parts = 0;

            for x in s.split('/') {
                if x.is_empty() {
                    return Err(InvalidSeq("//"));
                }
                if x.len() > MAX_FILENAME {
                    return Err(NameTooLong);
                }

                parts += 1;

                if x.ends_with(".lock") {
                    return Err(InvalidSeq(".lock"));
                }

                let last_char = x.len() - 1;
                for (i, y) in x.chars().zip(x.chars().cycle().skip(1)).enumerate() {
                    match y {
                        ('.', '.') => return Err(InvalidSeq("..")),
                        ('@', '{') => return Err(InvalidSeq("@{")),
                        ('*', _) => globs += 1,
                        (z, _) => match z {
                            '\0' | '\\' | '~' | '^' | ':' | '?' | '[' | ' ' => {
                                return Err(InvalidChar(z))
                            },
                            '.' if i == 0 || i == last_char => return Err(InvalidChar('.')),
                            _ if z.is_ascii_control() => return Err(InvalidChar(z)),

                            _ => continue,
                        },
                    }
                }
            }

            if parts < 2 && !opts.allow_onelevel {
                Err(OneLevel)
            } else if globs > 1 && opts.allow_pattern {
                Err(Pattern)
            } else if globs > 0 && !opts.allow_pattern {
                Err(InvalidChar('*'))
            } else {
                Ok(())
            }
        },
    }
}

/// A valid git refname.
///
/// If the input starts with 'refs/`, it is taken verbatim (after validation),
/// otherwise `refs/heads/' is prepended (ie. the input is considered a branch
/// name).
#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ::serde::Serialize, ::serde::Deserialize,
)]
#[serde(try_from = "String")]
pub struct Refname(String);

impl Refname {
    pub fn main() -> Self {
        Self("refs/heads/main".into())
    }

    pub fn master() -> Self {
        Self("refs/heads/master".into())
    }
}

impl fmt::Display for Refname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self)
    }
}

impl Deref for Refname {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for Refname {
    fn as_ref(&self) -> &str {
        self
    }
}

impl AsRef<Path> for Refname {
    fn as_ref(&self) -> &Path {
        Path::new(self.0.as_str())
    }
}

impl From<Refname> for String {
    fn from(r: Refname) -> Self {
        r.0
    }
}

impl FromStr for Refname {
    type Err = error::RefFormat;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl TryFrom<String> for Refname {
    type Error = error::RefFormat;

    fn try_from(value: String) -> core::result::Result<Self, Self::Error> {
        const OPTIONS: Options = Options {
            allow_onelevel: true,
            allow_pattern: false,
        };

        check_ref_format(OPTIONS, &value)?;
        let name = if value.starts_with("refs/") {
            value
        } else {
            format!("refs/heads/{}", value)
        };

        Ok(Self(name))
    }
}

/// Iterator over reference names
///
/// [`git2::ReferenceNames`] is advertised as more efficient if only the
/// reference names are needed, and not a full [`git2::Reference`]. However,
/// that type has overly restrictive lifetime constraints (because,
/// inexplicably, it does **not** consume [`git2::References`] even though
/// the documentation claims so).
///
/// We can work around this by transforming the reference `&str` into some other
/// type which is not subject to its lifetime.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ReferenceNames<'a, F> {
    inner: git2::References<'a>,
    trans: F,
}

impl<'a, F> ReferenceNames<'a, F> {
    pub fn new(refs: git2::References<'a>, trans: F) -> Self {
        Self { inner: refs, trans }
    }
}

impl<'a, F, E, T> Iterator for ReferenceNames<'a, F>
where
    F: FnMut(&str) -> core::result::Result<T, E>,
    E: From<git2::Error>,
{
    type Item = core::result::Result<T, E>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .names()
            .next()
            .map(|r| r.map_err(E::from).and_then(|name| (self.trans)(name)))
    }
}

pub struct Transaction<'a> {
    tx: git2::Transaction<'a>,
    locked: HashMap<Refname, Rc<Cell<Op>>>,
}

impl<'a> Transaction<'a> {
    pub fn new(repo: &'a git2::Repository) -> super::Result<Self> {
        let tx = repo.transaction()?;
        Ok(Self {
            tx,
            locked: HashMap::new(),
        })
    }

    pub fn lock_ref(&mut self, name: Refname) -> super::Result<LockedRef> {
        use std::collections::hash_map::Entry;

        let lref = match self.locked.entry(name) {
            Entry::Vacant(v) => {
                let name = v.key().clone();
                self.tx.lock_ref(&name)?;
                let op = Rc::new(Cell::new(Op::default()));
                v.insert(Rc::clone(&op));
                LockedRef { name, op }
            },
            Entry::Occupied(v) => LockedRef {
                name: v.key().clone(),
                op: Rc::clone(v.get()),
            },
        };

        Ok(lref)
    }

    pub fn commit(mut self) -> super::Result<()> {
        for (name, op) in self.locked {
            match op.take() {
                Op::None => continue,
                Op::DirTarget { target, reflog } => {
                    self.tx.set_target(&name, target, None, &reflog)?
                },
                Op::SymTarget { target, reflog } => {
                    self.tx.set_symbolic_target(&name, &target, None, &reflog)?
                },
                Op::Remove => self.tx.remove(&name)?,
            }
        }
        self.tx.commit()
    }
}

#[derive(Debug, Default)]
enum Op {
    #[default]
    None,
    DirTarget {
        target: git2::Oid,
        reflog: Cow<'static, str>,
    },
    SymTarget {
        target: Refname,
        reflog: Cow<'static, str>,
    },
    #[allow(unused)]
    Remove,
}

pub struct LockedRef {
    name: Refname,
    op: Rc<Cell<Op>>,
}

impl LockedRef {
    pub fn name(&self) -> &Refname {
        &self.name
    }

    pub fn set_target<S: Into<Cow<'static, str>>>(&self, target: git2::Oid, reflog: S) {
        self.op.set(Op::DirTarget {
            target,
            reflog: reflog.into(),
        })
    }

    pub fn set_symbolic_target<S: Into<Cow<'static, str>>>(&self, target: Refname, reflog: S) {
        self.op.set(Op::SymTarget {
            target,
            reflog: reflog.into(),
        })
    }

    #[allow(unused)]
    pub fn remove(&self) {
        self.op.set(Op::Remove)
    }
}

impl fmt::Display for LockedRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl From<LockedRef> for Refname {
    fn from(LockedRef { name, .. }: LockedRef) -> Self {
        name
    }
}
