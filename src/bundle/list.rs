// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

//! Bundle Lists in git config format, as per [`bundle-uri`].
//!
//! [`bundle-uri`]: https://git.kernel.org/pub/scm/git/git.git/tree/Documentation/technical/bundle-uri.txt

use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::HashMap,
    fmt,
    io,
    str::FromStr,
    time::{
        SystemTime,
        UNIX_EPOCH,
    },
};

use anyhow::anyhow;
use once_cell::sync::Lazy;
use sha2::{
    Digest,
    Sha256,
};
use url::Url;

use crate::git::{
    self,
    if_not_found_none,
};

pub const FILE_EXTENSION: &str = "uris";
pub const DOT_FILE_EXTENSION: &str = ".uris";

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    All,
    Any,
}

impl Mode {
    pub fn as_str(&self) -> &str {
        match self {
            Self::All => "all",
            Self::Any => "any",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Mode {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(Self::All),
            "any" => Ok(Self::Any),
            x => Err(anyhow!("unknown bundle list mode: {x}")),
        }
    }
}

#[derive(Debug)]
pub enum Uri {
    Absolute(Url),
    Relative(String),
}

impl Uri {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Absolute(url) => url.as_str(),
            Self::Relative(path) => path.as_str(),
        }
    }

    pub fn abs(&self, base: &Url) -> Result<Cow<Url>, url::ParseError> {
        match self {
            Self::Absolute(url) => Ok(Cow::Borrowed(url)),
            Self::Relative(path) => base.join(path).map(Cow::Owned),
        }
    }
}

impl From<Url> for Uri {
    fn from(url: Url) -> Self {
        Self::Absolute(url)
    }
}

impl FromStr for Uri {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        static DUMMY_BASE: Lazy<Url> =
            Lazy::new(|| Url::parse("https://bundles.example.com").unwrap());

        Url::parse(s).map(Self::Absolute).or_else(|e| match e {
            url::ParseError::RelativeUrlWithoutBase => {
                let url = Url::options().base_url(Some(&DUMMY_BASE)).parse(s)?;

                let path = if s.starts_with('/') {
                    url.path()
                } else {
                    url.path().trim_start_matches('/')
                };

                Ok(Self::Relative(path.to_owned()))
            },
            other => Err(other),
        })
    }
}

#[derive(Debug)]
pub struct Location {
    pub id: String,
    pub uri: Uri,
    pub filter: Option<String>,
    pub creation_token: Option<u64>,
    pub location: Option<String>,
}

impl Location {
    pub fn new(id: String, uri: Uri) -> Self {
        Self {
            id,
            uri,
            filter: None,
            creation_token: None,
            location: None,
        }
    }

    pub fn to_config(&self, cfg: &mut git2::Config) -> crate::Result<()> {
        let section = format!("bundle.{}", self.id);

        cfg.set_str(&format!("{section}.uri"), self.uri.as_str())?;
        if let Some(filter) = self.filter.as_deref() {
            cfg.set_str(&format!("{section}.filter"), filter)?;
        }
        if let Some(token) = &self.creation_token {
            cfg.set_str(&format!("{section}.creationToken"), &token.to_string())?;
        }
        if let Some(loc) = self.location.as_deref() {
            cfg.set_str(&format!("{section}.location"), loc)?;
        }

        Ok(())
    }

    pub fn to_writer<W: io::Write>(&self, mut out: W) -> io::Result<()> {
        writeln!(&mut out, "[bundle \"{}\"]", self.id)?;
        writeln!(&mut out, "\turi = {}", self.uri.as_str())?;
        if let Some(filter) = self.filter.as_deref() {
            writeln!(&mut out, "\tfilter = {}", filter)?;
        }
        if let Some(token) = &self.creation_token {
            writeln!(&mut out, "\tcreationToken = {}", token)?;
        }
        if let Some(loc) = self.location.as_deref() {
            writeln!(&mut out, "\tlocation = {}", loc)?;
        }

        Ok(())
    }
}

impl From<Url> for Location {
    fn from(url: Url) -> Self {
        let id = hex::encode(Sha256::digest(url.as_str()));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("backwards system clock")
            .as_secs();
        Self {
            id,
            uri: url.into(),
            filter: None,
            creation_token: Some(now),
            location: None,
        }
    }
}

#[derive(Debug)]
pub struct List {
    pub mode: Mode,
    pub heuristic: Option<String>,
    pub bundles: Vec<Location>,
}

impl List {
    pub fn any() -> Self {
        Self {
            mode: Mode::Any,
            heuristic: Some("creationToken".into()),
            bundles: Vec::new(),
        }
    }

    /// Parse a bundle list from a [`git2::Config`]
    ///
    /// The config is expected to contain the list config keys `bundle.mode` and
    /// optionally `bundle.heuristic`. `bundle.version` is currently ignored.
    ///
    /// A bundle [`Location`] is yielded if at least `bundle.<id>.uri` is set
    /// and a valid [`Url`]. The `base` [`Url`] must be provided to resolve
    /// relative uris in the file.
    ///
    /// The [`Location`] list is sorted by creation token in descending order
    /// (entries without a token sort last). The sort is unstable.
    pub fn from_config(cfg: git::config::Snapshot) -> crate::Result<Self> {
        // nb. ignoring version
        let mode = cfg.get_str("bundle.mode")?.parse()?;
        let heuristic = if_not_found_none(cfg.get_string("bundle.heuristic"))?;

        #[derive(Default)]
        struct Info {
            uri: Option<Uri>,
            filter: Option<String>,
            creation_token: Option<u64>,
            location: Option<String>,
        }

        let mut bundles: HashMap<String, Info> = HashMap::new();
        let mut iter = cfg.entries(Some("bundle\\.[^.]+\\.[^.]+$"))?;
        while let Some(entry) = iter.next() {
            let entry = entry?;
            if let Some(("bundle", id, key)) = entry
                .name()
                .and_then(|name| name.split_once('.'))
                .and_then(|(a, b)| b.split_once('.').map(|(c, d)| (a, c, d)))
            {
                let value = entry
                    .value()
                    .ok_or_else(|| anyhow!("value for bundle.{id}.{key} not utf8"))?;
                let info = bundles.entry(id.to_owned()).or_default();
                match key {
                    "uri" => {
                        let uri = value.parse()?;
                        info.uri = Some(uri);
                    },

                    "filter" => {
                        info.filter = Some(value.to_owned());
                    },

                    "creationToken" | "creationtoken" => {
                        let token = value.parse()?;
                        info.creation_token = Some(token);
                    },

                    "location" => {
                        info.location = Some(value.to_owned());
                    },

                    _ => {},
                }
            }
        }
        let mut bundles = bundles
            .into_iter()
            .filter_map(|(id, info)| {
                info.uri.map(|uri| Location {
                    id,
                    uri,
                    filter: info.filter,
                    creation_token: info.creation_token,
                    location: info.location,
                })
            })
            .collect::<Vec<_>>();
        bundles.sort_unstable_by(|a, b| match (&a.creation_token, &b.creation_token) {
            (Some(x), Some(y)) => y.cmp(x),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        });

        Ok(Self {
            mode,
            heuristic,
            bundles,
        })
    }

    pub fn to_config(&self, cfg: &mut git2::Config) -> crate::Result<()> {
        cfg.set_i32("bundle.version", 1)?;
        cfg.set_str("bundle.mode", self.mode.as_str())?;
        if let Some(heuristic) = self.heuristic.as_deref() {
            cfg.set_str("bundle.heuristic", heuristic)?;
        }
        self.bundles.iter().try_for_each(|loc| loc.to_config(cfg))?;

        Ok(())
    }

    pub fn to_writer<W: io::Write>(&self, mut out: W) -> io::Result<()> {
        writeln!(&mut out, "[bundle]")?;
        writeln!(&mut out, "\tversion = 1")?;
        writeln!(&mut out, "\tmode = {}", self.mode)?;
        if let Some(heuristic) = self.heuristic.as_deref() {
            writeln!(&mut out, "\theuristic = {}", heuristic)?;
        }
        for loc in &self.bundles {
            writeln!(&mut out)?;
            loc.to_writer(&mut out)?;
        }

        Ok(())
    }

    pub fn to_str(&self) -> String {
        let mut buf = Vec::new();
        self.to_writer(&mut buf).unwrap();
        unsafe { String::from_utf8_unchecked(buf) }
    }
}

impl Extend<Location> for List {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = Location>,
    {
        self.bundles.extend(iter)
    }
}
