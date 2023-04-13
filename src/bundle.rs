// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    fmt::{
        self,
        Debug,
        Display,
    },
    io,
};

use log::info;
use url::Url;

use crate::io::{
    HashWriter,
    LenWriter,
};

pub mod error;

mod fetch;
pub use fetch::{
    Fetched,
    Fetcher,
};

mod header;
pub use header::{
    Hash,
    Header,
    ObjectFormat,
    ObjectId,
    Version,
};

pub mod list;
pub use list::{
    List,
    Location,
    Uri,
};

pub const FILE_EXTENSION: &str = "bundle";
pub const DOT_FILE_EXTENSION: &str = ".bundle";

#[derive(Clone, Copy, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Checksum(#[serde(with = "crate::serde::display")] blake3::Hash);

impl Debug for Checksum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hex = self.0.to_hex();
        let hex: &str = hex.as_str();

        f.debug_tuple("Checksum").field(&hex).finish()
    }
}

impl Display for Checksum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl From<&blake3::Hasher> for Checksum {
    fn from(hasher: &blake3::Hasher) -> Self {
        Self(hasher.finalize())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Info {
    pub len: u64,
    pub hash: Hash,
    pub checksum: Checksum,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uris: Vec<Url>,
}

#[derive(Clone, Copy)]
pub struct Expect<'a> {
    pub len: u64,
    pub hash: &'a Hash,
    pub checksum: Option<&'a Checksum>,
}

impl<'a> From<&'a Info> for Expect<'a> {
    fn from(
        Info {
            len,
            hash,
            checksum,
            ..
        }: &'a Info,
    ) -> Self {
        Self {
            len: *len,
            hash,
            checksum: Some(checksum),
        }
    }
}

pub fn create<W>(mut out: W, repo: &git2::Repository, header: &Header) -> crate::Result<Info>
where
    W: io::Write,
{
    let mut hasher = HashWriter::new(blake3::Hasher::new(), &mut out);
    let mut writer = LenWriter::new(&mut hasher);
    let mut pack = {
        let mut pack = repo.packbuilder()?;
        let mut walk = repo.revwalk()?;
        for pre in &header.prerequisites {
            walk.hide(pre.try_into()?)?;
        }
        for inc in header.references.values() {
            walk.push(inc.try_into()?)?;
        }
        pack.insert_walk(&mut walk)?;
        pack
    };
    header.to_writer(&mut writer)?;

    info!("Packing objects...");
    pack.foreach(|chunk| io::Write::write_all(&mut writer, chunk).is_ok())?;

    let len = writer.bytes_written();
    let hash = header.hash();
    let checksum = Checksum::from(hasher.hasher());

    info!("Created patch bundle {hash}");

    Ok(Info {
        len,
        hash,
        checksum,
        uris: vec![],
    })
}
