// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    fs,
    io::{
        self,
        Read,
        Seek,
        SeekFrom,
        Write,
    },
    path::{
        Path,
        PathBuf,
    },
};

use anyhow::ensure;
use either::Either::{
    self,
    Left,
    Right,
};
use sha2::{
    Digest,
    Sha256,
};
use tempfile::NamedTempFile;
use url::Url;

use super::{
    header,
    Expect,
    Header,
};
use crate::{
    bundle,
    fs::LockedFile,
    git,
    io::HashWriter,
};

const MAX_BUNDLE_URIS_BYTES: u64 = 50_000;

pub struct Fetched {
    path: PathBuf,
    info: bundle::Info,
}

impl Fetched {
    pub fn into_inner(self) -> (PathBuf, bundle::Info) {
        (self.path, self.info)
    }
}

pub struct Fetcher {
    agent: ureq::Agent,
}

impl Default for Fetcher {
    fn default() -> Self {
        Self {
            agent: ureq::agent(),
        }
    }
}

impl Fetcher {
    pub fn fetch(
        &self,
        url: &Url,
        out_dir: &Path,
        expect: Expect,
    ) -> crate::Result<Either<bundle::List, Fetched>> {
        let resp = self.agent.request_url("GET", url).call()?;
        let mut body = resp.into_reader();

        let mut buf = [0; 16];
        body.read_exact(&mut buf)?;
        let is_bundle = buf.starts_with(header::SIGNATURE_V2.as_bytes())
            || buf.starts_with(header::SIGNATURE_V3.as_bytes());
        if is_bundle {
            ensure!(
                matches!(buf.last(), Some(b'\n')),
                "malformed bundle header: trailing data"
            )
        }

        if is_bundle {
            let mut path = out_dir.join(expect.hash.to_string());
            path.set_extension(bundle::FILE_EXTENSION);

            let mut lck = {
                fs::create_dir_all(out_dir)?;
                LockedFile::atomic(&path, true, LockedFile::DEFAULT_PERMISSIONS)?
            };

            let mut out = HashWriter::new(Sha256::new(), &mut lck);
            out.write_all(&buf)?;

            let len = buf.len() as u64 + io::copy(&mut body.take(expect.len), &mut out)?;
            let checksum = out.hash().into();
            if let Some(chk) = expect.checksum {
                ensure!(chk == checksum, "checksum mismatch");
            }
            lck.seek(SeekFrom::Start(0))?;
            let header = Header::from_reader(&mut lck)?;
            let hash = header.hash();

            lck.persist()?;

            let info = bundle::Info {
                len,
                hash,
                checksum,
                uris: vec![url.clone()],
            };
            Ok(Right(Fetched { path, info }))
        } else {
            let mut tmp = NamedTempFile::new()?;
            tmp.write_all(&buf)?;
            io::copy(&mut body.take(MAX_BUNDLE_URIS_BYTES), &mut tmp)?;
            let cfg = git::config::Snapshot::try_from(git2::Config::open(tmp.path())?)?;
            let list = bundle::List::from_config(cfg)?;

            Ok(Left(list))
        }
    }
}
