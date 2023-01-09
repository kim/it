// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    fs::File,
    io::{
        self,
        Read,
        Seek,
        SeekFrom,
    },
    iter,
    path::{
        Path,
        PathBuf,
    },
};

use anyhow::{
    bail,
    ensure,
    Context,
};
use multipart::client::lazy::Multipart;
use sha2::{
    Digest,
    Sha256,
};
use tempfile::NamedTempFile;
use url::Url;

use super::record::{
    self,
    Encryption,
};
use crate::{
    bundle,
    io::HashWriter,
    keys::Signature,
    Result,
};

pub struct Bundle {
    pub(super) header: bundle::Header,
    pub(super) path: PathBuf,
    pub(super) info: bundle::Info,
    pub(super) encryption: Option<Encryption>,
    pack_start: u64,
}

impl Bundle {
    pub fn create<P>(bundle_dir: P, repo: &git2::Repository, header: bundle::Header) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let bundle_dir = bundle_dir.as_ref();
        std::fs::create_dir_all(bundle_dir)?;

        let mut tmp = NamedTempFile::new_in(bundle_dir)?;
        let info = bundle::create(&mut tmp, repo, &header)?;
        let path = bundle_dir
            .join(info.hash.to_string())
            .with_extension(bundle::FILE_EXTENSION);
        tmp.persist(&path)?;
        let mut buf = Vec::new();
        header.to_writer(&mut buf)?;
        let pack_start = buf.len() as u64;

        Ok(Self {
            header,
            path,
            info,
            encryption: None,
            pack_start,
        })
    }

    pub fn from_fetched(bundle: bundle::Fetched) -> Result<Self> {
        let (path, info) = bundle.into_inner();
        let (header, mut pack) = split(&path)?;
        let pack_start = pack.offset;
        let encryption = pack.encryption()?;

        Ok(Self {
            header,
            path,
            info,
            encryption,
            pack_start,
        })
    }

    // TODO: defer computing the checksum until needed
    pub fn from_stored<P>(bundle_dir: P, expect: bundle::Expect) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let path = bundle_dir
            .as_ref()
            .join(expect.hash.to_string())
            .with_extension(bundle::FILE_EXTENSION);

        let (header, mut pack) = split(&path)?;
        let pack_start = pack.offset;
        let encryption = pack.encryption()?;
        drop(pack);
        let mut file = File::open(&path)?;
        let mut sha2 = Sha256::new();

        let len = io::copy(&mut file, &mut sha2)?;
        let hash = header.hash();
        ensure!(expect.hash == &hash, "header hash mismatch");
        let checksum = sha2.finalize().into();
        if let Some(expect) = expect.checksum {
            ensure!(expect == checksum, "claimed and actual hash differ");
        }

        let info = bundle::Info {
            len,
            hash,
            checksum,
            uris: vec![],
        };

        Ok(Self {
            header,
            path,
            info,
            encryption,
            pack_start,
        })
    }

    pub fn copy<R, P>(mut from: R, to: P) -> Result<Self>
    where
        R: Read,
        P: AsRef<Path>,
    {
        std::fs::create_dir_all(&to)?;
        let mut tmp = NamedTempFile::new_in(&to)?;
        let mut out = HashWriter::new(Sha256::new(), &mut tmp);

        let len = io::copy(&mut from, &mut out)?;
        let checksum = out.hash().into();

        let (header, mut pack) = split(tmp.path())?;
        let hash = header.hash();
        let pack_start = pack.offset;
        let encryption = pack.encryption()?;

        let info = bundle::Info {
            len,
            hash,
            checksum,
            uris: vec![],
        };

        let path = to
            .as_ref()
            .join(hash.to_string())
            .with_extension(bundle::FILE_EXTENSION);
        tmp.persist(&path)?;

        Ok(Self {
            header,
            path,
            info,
            encryption,
            pack_start,
        })
    }

    pub fn encryption(&self) -> Option<Encryption> {
        self.encryption
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    pub fn reader(&self) -> Result<impl io::Read> {
        Ok(File::open(&self.path)?)
    }

    pub fn header(&self) -> &bundle::Header {
        &self.header
    }

    pub fn info(&self) -> &bundle::Info {
        &self.info
    }

    pub fn packdata(&self) -> Result<Packdata> {
        let bundle = File::open(&self.path)?;
        Ok(Packdata {
            offset: self.pack_start,
            bundle,
        })
    }

    pub fn default_location(&self) -> bundle::Location {
        let uri = bundle::Uri::Relative(format!("/bundles/{}.bundle", self.info.hash));
        let id = hex::encode(Sha256::digest(uri.as_str()));

        bundle::Location {
            id,
            uri,
            filter: None,
            creation_token: None,
            location: None,
        }
    }

    pub fn bundle_list_path(&self) -> PathBuf {
        self.path.with_extension(bundle::list::FILE_EXTENSION)
    }

    pub fn write_bundle_list<I>(&self, extra: I) -> Result<()>
    where
        I: IntoIterator<Item = bundle::Location>,
    {
        let mut blist = bundle::List::any();
        blist.extend(
            iter::once(self.default_location())
                .chain(self.info.uris.iter().map(|url| {
                    let uri = bundle::Uri::Absolute(url.clone());
                    let id = hex::encode(Sha256::digest(uri.as_str()));

                    bundle::Location {
                        id,
                        uri,
                        filter: None,
                        creation_token: None,
                        location: None,
                    }
                }))
                .chain(extra),
        );

        let mut cfg = git2::Config::open(&self.bundle_list_path())?;
        blist.to_config(&mut cfg)?;

        Ok(())
    }

    pub fn sign<S>(&self, signer: &mut S) -> Result<Signature>
    where
        S: crate::keys::Signer,
    {
        Ok(signer.sign(record::Heads::from(&self.header).as_slice())?)
    }

    pub fn ipfs_add(&mut self, via: &Url) -> Result<Url> {
        let name = format!("{}.{}", self.info.hash, bundle::FILE_EXTENSION);
        let mut api = via.join("api/v0/add")?;
        api.query_pairs_mut()
            // FIXME: we may want this, but `rust-chunked-transfer` (used by
            // `ureq`) doesn't know about trailers
            // .append_pair("to-files", &name)
            .append_pair("quiet", "true");
        let mpart = Multipart::new()
            .add_file(name, self.path.as_path())
            .prepare()?;

        #[derive(serde::Deserialize)]
        struct Response {
            #[serde(rename = "Hash")]
            cid: String,
        }

        let Response { cid } = ureq::post(api.as_str())
            .set(
                "Content-Length",
                &mpart
                    .content_len()
                    .expect("zero-size bundle file?")
                    .to_string(),
            )
            .set(
                "Content-Type",
                &format!("multipart/form-data; boundary={}", mpart.boundary()),
            )
            .send(mpart)
            .context("posting to IPFS API")?
            .into_json()
            .context("parsing IPFS API response")?;

        let url = Url::parse(&format!("ipfs://{cid}"))?;
        self.info.uris.push(url.clone());

        Ok(url)
    }
}

impl From<Bundle> for bundle::Info {
    fn from(Bundle { info, .. }: Bundle) -> Self {
        info
    }
}

fn split(bundle: &Path) -> Result<(bundle::Header, Packdata)> {
    let mut bundle = File::open(bundle)?;
    let header = bundle::Header::from_reader(&mut bundle)?;
    let offset = bundle.stream_position()?;
    let pack = Packdata { offset, bundle };
    Ok((header, pack))
}

pub struct Packdata {
    offset: u64,
    bundle: File,
}

impl Packdata {
    pub fn index(&mut self, odb: &git2::Odb) -> Result<()> {
        self.bundle.seek(SeekFrom::Start(self.offset))?;

        let mut pw = odb.packwriter()?;
        io::copy(&mut self.bundle, &mut pw)?;
        pw.commit()?;

        Ok(())
    }

    pub fn encryption(&mut self) -> Result<Option<Encryption>> {
        const PACK: &[u8] = b"PACK";
        const AGE: &[u8] = b"age-encryption.org/v1";
        const GPG: &[u8] = b"-----BEGIN PGP MESSAGE-----";

        self.bundle.seek(SeekFrom::Start(self.offset))?;

        let mut buf = [0; 32];
        self.bundle.read_exact(&mut buf)?;
        if buf.starts_with(PACK) {
            Ok(None)
        } else if buf.starts_with(AGE) {
            Ok(Some(Encryption::Age))
        } else if buf.starts_with(GPG) {
            Ok(Some(Encryption::Gpg))
        } else {
            bail!("packdata does not appear to be in a known format")
        }
    }
}
