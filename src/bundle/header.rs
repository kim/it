// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use core::fmt;
use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    io,
    ops::Deref,
    str::FromStr,
};

use digest::Digest;
use hex::{
    FromHex,
    FromHexError,
};
use refs::Refname;
use sha2::Sha256;

use super::error;
use crate::{
    git::refs,
    io::Lines,
};

pub const SIGNATURE_V2: &str = "# v2 git bundle";
pub const SIGNATURE_V3: &str = "# v3 git bundle";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Version {
    V2,
    V3,
}

impl Default for Version {
    fn default() -> Self {
        Self::V2
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectFormat {
    Sha1,
    Sha256,
}

impl Default for ObjectFormat {
    fn default() -> Self {
        Self::Sha1
    }
}

impl fmt::Display for ObjectFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        })
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ObjectId {
    Sha1(#[serde(with = "hex::serde")] [u8; 20]),
    Sha2(#[serde(with = "hex::serde")] [u8; 32]),
}

impl ObjectId {
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for ObjectId {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Sha1(b) => &b[..],
            Self::Sha2(b) => &b[..],
        }
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self))
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Sha1(x) => f.debug_tuple("Sha1").field(&hex::encode(x)).finish(),
            Self::Sha2(x) => f.debug_tuple("Sha2").field(&hex::encode(x)).finish(),
        }
    }
}

impl FromHex for ObjectId {
    type Error = hex::FromHexError;

    #[inline]
    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        match hex.as_ref().len() {
            40 => Ok(Self::Sha1(<[u8; 20]>::from_hex(hex)?)),
            64 => Ok(Self::Sha2(<[u8; 32]>::from_hex(hex)?)),
            _ => Err(hex::FromHexError::InvalidStringLength),
        }
    }
}

impl From<&git2::Oid> for ObjectId {
    fn from(oid: &git2::Oid) -> Self {
        let bs = oid.as_bytes();
        match bs.len() {
            20 => Self::Sha1(bs.try_into().unwrap()),
            32 => Self::Sha2(bs.try_into().unwrap()),
            x => unreachable!("oid with strange hash size: {}", x),
        }
    }
}

impl TryFrom<&ObjectId> for git2::Oid {
    type Error = git2::Error;

    fn try_from(oid: &ObjectId) -> Result<Self, Self::Error> {
        match oid {
            ObjectId::Sha1(hash) => Self::from_bytes(hash),
            ObjectId::Sha2(_) => Err(git2::Error::new(
                git2::ErrorCode::Invalid,
                git2::ErrorClass::Sha1,
                "sha2 oids not yet supported",
            )),
        }
    }
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Header {
    pub version: Version,
    pub object_format: ObjectFormat,
    pub prerequisites: BTreeSet<ObjectId>,
    pub references: BTreeMap<Refname, ObjectId>,
}

impl Header {
    /// Parse a [`Header`] from an IO stream.
    ///
    /// The stream will be buffered internally, and its position set to the
    /// start of the packfile section.
    pub fn from_reader<R>(mut io: R) -> Result<Self, error::Header>
    where
        R: io::Read + io::Seek,
    {
        use hex::FromHex as _;

        let mut lines = Lines::new(io::BufReader::new(&mut io)).until_blank();

        let mut version: Option<Version> = None;
        let mut object_format: Option<ObjectFormat> = None;
        let mut prerequisites = BTreeSet::new();
        let mut references = BTreeMap::new();

        match lines
            .next()
            .ok_or(error::Header::Format("empty input"))??
            .as_str()
        {
            SIGNATURE_V2 => {
                version = Some(Version::V2);
                object_format = Some(ObjectFormat::Sha1);
                Ok(())
            },

            SIGNATURE_V3 => {
                version = Some(Version::V2);
                Ok(())
            },

            _ => Err(error::Header::Format("invalid signature")),
        }?;

        if let Some(Version::V3) = version {
            for capability in lines.by_ref() {
                let capability = capability?;

                if !capability.starts_with('@') {
                    return Err(error::Header::Format("expected capabilities"));
                }

                if capability.starts_with("@filter") {
                    return Err(error::Header::Format("object filters are not supported"));
                }

                match capability.strip_prefix("@object-format=") {
                    Some("sha1") => {
                        object_format = Some(ObjectFormat::Sha1);
                    },

                    Some("sha256") => {
                        object_format = Some(ObjectFormat::Sha256);
                    },

                    _ => return Err(error::Header::Format("unrecognised capability")),
                }

                if object_format.is_some() {
                    break;
                }
            }
        }

        let version = version.unwrap();
        let object_format = object_format.ok_or(error::Header::Format("missing object-format"))?;

        for tip in lines.by_ref() {
            let mut tip = tip?;
            let oid_off = usize::from(tip.starts_with('-'));
            let oid_hexsz = match object_format {
                ObjectFormat::Sha1 => 40,
                ObjectFormat::Sha256 => 64,
            };

            let oid = ObjectId::from_hex(&tip[oid_off..oid_hexsz + oid_off])?;
            if matches!(
                (&object_format, &oid),
                (ObjectFormat::Sha1, ObjectId::Sha2(_)) | (ObjectFormat::Sha256, ObjectId::Sha1(_))
            ) {
                return Err(error::Header::ObjectFormat {
                    fmt: object_format,
                    oid,
                });
            }
            if !matches!(tip.chars().nth(oid_off + oid_hexsz), None | Some(' ')) {
                return Err(error::Header::UnrecognisedHeader(tip));
            }

            if oid_off > 0 {
                prerequisites.insert(oid);
            } else {
                let refname = tip.split_off(oid_off + oid_hexsz + 1);
                if !refname.starts_with("refs/") {
                    return Err(error::Header::Format("shorthand refname"));
                }
                if references.insert(refname.parse()?, oid).is_some() {
                    return Err(error::Header::Format("duplicate refname"));
                }
            }
        }

        if references.is_empty() {
            return Err(error::Header::Format("empty references"));
        }

        let pos = io::Seek::stream_position(&mut lines)?;
        drop(lines);
        io.seek(io::SeekFrom::Start(pos))?;

        Ok(Header {
            version,
            object_format,
            prerequisites,
            references,
        })
    }

    pub fn to_writer<W>(&self, mut io: W) -> io::Result<()>
    where
        W: io::Write,
    {
        match self.version {
            Version::V2 => writeln!(&mut io, "{}", SIGNATURE_V2)?,
            Version::V3 => {
                writeln!(&mut io, "{}", SIGNATURE_V3)?;
                match self.object_format {
                    ObjectFormat::Sha1 => writeln!(&mut io, "@object-format=sha1")?,
                    ObjectFormat::Sha256 => writeln!(&mut io, "@object-format=sha256")?,
                }
            },
        }
        for pre in &self.prerequisites {
            writeln!(&mut io, "-{}", pre)?;
        }
        for (name, oid) in &self.references {
            writeln!(&mut io, "{} {}", oid, name)?;
        }

        writeln!(&mut io)
    }

    pub fn add_prerequisite<O>(&mut self, oid: O) -> bool
    where
        O: Into<ObjectId>,
    {
        self.prerequisites.insert(oid.into())
    }

    pub fn add_reference<O>(&mut self, name: Refname, oid: O) -> Option<ObjectId>
    where
        O: Into<ObjectId>,
    {
        self.references.insert(name, oid.into())
    }

    pub fn hash(&self) -> Hash {
        let mut ids: BTreeSet<&ObjectId> = BTreeSet::new();
        ids.extend(self.prerequisites.iter());
        ids.extend(self.references.values());

        let mut sha = Sha256::new();
        for id in ids {
            sha.update(id);
        }
        Hash(sha.finalize().into())
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
pub struct Hash(#[serde(with = "hex::serde")] [u8; 32]);

impl Hash {
    pub fn as_bytes(&self) -> &[u8] {
        self.deref()
    }

    pub fn is_valid(hex: &str) -> bool {
        Self::from_str(hex).is_ok()
    }
}

impl Deref for Hash {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for Hash {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <[u8; 32]>::from_hex(s).map(Self)
    }
}
