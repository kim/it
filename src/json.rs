// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    fs::File,
    io::BufReader,
    path::Path,
};

use serde::{
    de::DeserializeOwned,
    Deserialize,
    Serialize,
};

pub mod canonical;

pub fn from_blob<'a, T>(blob: &'a git2::Blob) -> crate::Result<T>
where
    T: Deserialize<'a>,
{
    Ok(serde_json::from_slice(blob.content())?)
}

pub fn to_blob<T>(repo: &git2::Repository, data: &T) -> crate::Result<git2::Oid>
where
    T: Serialize,
{
    let mut writer = repo.blob_writer(None)?;
    serde_json::to_writer_pretty(&mut writer, data)?;
    Ok(writer.commit()?)
}

pub fn from_file<P, T>(path: P) -> crate::Result<T>
where
    P: AsRef<Path>,
    T: DeserializeOwned,
{
    let file = File::open(path)?;
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

pub fn load<P, T>(path: P) -> crate::Result<T>
where
    P: AsRef<Path>,
    T: DeserializeOwned,
{
    from_file(path)
}
