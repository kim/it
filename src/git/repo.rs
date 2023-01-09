// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    collections::HashSet,
    ffi::OsString,
    io::{
        BufReader,
        Seek,
        Write,
    },
    iter,
    path::Path,
    result::Result as StdResult,
};

use super::{
    if_not_found_then,
    Result,
};
use crate::{
    fs::LockedFile,
    io::Lines,
};

pub fn open<P: AsRef<Path>>(path: P) -> Result<git2::Repository> {
    git2::Repository::open_ext(
        path,
        git2::RepositoryOpenFlags::FROM_ENV,
        iter::empty::<OsString>(),
    )
}

pub fn open_bare<P: AsRef<Path>>(path: P) -> Result<git2::Repository> {
    git2::Repository::open_ext(
        path,
        git2::RepositoryOpenFlags::FROM_ENV | git2::RepositoryOpenFlags::BARE,
        iter::empty::<OsString>(),
    )
}

pub fn open_or_init<P: AsRef<Path>>(path: P, opts: InitOpts) -> Result<git2::Repository> {
    if_not_found_then(open(path.as_ref()), || init(path, opts))
}

pub struct InitOpts<'a> {
    pub bare: bool,
    pub description: &'a str,
    pub initial_head: &'a str,
}

pub fn init<P: AsRef<Path>>(path: P, opts: InitOpts) -> Result<git2::Repository> {
    git2::Repository::init_opts(
        path,
        git2::RepositoryInitOptions::new()
            .no_reinit(true)
            .mkdir(true)
            .mkpath(true)
            .bare(opts.bare)
            .description(opts.description)
            .initial_head(opts.initial_head),
    )
}

pub fn add_alternates<'a, I>(repo: &git2::Repository, alt: I) -> crate::Result<()>
where
    I: IntoIterator<Item = &'a git2::Repository>,
{
    let (mut persistent, known) = {
        let mut lock = LockedFile::atomic(
            repo.path().join("objects").join("info").join("alternates"),
            false,
            LockedFile::DEFAULT_PERMISSIONS,
        )?;
        lock.seek(std::io::SeekFrom::Start(0))?;
        let mut bufread = BufReader::new(lock);
        let known = Lines::new(&mut bufread).collect::<StdResult<HashSet<String>, _>>()?;
        (bufread.into_inner(), known)
    };
    {
        let odb = repo.odb()?;
        for alternate in alt {
            let path = format!("{}", alternate.path().join("objects").display());
            odb.add_disk_alternate(&path)?;
            if !known.contains(&path) {
                writeln!(&mut persistent, "{}", path)?
            }
        }
    }
    persistent.persist()?;

    Ok(())
}
