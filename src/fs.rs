// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    fs::{
        remove_file,
        rename,
        File,
    },
    io::{
        self,
        Read,
        Seek,
        Write,
    },
    path::{
        Path,
        PathBuf,
    },
};

/// A [`File`] which is protected by a git-style lock file
///
/// When a [`LockedFile`] is created, a lock file named after its path with
/// suffix ".lock" is created with `O_EXCL`. That is, if the lock file already
/// exists, the operation will fail.
///
/// Then, either the lock file (when using [`LockedFile::atomic`]) or the base
/// file (when using [`LockedFile::in_place`] is opened for writing.
/// [`LockedFile`] implements [`Write`], [`Read`], and [`Seek`].
///
/// When a [`LockedFile`] is dropped, the lock file is unlinked. **NOTE** that
/// this may leave the lock file in place if the process exits forcefully.
///
/// When using [`LockedFile::atomic`], the modified lock file is renamed to the
/// base file atomically. For this to happen, [`LockedFile::persist`] must be
/// called explicitly.
pub struct LockedFile {
    /// Path to the lock file
    lock: PathBuf,
    /// Path to the file being edited
    path: PathBuf,
    /// File being edited
    edit: File,
    /// Commit mode
    mode: Commit,
}

enum Commit {
    Atomic,
    InPlace,
}

impl Drop for LockedFile {
    fn drop(&mut self) {
        remove_file(&self.lock).ok();
    }
}

impl LockedFile {
    pub const DEFAULT_PERMISSIONS: u32 = 0o644;

    pub fn atomic<P, M>(path: P, truncate: bool, mode: M) -> io::Result<Self>
    where
        P: Into<PathBuf>,
        M: Into<Option<u32>>,
    {
        let path = path.into();
        let perm = mode.into().unwrap_or(Self::DEFAULT_PERMISSIONS);
        let lock = path.with_extension("lock");
        let mut edit = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .permissions(perm)
            .open(&lock)?;
        if !truncate && path.exists() {
            std::fs::copy(&path, &lock)?;
            edit = File::options().read(true).append(true).open(&lock)?;
        }
        let mode = Commit::Atomic;

        Ok(Self {
            lock,
            path,
            edit,
            mode,
        })
    }

    pub fn in_place<P, M>(path: P, truncate: bool, mode: M) -> io::Result<Self>
    where
        P: Into<PathBuf>,
        M: Into<Option<u32>>,
    {
        let path = path.into();
        let perm = mode.into().unwrap_or(Self::DEFAULT_PERMISSIONS);
        let lock = path.with_extension("lock");
        let _ = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .permissions(perm)
            .open(&lock)?;
        let edit = File::options()
            .read(true)
            .write(true)
            .truncate(truncate)
            .create(true)
            .permissions(perm)
            .open(&path)?;
        let mode = Commit::InPlace;

        Ok(Self {
            lock,
            path,
            edit,
            mode,
        })
    }

    /// Reopen the file handle
    ///
    /// This is sometimes necessary, eg. when launching an editor to let the
    /// user modify the file, in which case the file descriptor of the
    /// handle is invalidated.
    pub fn reopen(&mut self) -> io::Result<()> {
        self.edit = File::options()
            .read(true)
            .write(true)
            .open(self.edit_path())?;
        Ok(())
    }

    pub fn edit_path(&self) -> &Path {
        match self.mode {
            Commit::Atomic => &self.lock,
            Commit::InPlace => &self.path,
        }
    }

    #[allow(unused)]
    pub fn target_path(&self) -> &Path {
        &self.path
    }

    pub fn persist(self) -> io::Result<()> {
        match self.mode {
            Commit::Atomic => rename(&self.lock, &self.path),
            Commit::InPlace => remove_file(&self.lock),
        }
    }
}

impl Read for LockedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.edit.read(buf)
    }
}

impl Write for LockedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.edit.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.edit.flush()
    }
}

impl Seek for LockedFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.edit.seek(pos)
    }
}

pub(crate) trait PermissionsExt {
    fn permissions(&mut self, mode: u32) -> &mut Self;
}

impl PermissionsExt for std::fs::OpenOptions {
    #[cfg(unix)]
    fn permissions(&mut self, mode: u32) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt as _;
        self.mode(mode)
    }

    #[cfg(not(unix))]
    fn permissions(&mut self, mode: u32) -> &mut Self {
        self
    }
}
