// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use sha2::{
    digest::generic_array::GenericArray,
    Digest,
};

/// Created by [`Lines::until_blank`], stops iteration at the first blank line.
pub struct UntilBlank<B> {
    inner: Lines<B>,
}

impl<B: std::io::BufRead> Iterator for UntilBlank<B> {
    type Item = std::io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().and_then(|res| match res {
            Ok(line) => {
                if line.is_empty() {
                    None
                } else {
                    Some(Ok(line))
                }
            },
            Err(e) => Some(Err(e)),
        })
    }
}

impl<B: std::io::Seek> std::io::Seek for UntilBlank<B> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Like [`std::io::Lines`], but allows to retain ownership of the underlying
/// [`std::io::BufRead`].
pub struct Lines<B> {
    buf: B,
}

impl<B: std::io::BufRead> Lines<B> {
    pub fn new(buf: B) -> Self {
        Self { buf }
    }

    pub fn until_blank(self) -> UntilBlank<B> {
        UntilBlank { inner: self }
    }
}

impl<B: std::io::BufRead> Iterator for Lines<B> {
    type Item = std::io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = String::new();
        match self.buf.read_line(&mut buf) {
            Ok(0) => None,
            Ok(_) => {
                if buf.ends_with('\n') {
                    buf.pop();
                    if buf.ends_with('\r') {
                        buf.pop();
                    }
                }
                Some(Ok(buf))
            },
            Err(e) => Some(Err(e)),
        }
    }
}

impl<B: std::io::Seek> std::io::Seek for Lines<B> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.buf.seek(pos)
    }
}

/// A [`std::io::Write`] which also computes a hash digest from the bytes
/// written to it.
pub struct HashWriter<D, W> {
    hasher: D,
    writer: W,
}

impl<D, W> HashWriter<D, W> {
    pub fn new(hasher: D, writer: W) -> Self {
        Self { hasher, writer }
    }
}

impl<D, W> HashWriter<D, W>
where
    D: Digest,
{
    pub fn hash(self) -> GenericArray<u8, D::OutputSize> {
        self.hasher.finalize()
    }
}

impl<D, W> std::io::Write for HashWriter<D, W>
where
    D: Digest,
    W: std::io::Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

/// A [`std::io::Write`] which keeps track of the number of bytes written to it
pub struct LenWriter<W> {
    written: u64,
    writer: W,
}

impl<W> LenWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { written: 0, writer }
    }

    pub fn bytes_written(&self) -> u64 {
        self.written
    }
}

impl<W> std::io::Write for LenWriter<W>
where
    W: std::io::Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.writer.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
