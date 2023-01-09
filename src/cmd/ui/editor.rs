// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    env,
    ffi::OsString,
    io::{
        self,
        BufRead as _,
        Write as _,
    },
    path::{
        Path,
        PathBuf,
    },
    process::Command,
};

use tempfile::TempPath;

use crate::{
    fs::LockedFile,
    patches::notes,
};

const SCISSORS: &str = "# ------------------------ >8 ------------------------";

pub struct Commit(Editmsg);

impl Commit {
    pub fn new<P: AsRef<Path>>(git_dir: P) -> io::Result<Self> {
        Editmsg::new(git_dir.as_ref().join("COMMIT_EDITMSG")).map(Self)
    }

    pub fn edit(self, branch: &str, diff: git2::Diff) -> io::Result<Option<String>> {
        let branch = branch.strip_prefix("refs/heads/").unwrap_or(branch);
        self.0.edit(|buf| {
            write!(
                buf,
                "
# Please enter the commit message for your changes. Lines starting
# with '#' will be ignored, and an empty message aborts the commit.
#
# On branch {branch}
#
{SCISSORS}
# Do not modify or remove the line above.
# Everything below it will be ignored.
#
# Changes to be committed:
"
            )?;
            diff.print(git2::DiffFormat::Patch, |_delta, _hunk, line| {
                use git2::DiffLineType::{
                    Addition,
                    Context,
                    Deletion,
                };
                let ok = if matches!(line.origin_value(), Context | Addition | Deletion) {
                    write!(buf, "{}", line.origin()).is_ok()
                } else {
                    true
                };
                ok && buf.write_all(line.content()).is_ok()
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            Ok(())
        })
    }
}

pub struct CoverLetter(Editmsg);

impl CoverLetter {
    pub fn new<P: AsRef<Path>>(git_dir: P) -> io::Result<Self> {
        Editmsg::new(git_dir.as_ref().join("NOTES_EDITMSG")).map(Self)
    }

    // TODO: render patch series a la git log
    pub fn edit(self) -> io::Result<Option<notes::Simple>> {
        let txt = self.0.edit(|buf| {
            writeln!(
                buf,
                "
# Please describe your patch as you would in a cover letter or PR.
# Lines starting with '#' will be ignored, and an empty message
# aborts the patch creation.
#
{SCISSORS}
# Do not modify or remove the line above.
# Everything below it will be ignored.
#
# Changes to be committed:

TODO (sorry)
"
            )?;

            Ok(())
        })?;

        Ok(txt.map(notes::Simple::new))
    }
}

pub struct Comment(Editmsg);

impl Comment {
    pub fn new<P: AsRef<Path>>(git_dir: P) -> io::Result<Self> {
        Editmsg::new(git_dir.as_ref().join("NOTES_EDITMSG")).map(Self)
    }

    pub fn edit(self, re: Option<&notes::Simple>) -> io::Result<Option<notes::Simple>> {
        let txt = self.0.edit(|buf| {
            write!(
                buf,
                "
# Enter your comment above. Lines starting with '#' will be ignored,
# and an empty message aborts the comment creation.
"
            )?;

            if let Some(prev) = re {
                write!(
                    buf,
                    "#
{SCISSORS}
# Do not modify or remove the line above.
# Everything below it will be ignored.
#
# Replying to:
"
                )?;

                serde_json::to_writer_pretty(buf, prev)?;
            }

            Ok(())
        })?;

        Ok(txt.map(notes::Simple::new))
    }
}

pub struct Metadata {
    _tmp: TempPath,
    msg: Editmsg,
}

impl Metadata {
    pub fn new() -> io::Result<Self> {
        let _tmp = tempfile::Builder::new()
            .suffix(".json")
            .tempfile()?
            .into_temp_path();
        let msg = Editmsg::new(&_tmp)?;

        Ok(Self { _tmp, msg })
    }

    // TODO: explainers, edit errors
    pub fn edit<T>(self, template: T) -> io::Result<Option<T>>
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let txt = self.msg.edit(|buf| {
            serde_json::to_writer_pretty(buf, &template)?;

            Ok(())
        })?;

        Ok(txt.as_deref().map(serde_json::from_str).transpose()?)
    }
}

struct Editmsg {
    file: LockedFile,
}

impl Editmsg {
    fn new<P: Into<PathBuf>>(path: P) -> io::Result<Self> {
        LockedFile::in_place(path, true, 0o644).map(|file| Self { file })
    }

    fn edit<F>(mut self, pre_fill: F) -> io::Result<Option<String>>
    where
        F: FnOnce(&mut LockedFile) -> io::Result<()>,
    {
        pre_fill(&mut self.file)?;
        Command::new(editor())
            .arg(self.file.edit_path())
            .spawn()?
            .wait()?;
        self.file.reopen()?;
        let mut msg = String::new();
        for line in io::BufReader::new(self.file).lines() {
            let line = line?;
            if line == SCISSORS {
                break;
            }
            if line.starts_with('#') {
                continue;
            }

            msg.push_str(&line);
            msg.push('\n');
        }
        let len = msg.trim_end().len();
        msg.truncate(len);

        Ok(if msg.is_empty() { None } else { Some(msg) })
    }
}

fn editor() -> OsString {
    #[cfg(windows)]
    const DEFAULT_EDITOR: &str = "notepad.exe";
    #[cfg(not(windows))]
    const DEFAULT_EDITOR: &str = "vi";

    if let Some(exe) = env::var_os("VISUAL") {
        return exe;
    }
    if let Some(exe) = env::var_os("EDITOR") {
        return exe;
    }
    DEFAULT_EDITOR.into()
}
