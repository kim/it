// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    borrow::Cow,
    env,
    ffi::OsStr,
    io,
    process::{
        self,
        Command,
        Stdio,
    },
};

use anyhow::ensure;
use console::Term;
use zeroize::Zeroizing;

use crate::{
    cmd::{
        self,
        Aborted,
    },
    patches::notes,
};

mod editor;
mod output;
pub use output::{
    debug,
    error,
    info,
    warn,
    Output,
};

pub fn edit_commit_message(
    repo: &git2::Repository,
    branch: &str,
    old: &git2::Tree,
    new: &git2::Tree,
) -> cmd::Result<String> {
    let diff = repo.diff_tree_to_tree(
        Some(old),
        Some(new),
        Some(
            git2::DiffOptions::new()
                .patience(true)
                .minimal(true)
                .context_lines(5),
        ),
    )?;
    abort_if_empty(
        "commit message",
        editor::Commit::new(repo.path())?.edit(branch, diff),
    )
}

pub fn edit_cover_letter(repo: &git2::Repository) -> cmd::Result<notes::Simple> {
    abort_if_empty(
        "cover letter",
        editor::CoverLetter::new(repo.path())?.edit(),
    )
}

pub fn edit_comment(
    repo: &git2::Repository,
    re: Option<&notes::Simple>,
) -> cmd::Result<notes::Simple> {
    abort_if_empty("comment", editor::Comment::new(repo.path())?.edit(re))
}

pub fn edit_metadata<T>(template: T) -> cmd::Result<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    abort_if_empty("metadata", editor::Metadata::new()?.edit(template))
}

fn abort_if_empty<T>(ctx: &str, edit: io::Result<Option<T>>) -> cmd::Result<T> {
    edit?.map(Ok).unwrap_or_else(|| {
        info!("Aborting due to empty {ctx}");
        cmd::abort!()
    })
}

pub fn askpass(prompt: &str) -> cmd::Result<Zeroizing<Vec<u8>>> {
    const DEFAULT_ASKPASS: &str = "ssh-askpass";

    fn ssh_askpass() -> Cow<'static, OsStr> {
        env::var_os("SSH_ASKPASS")
            .map(Into::into)
            .unwrap_or_else(|| OsStr::new(DEFAULT_ASKPASS).into())
    }

    let ssh = env::var_os("SSH_ASKPASS_REQUIRE").and_then(|require| {
        if require == "force" {
            Some(ssh_askpass())
        } else if require == "prefer" {
            env::var_os("DISPLAY").map(|_| ssh_askpass())
        } else {
            None
        }
    });

    match ssh {
        Some(cmd) => {
            let process::Output { status, stdout, .. } = Command::new(&cmd)
                .arg(prompt)
                .stderr(Stdio::inherit())
                .output()?;
            ensure!(
                status.success(),
                "{} failed with {:?}",
                cmd.to_string_lossy(),
                status.code()
            );
            Ok(Zeroizing::new(stdout))
        },
        None => {
            let tty = Term::stderr();
            if tty.is_term() {
                tty.write_line(prompt)?;
            }
            tty.read_secure_line()
                .map(|s| Zeroizing::new(s.into_bytes()))
                .map_err(Into::into)
        },
    }
}
