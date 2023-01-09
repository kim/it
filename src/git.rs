// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::process::{
    self,
    Command,
};

use anyhow::{
    anyhow,
    ensure,
    Context,
};
use once_cell::sync::Lazy;
use sha2::{
    Digest,
    Sha256,
};

mod commit;
pub use commit::{
    commit_signed,
    verify_commit_signature,
};

pub mod config;

pub mod refs;
pub use refs::{
    ReferenceNames,
    Refname,
};
pub mod repo;
pub use repo::add_alternates;
pub mod serde;

pub static EMPTY_TREE: Lazy<git2::Oid> =
    Lazy::new(|| git2::Oid::from_str("4b825dc642cb6eb9a060e54bf8d69288fbee4904").unwrap());

pub type Result<T> = core::result::Result<T, git2::Error>;

pub fn empty_tree(repo: &git2::Repository) -> Result<git2::Tree> {
    repo.find_tree(*EMPTY_TREE)
}

pub fn if_not_found_none<T>(r: Result<T>) -> Result<Option<T>> {
    if_not_found_then(r.map(Some), || Ok(None))
}

pub fn if_not_found_then<F, T>(r: Result<T>, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    r.or_else(|e| match e.code() {
        git2::ErrorCode::NotFound => f(),
        _ => Err(e),
    })
}

pub fn blob_hash(data: &[u8]) -> Result<git2::Oid> {
    // very minimally faster than going through libgit2. not sure yet if that's
    // worth the dependency.
    #[cfg(feature = "sha1dc")]
    {
        use sha1collisiondetection::Sha1CD;

        let mut hasher = Sha1CD::default();
        hasher.update("blob ");
        hasher.update(data.len().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(data);
        let hash = hasher.finalize_cd().expect("sha1 collision detected");
        git2::Oid::from_bytes(&hash)
    }
    #[cfg(not(feature = "sha1dc"))]
    git2::Oid::hash_object(git2::ObjectType::Blob, data)
}

pub fn blob_hash_sha2(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update("blob ");
    hasher.update(data.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(data);
    hasher.finalize().into()
}

/// Look up `key` from config and run the value as a command
pub fn config_command(cfg: &git2::Config, key: &str) -> crate::Result<Option<String>> {
    if_not_found_none(cfg.get_string(key))?
        .map(|cmd| {
            let process::Output { status, stdout, .. } = {
                let invalid = || anyhow!("'{cmd}' is not a valid command");
                let lex = shlex::split(&cmd).ok_or_else(invalid)?;
                let (bin, args) = lex.split_first().ok_or_else(invalid)?;
                Command::new(bin)
                    .args(args)
                    .stderr(process::Stdio::inherit())
                    .output()?
            };
            ensure!(status.success(), "'{cmd}' failed");
            const NL: u8 = b'\n';
            let line1 = stdout
                .into_iter()
                .take_while(|b| b != &NL)
                .collect::<Vec<_>>();
            ensure!(!line1.is_empty(), "no output from '{cmd}'");
            String::from_utf8(line1).with_context(|| format!("invalid output from '{cmd}'"))
        })
        .transpose()
}
