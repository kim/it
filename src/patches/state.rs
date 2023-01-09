// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    io,
    ops::Range,
};

use anyhow::{
    anyhow,
    ensure,
    Context,
};
use log::warn;

use super::{
    Record,
    TrackingBranch,
};
use crate::{
    git::{
        self,
        if_not_found_none,
        refs::{
            self,
            LockedRef,
        },
        Refname,
    },
    keys::VerificationKey,
    metadata::{
        self,
        git::FromGit,
        identity,
    },
    Result,
};

/// Somewhat ad-hoc view of the tip of a drop
pub struct DropHead<'a> {
    pub tip: git2::Reference<'a>,
    pub ids: git2::Tree<'a>,
    pub meta: metadata::drop::Verified,
}

impl<'a> DropHead<'a> {
    pub fn from_refname<S: AsRef<str>>(repo: &'a git2::Repository, name: S) -> crate::Result<Self> {
        let tip = repo.find_reference(name.as_ref())?;
        let root = tip.peel_to_tree()?;
        let ids = root
            .get_name("ids")
            .ok_or_else(|| anyhow!("invalid drop: 'ids' tree not found"))?
            .to_object(repo)?
            .into_tree()
            .map_err(|_| anyhow!("invalid drop: 'ids' tree is not a tree"))?;
        let meta = metadata::Drop::from_tree(repo, &root)
            .context("error loading drop metadata")?
            .verified(metadata::git::find_parent(repo), |id| {
                metadata::identity::find_in_tree(repo, &ids, id)
                    .map(|verified| verified.into_parts().1.keys)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            })?;

        Ok(Self { tip, ids, meta })
    }
}

pub fn unbundle(
    odb: &git2::Odb,
    tx: &mut refs::Transaction,
    ref_prefix: &str,
    record: &Record,
) -> Result<Vec<(Refname, git2::Oid)>> {
    let reflog = format!("it: storing head from {}", record.bundle_hash());

    let mut updated = Vec::with_capacity(record.meta.bundle.references.len());
    for (name, oid) in &record.meta.bundle.references {
        let oid = git2::Oid::try_from(oid)?;
        ensure!(odb.exists(oid), "ref not actually in bundle: {oid} {name}");

        let by_heads = unbundled_ref(ref_prefix, record, name)?;
        tx.lock_ref(by_heads.clone())?
            .set_target(oid, reflog.clone());
        updated.push((by_heads, oid));
    }

    Ok(updated)
}

pub fn unbundled_ref(prefix: &str, record: &Record, name: &Refname) -> Result<Refname> {
    format!(
        "{}/{}/{}",
        prefix.trim_matches('/'),
        record.heads,
        name.trim_start_matches("refs/")
    )
    .try_into()
    .map_err(Into::into)
}

pub fn merge_notes(
    repo: &git2::Repository,
    submitter: &identity::Verified,
    topics_ref: &LockedRef,
    record: &Record,
) -> Result<()> {
    let theirs: git2::Oid = record
        .meta
        .bundle
        .references
        .get(topics_ref.name())
        .ok_or_else(|| anyhow!("invalid record: missing '{topics_ref}'"))?
        .try_into()?;

    let tree = git::empty_tree(repo)?;
    let usr = repo.signature()?;
    let theirs_commit = repo.find_commit(theirs)?;
    match if_not_found_none(repo.find_reference(topics_ref.name()))? {
        None => {
            let msg = format!(
                "Create topic from '{theirs}'\n\n{}",
                record.heads.as_trailer()
            );
            let oid = repo.commit(None, &usr, &usr, &msg, &tree, &[&theirs_commit])?;
            topics_ref.set_target(oid, "it: create topic");
        },
        Some(ours_ref) => {
            let ours_commit = ours_ref.peel_to_commit()?;
            let ours = ours_commit.id();

            ensure!(ours != theirs, "illegal state: theirs equals ours ({ours})");

            let base = repo
                .merge_base(ours, theirs)
                .with_context(|| format!("{topics_ref}: {theirs} diverges from {ours}"))?;
            let theirs_commit = repo.find_commit(theirs)?;

            verify_commit_range(repo, submitter, theirs_commit.id()..base)?;

            let msg = format!(
                "Merge '{theirs}' into {}\n\n{}",
                record.topic,
                record.heads.as_trailer()
            );
            let oid = repo.commit(
                None,
                &usr,
                &usr,
                &msg,
                &tree,
                &[&ours_commit, &theirs_commit],
            )?;
            let reflog = format!("it: auto-merge from {theirs}");
            topics_ref.set_target(oid, reflog);
        },
    }

    Ok(())
}

pub fn update_branches(
    repo: &git2::Repository,
    tx: &mut refs::Transaction,
    submitter: &identity::Verified,
    meta: &metadata::drop::Verified,
    record: &Record,
) -> Result<()> {
    let branches = meta
        .roles
        .branches
        .iter()
        .filter_map(|(name, role)| role.role.ids.contains(submitter.id()).then_some(name));
    for branch in branches {
        let sandboxed = match TrackingBranch::try_from(branch) {
            Ok(tracking) => tracking.into_refname(),
            Err(e) => {
                warn!("Skipping invalid branch {branch}: {e}");
                continue;
            },
        };

        if let Some(target) = record.meta.bundle.references.get(branch) {
            let target = git2::Oid::try_from(target)?;
            let locked = tx.lock_ref(sandboxed.clone())?;
            let reflog = format!(
                "it: update tip from {} by {}",
                record.bundle_hash(),
                submitter.id()
            );
            match if_not_found_none(repo.refname_to_id(&sandboxed))? {
                Some(ours) => {
                    ensure!(
                        repo.graph_descendant_of(target, ours)?,
                        "checkpoint branch {branch} diverges from previously recorded tip {target}"
                    );
                    locked.set_target(target, reflog);
                },
                None => locked.set_target(target, reflog),
            }

            if repo.is_bare() {
                tx.lock_ref(branch.clone())?
                    .set_symbolic_target(sandboxed, "it: symref auto-updated branch".to_owned());
            }
        }
    }

    Ok(())
}

fn verify_commit_range(
    repo: &git2::Repository,
    allowed: &identity::Verified,
    Range { start, end }: Range<git2::Oid>,
) -> Result<()> {
    let mut walk = repo.revwalk()?;
    walk.push(start)?;
    walk.hide(end)?;
    walk.simplify_first_parent()?;
    walk.set_sorting(git2::Sort::TOPOLOGICAL)?;
    for id in walk {
        let pk = git::verify_commit_signature(repo, &id?)?;
        let keyid = VerificationKey::from(pk).keyid();
        ensure!(
            allowed.identity().keys.contains_key(&keyid),
            "good signature by unknown signer"
        );
    }

    Ok(())
}
