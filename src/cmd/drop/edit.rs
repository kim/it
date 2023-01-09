// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    iter,
    path::PathBuf,
};

use anyhow::{
    anyhow,
    ensure,
};

use super::{
    find_id,
    Common,
    Editable,
};
use crate::{
    cfg,
    cmd::{
        self,
        ui::{
            self,
            edit_commit_message,
            edit_metadata,
            info,
        },
        Aborted,
    },
    git::{
        self,
        refs,
        Refname,
    },
    json,
    keys::Signer,
    metadata::{
        self,
        git::{
            FromGit,
            GitDrop,
            META_FILE_ALTERNATES,
            META_FILE_DROP,
            META_FILE_MIRRORS,
        },
        IdentityId,
        Metadata,
    },
    patches::{
        self,
        REF_HEADS_PATCHES,
        REF_IT_PATCHES,
    },
};

#[derive(Debug, clap::Args)]
pub struct Edit {
    #[clap(flatten)]
    common: Common,
    /// Commit message for this edit
    ///
    /// Like git, $EDITOR will be invoked if not specified.
    #[clap(short, long, value_parser)]
    message: Option<String>,

    #[clap(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Debug, clap::Subcommand)]
enum Cmd {
    /// Edit the mirrors file
    Mirrors,
    /// Edit the alternates file
    Alternates,
}

#[derive(serde::Serialize)]
pub struct Output {
    repo: PathBuf,
    #[serde(rename = "ref")]
    refname: Refname,
    #[serde(with = "crate::git::serde::oid")]
    commit: git2::Oid,
}

pub fn edit(args: Edit) -> cmd::Result<Output> {
    let Common { git_dir, id_path } = args.common;

    let repo = git::repo::open(git_dir)?;
    let drop_ref = if repo.is_bare() {
        REF_HEADS_PATCHES
    } else {
        REF_IT_PATCHES
    }
    .parse()
    .unwrap();

    let id_path = id_path.open_git();
    git::add_alternates(&repo, &id_path)?;
    let cfg = repo.config()?.snapshot()?;
    let signer = cfg::signer(&cfg, ui::askpass)?;
    let signer_id = SignerIdentity::new(&signer, &repo, &cfg, &id_path)?;
    let meta = metadata::Drop::from_tip(&repo, &drop_ref)?;

    let s = EditState {
        repo,
        id_path,
        signer,
        signer_id,
        drop_ref,
        meta,
    };

    match args.cmd {
        None => s.edit_drop(args.message),
        Some(Cmd::Mirrors) => s.edit_mirrors(args.message),
        Some(Cmd::Alternates) => s.edit_alternates(args.message),
    }
}

struct EditState<S> {
    repo: git2::Repository,
    id_path: Vec<git2::Repository>,
    signer: S,
    signer_id: SignerIdentity,
    drop_ref: Refname,
    meta: GitDrop,
}

impl<S: Signer + 'static> EditState<S> {
    fn edit_drop(mut self, message: Option<String>) -> cmd::Result<Output> {
        let GitDrop {
            hash: parent_hash,
            signed: metadata::Signed { signed: parent, .. },
        } = self.meta;

        ensure!(
            self.signer_id.can_edit_drop(&parent),
            "signer identity not allowed to edit the drop metadata"
        );

        let mut meta: metadata::Drop = edit_metadata(Editable::from(parent.clone()))?.try_into()?;
        if meta.canonicalise()? == parent.canonicalise()? {
            info!("Document unchanged");
            cmd::abort!();
        }
        meta.prev = Some(parent_hash);

        let signed = Metadata::drop(&meta).sign(iter::once(&mut self.signer as &mut dyn Signer))?;

        let mut tx = refs::Transaction::new(&self.repo)?;
        let drop_ref = tx.lock_ref(self.drop_ref)?;

        let parent = self
            .repo
            .find_reference(drop_ref.name())?
            .peel_to_commit()?;
        let parent_tree = parent.tree()?;
        let mut root = self.repo.treebuilder(Some(&parent_tree))?;
        patches::Record::remove_from(&mut root)?;

        let mut ids = self
            .repo
            .treebuilder(get_tree(&self.repo, &root, "ids")?.as_ref())?;
        let identities = meta
            .roles
            .ids()
            .into_iter()
            .map(|id| find_id(&self.repo, &self.id_path, &id).map(|signed| (id, signed)))
            .collect::<Result<Vec<_>, _>>()?;
        for (iid, id) in identities {
            let iid = iid.to_string();
            let mut tb = self
                .repo
                .treebuilder(get_tree(&self.repo, &ids, &iid)?.as_ref())?;
            metadata::identity::fold_to_tree(&self.repo, &mut tb, id)?;
            ids.insert(&iid, tb.write()?, git2::FileMode::Tree.into())?;
        }
        root.insert("ids", ids.write()?, git2::FileMode::Tree.into())?;

        root.insert(
            META_FILE_DROP,
            json::to_blob(&self.repo, &signed)?,
            git2::FileMode::Blob.into(),
        )?;
        let tree = self.repo.find_tree(root.write()?)?;

        let msg = message.map(Ok).unwrap_or_else(|| {
            edit_commit_message(&self.repo, drop_ref.name(), &parent_tree, &tree)
        })?;
        let commit = git::commit_signed(&mut self.signer, &self.repo, msg, &tree, &[&parent])?;
        drop_ref.set_target(commit, "it: metadata edit");

        tx.commit()?;

        Ok(Output {
            repo: self.repo.path().to_owned(),
            refname: drop_ref.into(),
            commit,
        })
    }

    pub fn edit_mirrors(mut self, message: Option<String>) -> cmd::Result<Output> {
        ensure!(
            self.signer_id.can_edit_mirrors(&self.meta.signed.signed),
            "signer identity not allowed to edit mirrors"
        );

        let prev = metadata::Mirrors::from_tip(&self.repo, &self.drop_ref)
            .map(|m| m.signed.signed)
            .or_else(|e| {
                if e.is::<metadata::git::error::FileNotFound>() {
                    Ok(Default::default())
                } else {
                    Err(e)
                }
            })?;
        let prev_canonical = prev.canonicalise()?;
        let meta = edit_metadata(prev)?;
        if meta.canonicalise()? == prev_canonical {
            info!("Document unchanged");
            cmd::abort!();
        }

        let signed =
            Metadata::mirrors(meta).sign(iter::once(&mut self.signer as &mut dyn Signer))?;

        let mut tx = refs::Transaction::new(&self.repo)?;
        let drop_ref = tx.lock_ref(self.drop_ref)?;

        let parent = self
            .repo
            .find_reference(drop_ref.name())?
            .peel_to_commit()?;
        let parent_tree = parent.tree()?;
        let mut root = self.repo.treebuilder(Some(&parent_tree))?;
        patches::Record::remove_from(&mut root)?;
        root.insert(
            META_FILE_MIRRORS,
            json::to_blob(&self.repo, &signed)?,
            git2::FileMode::Blob.into(),
        )?;
        let tree = self.repo.find_tree(root.write()?)?;

        let msg = message.map(Ok).unwrap_or_else(|| {
            edit_commit_message(&self.repo, drop_ref.name(), &parent_tree, &tree)
        })?;
        let commit = git::commit_signed(&mut self.signer, &self.repo, msg, &tree, &[&parent])?;
        drop_ref.set_target(commit, "it: mirrors edit");

        tx.commit()?;

        Ok(Output {
            repo: self.repo.path().to_owned(),
            refname: drop_ref.into(),
            commit,
        })
    }

    pub fn edit_alternates(mut self, message: Option<String>) -> cmd::Result<Output> {
        ensure!(
            self.signer_id.can_edit_mirrors(&self.meta.signed.signed),
            "signer identity not allowed to edit alternates"
        );

        let prev = metadata::Alternates::from_tip(&self.repo, &self.drop_ref)
            .map(|m| m.signed.signed)
            .or_else(|e| {
                if e.is::<metadata::git::error::FileNotFound>() {
                    Ok(Default::default())
                } else {
                    Err(e)
                }
            })?;
        let prev_canonical = prev.canonicalise()?;
        let meta = edit_metadata(prev)?;
        if meta.canonicalise()? == prev_canonical {
            info!("Document unchanged");
            cmd::abort!();
        }

        let signed =
            Metadata::alternates(meta).sign(iter::once(&mut self.signer as &mut dyn Signer))?;

        let mut tx = refs::Transaction::new(&self.repo)?;
        let drop_ref = tx.lock_ref(self.drop_ref)?;

        let parent = self
            .repo
            .find_reference(drop_ref.name())?
            .peel_to_commit()?;
        let parent_tree = parent.tree()?;
        let mut root = self.repo.treebuilder(Some(&parent_tree))?;
        patches::Record::remove_from(&mut root)?;
        root.insert(
            META_FILE_ALTERNATES,
            json::to_blob(&self.repo, &signed)?,
            git2::FileMode::Blob.into(),
        )?;
        let tree = self.repo.find_tree(root.write()?)?;

        let msg = message.map(Ok).unwrap_or_else(|| {
            edit_commit_message(&self.repo, drop_ref.name(), &parent_tree, &tree)
        })?;
        let commit = git::commit_signed(&mut self.signer, &self.repo, msg, &tree, &[&parent])?;
        drop_ref.set_target(commit, "it: alternates edit");

        tx.commit()?;

        Ok(Output {
            repo: self.repo.path().to_owned(),
            refname: drop_ref.into(),
            commit,
        })
    }
}

fn get_tree<'a>(
    repo: &'a git2::Repository,
    builder: &git2::TreeBuilder,
    name: &str,
) -> cmd::Result<Option<git2::Tree<'a>>> {
    if let Some(entry) = builder.get(name)? {
        return Ok(Some(
            entry
                .to_object(repo)?
                .into_tree()
                .map_err(|_| anyhow!("{name} is not a tree"))?,
        ));
    }

    Ok(None)
}

struct SignerIdentity {
    id: IdentityId,
}

impl SignerIdentity {
    pub fn new<S: Signer>(
        signer: &S,
        repo: &git2::Repository,
        cfg: &git2::Config,
        id_path: &[git2::Repository],
    ) -> cmd::Result<Self> {
        let id =
            cfg::git::identity(cfg)?.ok_or_else(|| anyhow!("signer identity not in gitconfig"))?;
        let meta = find_id(repo, id_path, &id)?;
        let keyid = metadata::KeyId::from(signer.ident());

        ensure!(
            meta.signed.keys.contains_key(&keyid),
            "signing key {keyid} is not in identity {id}"
        );

        Ok(Self { id })
    }

    pub fn can_edit_drop(&self, parent: &metadata::Drop) -> bool {
        parent.roles.root.ids.contains(&self.id)
    }

    pub fn can_edit_mirrors(&self, parent: &metadata::Drop) -> bool {
        parent.roles.mirrors.ids.contains(&self.id)
    }
}
