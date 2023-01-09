// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    fs::File,
    iter,
    path::Path,
};

use anyhow::{
    anyhow,
    bail,
    ensure,
    Context,
};

use super::{
    Common,
    Editable,
    META_FILE_ID,
};
use crate::{
    cfg,
    cmd::{
        self,
        args::Refname,
        ui::{
            self,
            edit_commit_message,
            edit_metadata,
            info,
            warn,
        },
        Aborted,
        FromGit as _,
        GitIdentity,
    },
    git::{
        self,
        refs,
    },
    json,
    metadata::{
        self,
        Metadata,
    },
};

#[derive(Debug, clap::Args)]
#[allow(rustdoc::bare_urls)]
pub struct Edit {
    #[clap(flatten)]
    common: Common,
    /// Commit to this branch to propose the update
    ///
    /// If not given, the edit is performed in-place if the signature threshold
    /// is met using the supplied keys.
    #[clap(long, value_parser)]
    propose_as: Option<Refname>,
    /// Check out the committed changes
    ///
    /// Only has an effect if the repository is non-bare.
    #[clap(long, value_parser)]
    checkout: bool,
    /// Don't commit anything to disk
    #[clap(long, value_parser)]
    dry_run: bool,
    /// Commit message for this edit
    ///
    /// Like git, $EDITOR will be invoked if not specified.
    #[clap(short, long, value_parser)]
    message: Option<String>,
}

#[derive(serde::Serialize)]
pub struct Output {
    #[serde(rename = "ref")]
    refname: Refname,
    #[serde(with = "crate::git::serde::oid")]
    commit: git2::Oid,
}

pub fn edit(args: Edit) -> cmd::Result<Output> {
    let (repo, refname) = args.common.resolve()?;

    let GitIdentity {
        hash: parent_hash,
        signed: metadata::Signed { signed: parent, .. },
    } = metadata::Identity::from_tip(&repo, &refname)?;

    let mut id: metadata::Identity = edit_metadata(Editable::from(parent.clone()))?.try_into()?;
    if id.canonicalise()? == parent.canonicalise()? {
        info!("Document unchanged");
        cmd::abort!();
    }
    id.prev = Some(parent_hash.clone());

    let cfg = repo.config()?;
    let mut signer = cfg::signer(&cfg, ui::askpass)?;
    let keyid = metadata::KeyId::from(signer.ident());
    ensure!(
        parent.keys.contains_key(&keyid) || id.keys.contains_key(&keyid),
        "signing key {keyid} is not eligible to sign the document"
    );
    let signed = Metadata::identity(&id).sign(iter::once(&mut signer))?;

    let commit_to = match id.verify(&signed.signatures, cmd::find_parent(&repo)) {
        Ok(_) => args.propose_as.as_ref().unwrap_or(&refname),
        Err(metadata::error::Verification::SignatureThreshold) => match &args.propose_as {
            None => bail!("cannot update {refname} in place as signature threshold is not met"),
            Some(tgt) => {
                warn!("Signature threshold is not met");
                tgt
            },
        },
        Err(e) => bail!(e),
    };

    let mut tx = refs::Transaction::new(&repo)?;

    let _tip = tx.lock_ref(refname.clone())?;
    let tip = repo.find_reference(_tip.name())?;
    let parent_commit = tip.peel_to_commit()?;
    let parent_tree = parent_commit.tree()?;
    // check that parent is valid
    {
        let entry = parent_tree.get_name(META_FILE_ID).ok_or_else(|| {
            anyhow!("{refname} was modified concurrently, {META_FILE_ID} not found in tree")
        })?;
        ensure!(
            parent_hash == entry.to_object(&repo)?.peel_to_blob()?.id(),
            "{refname} was modified concurrently",
        );
    }
    let commit_to = tx.lock_ref(commit_to.clone())?;
    let on_head =
        !repo.is_bare() && git2::Branch::wrap(repo.find_reference(commit_to.name())?).is_head();

    let tree = if on_head {
        write_tree(&repo, &signed)
    } else {
        write_tree_bare(&repo, &signed, Some(&parent_tree))
    }?;
    let msg = args
        .message
        .map(Ok)
        .unwrap_or_else(|| edit_commit_message(&repo, commit_to.name(), &parent_tree, &tree))?;
    let commit = git::commit_signed(&mut signer, &repo, msg, &tree, &[&parent_commit])?;
    commit_to.set_target(commit, "it: edit identity");

    tx.commit()?;

    if args.checkout && repo.is_bare() {
        bail!("repository is bare, refusing checkout");
    }
    if args.checkout || on_head {
        repo.checkout_tree(
            tree.as_object(),
            Some(git2::build::CheckoutBuilder::new().safe()),
        )?;
        repo.set_head(commit_to.name())?;
        info!("Switched to branch '{commit_to}'");
    }

    Ok(Output {
        refname: commit_to.into(),
        commit,
    })
}

pub(super) fn write_tree<'a>(
    repo: &'a git2::Repository,
    meta: &metadata::Signed<metadata::Metadata>,
) -> crate::Result<git2::Tree<'a>> {
    ensure!(
        repo.statuses(None)?.is_empty(),
        "uncommitted changes in working tree. Please commit or stash them before proceeding"
    );
    let id_json = repo
        .workdir()
        .expect("non-bare repo ought to have a workdir")
        .join(META_FILE_ID);
    let out = File::options()
        .write(true)
        .truncate(true)
        .open(&id_json)
        .with_context(|| format!("error opening {} for writing", id_json.display()))?;
    serde_json::to_writer_pretty(&out, meta)
        .with_context(|| format!("serialising to {} failed", id_json.display()))?;

    let mut index = repo.index()?;
    index.add_path(Path::new(META_FILE_ID))?;
    let oid = index.write_tree()?;

    Ok(repo.find_tree(oid)?)
}

pub(super) fn write_tree_bare<'a>(
    repo: &'a git2::Repository,
    meta: &metadata::Signed<metadata::Metadata>,
    from: Option<&git2::Tree>,
) -> crate::Result<git2::Tree<'a>> {
    let blob = json::to_blob(repo, meta)?;
    let mut bld = repo.treebuilder(from)?;
    bld.insert(META_FILE_ID, blob, git2::FileMode::Blob.into())?;
    let oid = bld.write()?;

    Ok(repo.find_tree(oid)?)
}
