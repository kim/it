// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::collections::BTreeMap;

use anyhow::{
    anyhow,
    bail,
    ensure,
    Context as _,
};

use super::{
    edit,
    Common,
};
use crate::{
    cfg,
    cmd::{
        self,
        args::Refname,
        id::META_FILE_ID,
        ui::{
            self,
            edit_commit_message,
            info,
        },
        FromGit as _,
        GitIdentity,
    },
    git::{
        self,
        if_not_found_none,
        refs,
    },
    metadata,
};

#[derive(Debug, clap::Args)]
pub struct Sign {
    #[clap(flatten)]
    common: Common,
    /// Commit to this branch if the signature threshold is met
    #[clap(short = 'b', long, value_parser, value_name = "REF")]
    commit_to: Refname,
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

pub fn sign(args: Sign) -> cmd::Result<Output> {
    let (repo, refname) = args.common.resolve()?;
    let mut tx = refs::Transaction::new(&repo)?;
    let _tip = tx.lock_ref(refname.clone())?;

    let GitIdentity {
        signed:
            metadata::Signed {
                signed: proposed,
                signatures: proposed_signatures,
            },
        ..
    } = metadata::Identity::from_tip(&repo, &refname)?;
    let prev_hash: git2::Oid = proposed
        .prev
        .as_ref()
        .ok_or_else(|| anyhow!("cannot sign a genesis revision"))?
        .into();
    let (parent, target_ref) = if refname == args.commit_to {
        // Signing in-place is only legal if the proposed update already
        // meets the signature threshold
        let _ = proposed
            .verify(&proposed_signatures, cmd::find_parent(&repo))
            .context("proposed update does not meet the signature threshold")?;
        (proposed.clone(), repo.find_reference(&args.commit_to)?)
    } else {
        let target_ref = if_not_found_none(repo.find_reference(&args.commit_to))?;
        match target_ref {
            // If the target ref exists, it must yield a verified id.json whose
            // blob hash equals the 'prev' hash of the proposed update
            Some(tgt) => {
                let parent_commit = tgt.peel_to_commit()?;
                let GitIdentity {
                    hash: parent_hash,
                    signed:
                        metadata::Signed {
                            signed: parent,
                            signatures: parent_signatures,
                        },
                } = metadata::Identity::from_commit(&repo, &parent_commit).with_context(|| {
                    format!("failed to load {} from {}", META_FILE_ID, &args.commit_to)
                })?;
                let _ = parent
                    .verify(&parent_signatures, cmd::find_parent(&repo))
                    .with_context(|| format!("target {} could not be verified", &args.commit_to))?;
                ensure!(
                    parent_hash == prev_hash,
                    "parent hash (.prev) doesn't match"
                );

                (parent, tgt)
            },

            // If the target ref is unborn, the proposed's parent commit must
            // yield a verified id.json, as we will create the target from
            // HEAD^1
            None => {
                let parent_commit = repo
                    .find_reference(&refname)?
                    .peel_to_commit()?
                    .parents()
                    .next()
                    .ok_or_else(|| anyhow!("cannot sign an initial commit"))?;
                let GitIdentity {
                    hash: parent_hash,
                    signed:
                        metadata::Signed {
                            signed: parent,
                            signatures: parent_signatures,
                        },
                } = metadata::Identity::from_commit(&repo, &parent_commit)?;
                let _ = parent
                    .verify(&parent_signatures, cmd::find_parent(&repo))
                    .with_context(|| {
                        format!(
                            "parent commit {} of {} could not be verified",
                            parent_commit.id(),
                            refname
                        )
                    })?;
                ensure!(
                    parent_hash == prev_hash,
                    "parent hash (.prev) doesn't match"
                );

                let tgt = repo.reference(
                    &args.commit_to,
                    parent_commit.id(),
                    false,
                    &format!("branch: Created from {}^1", refname),
                )?;

                (parent, tgt)
            },
        }
    };
    let commit_to = tx.lock_ref(args.commit_to)?;

    let canonical = proposed.canonicalise()?;
    let mut signer = cfg::signer(&repo.config()?, ui::askpass)?;
    let mut signatures = BTreeMap::new();
    let keyid = metadata::KeyId::from(signer.ident());
    if !parent.keys.contains_key(&keyid) && !proposed.keys.contains_key(&keyid) {
        bail!("key {} is not eligible to sign the document", keyid);
    }
    if proposed_signatures.contains_key(&keyid) {
        bail!("proposed update is already signed with key {}", keyid);
    }

    let signature = signer.sign(&canonical)?;
    signatures.insert(keyid, metadata::Signature::from(signature));
    signatures.extend(proposed_signatures);

    let _ = proposed
        .verify(&signatures, cmd::find_parent(&repo))
        .context("proposal could not be verified after signing")?;

    let signed = metadata::Signed {
        signed: metadata::Metadata::identity(proposed),
        signatures,
    };

    let parent_commit = target_ref.peel_to_commit()?;
    let parent_tree = parent_commit.tree()?;
    let on_head = !repo.is_bare() && git2::Branch::wrap(target_ref).is_head();

    let tree = if on_head {
        edit::write_tree(&repo, &signed)
    } else {
        edit::write_tree_bare(&repo, &signed, Some(&parent_tree))
    }?;
    let msg = args
        .message
        .map(Ok)
        .unwrap_or_else(|| edit_commit_message(&repo, commit_to.name(), &parent_tree, &tree))?;
    let commit = git::commit_signed(&mut signer, &repo, msg, &tree, &[&parent_commit])?;
    commit_to.set_target(commit, "it: identity signoff");

    tx.commit()?;

    if on_head {
        repo.checkout_tree(
            tree.as_object(),
            Some(git2::build::CheckoutBuilder::new().safe()),
        )?;
        info!("Checked out tree {}", tree.id());
    }

    Ok(Output {
        refname: commit_to.into(),
        commit,
    })
}
