// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    iter,
    num::NonZeroUsize,
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
        args::Refname,
        ui::{
            self,
            edit_metadata,
        },
    },
    git::{
        self,
        if_not_found_none,
        refs,
    },
    json,
    metadata::{
        self,
        git::META_FILE_DROP,
        Metadata,
    },
    patches::{
        REF_HEADS_PATCHES,
        REF_IT_PATCHES,
    },
};

#[derive(Debug, clap::Args)]
pub struct Init {
    #[clap(flatten)]
    common: Common,
    /// A description for this drop instance, max. 128 characters
    #[clap(long, value_parser, value_name = "STRING")]
    description: metadata::drop::Description,
    /// If the repository does not already exist, initialise it as non-bare
    ///
    /// A drop is usually initialised inside an already existing git repository,
    /// or as a standalone drop repository. The latter is advisable for serving
    /// over the network.
    ///
    /// When init is given a directory which does not already exist, it is
    /// assumed that a standalone drop should be created, and thus the
    /// repository is initialised as bare. This behaviour can be overridden
    /// by --no-bare.
    #[clap(long, value_parser)]
    no_bare: bool,
}

#[derive(serde::Serialize)]
pub struct Output {
    repo: PathBuf,
    #[serde(rename = "ref")]
    refname: Refname,
    #[serde(with = "crate::git::serde::oid")]
    commit: git2::Oid,
}

pub fn init(args: Init) -> cmd::Result<Output> {
    let Common { git_dir, id_path } = args.common;
    let drop_ref: Refname = REF_IT_PATCHES.parse().unwrap();

    let repo = git::repo::open_or_init(
        git_dir,
        git::repo::InitOpts {
            bare: !args.no_bare,
            description: "`it` drop",
            initial_head: &drop_ref,
        },
    )?;

    let mut tx = refs::Transaction::new(&repo)?;
    let drop_ref = tx.lock_ref(drop_ref)?;
    ensure!(
        if_not_found_none(repo.refname_to_id(drop_ref.name()))?.is_none(),
        "{} already exists",
        drop_ref
    );

    let id_path = id_path.open_git();
    git::add_alternates(&repo, &id_path)?;

    let cfg = repo.config()?.snapshot()?;
    let mut signer = cfg::signer(&cfg, ui::askpass)?;
    let signer_id = {
        let iid =
            cfg::git::identity(&cfg)?.ok_or_else(|| anyhow!("signer identity not in gitconfig"))?;
        let id = find_id(&repo, &id_path, &iid)?;
        let keyid = metadata::KeyId::from(signer.ident());
        ensure!(
            id.signed.keys.contains_key(&keyid),
            "signing key {keyid} is not in identity {iid}"
        );

        iid
    };

    let default = {
        let default_role = metadata::drop::Role {
            ids: [signer_id].into(),
            threshold: NonZeroUsize::new(1).unwrap(),
        };
        let default_branch = cfg::git::default_branch(&cfg)?;

        metadata::Drop {
            fmt_version: Default::default(),
            description: args.description,
            prev: None,
            custom: Default::default(),
            roles: metadata::drop::Roles {
                root: default_role.clone(),
                snapshot: default_role.clone(),
                mirrors: default_role.clone(),
                branches: [(
                    default_branch,
                    metadata::drop::Annotated {
                        role: default_role,
                        description: metadata::drop::Description::try_from(
                            "the default branch".to_owned(),
                        )
                        .unwrap(),
                    },
                )]
                .into(),
            },
        }
    };
    let meta: metadata::Drop = edit_metadata(Editable::from(default))?.try_into()?;
    ensure!(
        meta.roles.root.ids.contains(&signer_id),
        "signing identity {signer_id} is lacking the drop role required to sign the metadata"
    );
    let signed = Metadata::drop(&meta).sign(iter::once(&mut signer))?;

    let mut root = repo.treebuilder(None)?;
    let mut ids = repo.treebuilder(None)?;
    let identities = meta
        .roles
        .ids()
        .into_iter()
        .map(|id| find_id(&repo, &id_path, &id).map(|signed| (id, signed)))
        .collect::<Result<Vec<_>, _>>()?;
    for (iid, id) in identities {
        let iid = iid.to_string();
        let mut tb = repo.treebuilder(None)?;
        metadata::identity::fold_to_tree(&repo, &mut tb, id)?;
        ids.insert(&iid, tb.write()?, git2::FileMode::Tree.into())?;
    }
    root.insert("ids", ids.write()?, git2::FileMode::Tree.into())?;
    root.insert(
        META_FILE_DROP,
        json::to_blob(&repo, &signed)?,
        git2::FileMode::Blob.into(),
    )?;
    let tree = repo.find_tree(root.write()?)?;
    let msg = format!("Create drop '{}'", meta.description);
    let commit = git::commit_signed(&mut signer, &repo, msg, &tree, &[])?;

    if repo.is_bare() {
        // Arrange refs to be `git-clone`-friendly
        let heads_patches = tx.lock_ref(REF_HEADS_PATCHES.parse()?)?;
        heads_patches.set_target(commit, "it: create");
        drop_ref.set_symbolic_target(heads_patches.name().clone(), String::new());
        repo.set_head(heads_patches.name())?;
    } else {
        drop_ref.set_target(commit, "it: create");
    }

    tx.commit()?;

    Ok(Output {
        repo: repo.path().to_owned(),
        refname: drop_ref.into(),
        commit,
    })
}
