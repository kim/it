// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use core::{
    iter,
    num::NonZeroUsize,
};
use std::path::PathBuf;

use anyhow::ensure;
use clap::ValueHint;
use url::Url;

use super::{
    Editable,
    META_FILE_ID,
};
use crate::{
    cfg::{
        self,
        paths,
    },
    cmd::{
        self,
        args::Refname,
        ui::{
            self,
            edit_metadata,
            info,
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
        DateTime,
        Key,
        KeySet,
    },
};

#[derive(Debug, clap::Args)]
pub struct Init {
    /// Path to the 'keyring' repository
    #[clap(
        long,
        value_parser,
        value_name = "DIR",
        env = "GIT_DIR",
        default_value_os_t = paths::ids(),
        value_hint = ValueHint::DirPath,
    )]
    git_dir: PathBuf,
    /// If the repository does not already exist, initialise it as non-bare
    ///
    /// Having the identity files checked out into a work tree may make it
    /// easier to manipulate them with external tooling. Note, however, that
    /// only committed files are considered by `it`.
    #[clap(long, value_parser)]
    no_bare: bool,
    /// Set this identity as the default in the user git config
    #[clap(long, value_parser)]
    set_default: bool,
    /// Additional public key to add to the identity; may be given multiple
    /// times
    #[clap(short, long, value_parser)]
    public: Vec<Key<'static>>,
    /// Threshold of keys required to sign the next revision
    #[clap(long, value_parser)]
    threshold: Option<NonZeroUsize>,
    /// Alternate location where the identity history is published to; may be
    /// given multiple times
    #[clap(
        long = "mirror",
        value_parser,
        value_name = "URL",
        value_hint = ValueHint::Url,
    )]
    mirrors: Vec<Url>,
    /// Optional date/time after which the current revision of the identity
    /// should no longer be considered valid
    #[clap(long, value_parser, value_name = "DATETIME")]
    expires: Option<DateTime>,
    /// Custom data
    ///
    /// The data must be parseable as canonical JSON, ie. not contain any
    /// floating point values.
    #[clap(
        long,
        value_parser,
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
    )]
    custom: Option<PathBuf>,
    /// Stop for editing the metadata in $EDITOR
    #[clap(long, value_parser)]
    edit: bool,
    /// Don't commit anything to disk
    #[clap(long, value_parser)]
    dry_run: bool,
}

#[derive(serde::Serialize)]
pub struct Output {
    #[serde(skip_serializing_if = "Option::is_none")]
    committed: Option<Committed>,
    data: metadata::Signed<metadata::Metadata<'static>>,
}

#[derive(serde::Serialize)]
pub struct Committed {
    repo: PathBuf,
    #[serde(rename = "ref")]
    refname: Refname,
    #[serde(with = "crate::git::serde::oid")]
    commit: git2::Oid,
}

pub fn init(args: Init) -> cmd::Result<Output> {
    let git_dir = args.git_dir;
    info!("Initialising fresh identity at {}", git_dir.display());

    let custom = args.custom.map(json::load).transpose()?.unwrap_or_default();
    let cfg = git2::Config::open_default()?;
    let mut signer = cfg::signer(&cfg, ui::askpass)?;
    let threshold = match args.threshold {
        None => NonZeroUsize::new(1)
            .unwrap()
            .saturating_add(args.public.len() / 2),
        Some(t) => {
            ensure!(
                t.get() < args.public.len(),
                "threshold must be smaller than the number of keys"
            );
            t
        },
    };

    let signer_id = signer.ident().to_owned();
    let keys = iter::once(signer_id.clone())
        .map(metadata::Key::from)
        .chain(args.public)
        .collect::<KeySet>();

    let meta = {
        let id = metadata::Identity {
            spec_version: crate::SPEC_VERSION,
            prev: None,
            keys,
            threshold,
            mirrors: args.mirrors.into_iter().collect(),
            expires: args.expires,
            custom,
        };

        if args.edit {
            edit_metadata(Editable::from(id))?.try_into()?
        } else {
            id
        }
    };
    let sigid = metadata::IdentityId::try_from(&meta).unwrap();
    let signed = metadata::Metadata::identity(meta).sign(iter::once(&mut signer))?;

    let out = if !args.dry_run {
        let id_ref = Refname::try_from(format!("refs/heads/it/ids/{}", sigid)).unwrap();
        let repo = git::repo::open_or_init(
            git_dir,
            git::repo::InitOpts {
                bare: !args.no_bare,
                description: "`it` keyring",
                initial_head: &id_ref,
            },
        )?;

        let mut tx = refs::Transaction::new(&repo)?;
        let id_ref = tx.lock_ref(id_ref)?;
        ensure!(
            if_not_found_none(repo.refname_to_id(id_ref.name()))?.is_none(),
            "{id_ref} already exists",
        );

        let blob = json::to_blob(&repo, &signed)?;
        let tree = {
            let mut bld = repo.treebuilder(None)?;
            bld.insert(META_FILE_ID, blob, git2::FileMode::Blob.into())?;
            let oid = bld.write()?;
            repo.find_tree(oid)?
        };
        let msg = format!("Create identity {}", sigid);
        let oid = git::commit_signed(&mut signer, &repo, msg, &tree, &[])?;
        id_ref.set_target(oid, "it: create");

        let mut cfg = repo.config()?;
        cfg.set_str(
            cfg::git::USER_SIGNING_KEY,
            &format!("key::{}", signer_id.to_openssh()?),
        )?;
        let idstr = sigid.to_string();
        cfg.set_str(cfg::git::IT_ID, &idstr)?;
        if args.set_default {
            cfg.open_global()?.set_str(cfg::git::IT_ID, &idstr)?;
        }

        tx.commit()?;
        if !repo.is_bare() {
            repo.checkout_head(None).ok();
        }

        Output {
            committed: Some(Committed {
                repo: repo.path().to_owned(),
                refname: id_ref.into(),
                commit: oid,
            }),
            data: signed,
        }
    } else {
        Output {
            committed: None,
            data: signed,
        }
    };

    Ok(out)
}
