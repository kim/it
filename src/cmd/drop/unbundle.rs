// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    collections::BTreeMap,
    path::PathBuf,
};

use anyhow::anyhow;
use clap::ValueHint;

use crate::{
    cmd,
    git::{
        self,
        if_not_found_none,
        refs,
        Refname,
    },
    patches::{
        self,
        iter::dropped,
        Bundle,
        REF_IT_BUNDLES,
        REF_IT_PATCHES,
    },
    paths,
};

// TODO:
//
// - require drop metadata verification
// - abort if existing ref would be set to a different target (or --force)
// - honour snapshots
//

#[derive(Debug, clap::Args)]
pub struct Unbundle {
    #[clap(from_global)]
    git_dir: PathBuf,
    /// The directory where to write the bundle to
    ///
    /// Unless this is an absolute path, it is treated as relative to $GIT_DIR.
    #[clap(
        long,
        value_parser,
        value_name = "DIR",
        default_value_os_t = paths::bundles().to_owned(),
        value_hint = ValueHint::DirPath,
    )]
    bundle_dir: PathBuf,
    /// The drop history to find the topic in
    #[clap(value_parser)]
    drop: Option<String>,
}

#[derive(serde::Serialize)]
pub struct Output {
    updated: BTreeMap<Refname, git::serde::oid::Oid>,
}

pub fn unbundle(args: Unbundle) -> cmd::Result<Output> {
    let repo = git::repo::open(&args.git_dir)?;
    let bundle_dir = if args.bundle_dir.is_relative() {
        repo.path().join(args.bundle_dir)
    } else {
        args.bundle_dir
    };
    let drop = match args.drop {
        Some(rev) => if_not_found_none(repo.resolve_reference_from_short_name(&rev))?
            .ok_or_else(|| anyhow!("no ref matching {rev} found"))?
            .name()
            .ok_or_else(|| anyhow!("invalid drop"))?
            .to_owned(),
        None => REF_IT_PATCHES.to_owned(),
    };

    let odb = repo.odb()?;
    let mut tx = refs::Transaction::new(&repo)?;
    let mut up = BTreeMap::new();
    for rec in dropped::records_rev(&repo, &drop) {
        let rec = rec?;
        let bundle = Bundle::from_stored(&bundle_dir, rec.bundle_info().as_expect())?;
        bundle.packdata()?.index(&odb)?;
        let updated = patches::unbundle(&odb, &mut tx, REF_IT_BUNDLES, &rec)?;
        for (name, oid) in updated {
            up.insert(name, oid.into());
        }
    }
    tx.commit()?;

    Ok(Output { updated: up })
}
