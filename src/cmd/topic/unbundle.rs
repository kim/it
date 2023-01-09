// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    path::PathBuf,
};

use anyhow::anyhow;
use clap::ValueHint;

use super::Common;
use crate::{
    cmd::{
        self,
        ui::{
            debug,
            info,
            warn,
        },
        Aborted,
    },
    git::{
        self,
        if_not_found_none,
        refs,
        Refname,
    },
    metadata::{
        self,
        git::FromGit,
    },
    patches::{
        self,
        iter::dropped,
        Bundle,
        Record,
        Topic,
        REF_IT_BUNDLES,
        REF_IT_PATCHES,
        TOPIC_MERGES,
        TOPIC_SNAPSHOTS,
    },
    paths,
};

// TODO:
//
// - don't require patch bundle to be present on-disk when snapshots would do

#[derive(Debug, clap::Args)]
pub struct Unbundle {
    #[clap(flatten)]
    common: Common,
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
    /// The topic to unbundle
    #[clap(value_parser)]
    topic: Topic,
    /// The drop history to find the topic in
    #[clap(value_parser)]
    drop: Option<String>,
}

#[derive(serde::Serialize)]
pub struct Output {
    updated: BTreeMap<Refname, git::serde::oid::Oid>,
}

pub fn unbundle(args: Unbundle) -> cmd::Result<Output> {
    let repo = git::repo::open(&args.common.git_dir)?;
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

    let filter = [&args.topic, &TOPIC_MERGES, &TOPIC_SNAPSHOTS];
    let mut on_topic: Vec<Record> = Vec::new();
    let mut checkpoints: Vec<Record> = Vec::new();
    for row in dropped::topics(&repo, &drop) {
        let (t, id) = row?;

        if filter.into_iter().any(|f| f == &t) {
            let commit = repo.find_commit(id)?;
            let record = Record::from_commit(&repo, &commit)?;
            if t == args.topic {
                on_topic.push(record);
                continue;
            }

            // Skip checkpoint which came after the most recent record on the topic
            if !on_topic.is_empty() {
                checkpoints.push(record);
            }
        }
    }

    let odb = repo.odb()?;

    info!("Indexing checkpoints...");
    for rec in checkpoints.into_iter().rev() {
        Bundle::from_stored(&bundle_dir, rec.bundle_info().as_expect())?
            .packdata()?
            .index(&odb)?
    }

    let mut missing = BTreeSet::new();
    for oid in on_topic
        .iter()
        .flat_map(|rec| &rec.bundle_info().prerequisites)
    {
        let oid = git2::Oid::try_from(oid)?;
        if !odb.exists(oid) {
            missing.insert(oid);
        }
    }

    if !missing.is_empty() {
        warn!("Unable to satisfy all prerequisites");
        info!("The following prerequisite commits are missing:\n");
        for oid in missing {
            info!("{oid}");
        }
        info!("\nYou may try to unbundle the entire drop history");
        cmd::abort!();
    }

    info!("Unbundling topic records...");
    let mut tx = refs::Transaction::new(&repo)?;
    let topic_ref = tx.lock_ref(args.topic.as_refname())?;
    let mut up = BTreeMap::new();
    for rec in on_topic.into_iter().rev() {
        let hash = rec.bundle_hash();
        let bundle = Bundle::from_stored(&bundle_dir, rec.bundle_info().as_expect())?;
        if bundle.is_encrypted() {
            warn!("Skipping encrypted bundle {hash}");
            continue;
        }
        bundle.packdata()?.index(&odb)?;
        debug!("{hash}: unbundle");
        let updated = patches::unbundle(&odb, &mut tx, REF_IT_BUNDLES, &rec)?;
        for (name, oid) in updated {
            up.insert(name, oid.into());
        }
        debug!("{hash}: merge notes");
        let submitter = metadata::Identity::from_content_hash(&repo, &rec.meta.signature.signer)?
            .verified(metadata::git::find_parent(&repo))?;
        patches::merge_notes(&repo, &submitter, &topic_ref, &rec)?;
    }
    tx.commit()?;

    Ok(Output { updated: up })
}
