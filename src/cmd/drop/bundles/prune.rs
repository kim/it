// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    str::FromStr,
};

use clap::ValueHint;

use crate::{
    bundle,
    cfg,
    cmd::{
        self,
        ui::{
            info,
            warn,
        },
    },
    git,
    patches::iter::dropped,
};

// TODO:
//
// - option to prune bundles made obsolete by snapshots

#[derive(Debug, clap::Args)]
pub struct Prune {
    /// Path to the drop repository
    #[clap(from_global)]
    git_dir: PathBuf,
    /// The directory where to write the bundle to
    ///
    /// Unless this is an absolute path, it is treated as relative to $GIT_DIR.
    #[clap(
        long,
        value_parser,
        value_name = "DIR",
        default_value_os_t = cfg::paths::bundles().to_owned(),
        value_hint = ValueHint::DirPath,
    )]
    bundle_dir: PathBuf,
    /// Name of a git ref holding the drop metadata history
    ///
    /// All locally tracked drops should be given, otherwise bundles might get
    /// pruned which are still being referred to.
    #[clap(long = "drop", value_parser, value_name = "REF")]
    drop_refs: Vec<String>,
    /// Pretend to unlink, but don't
    #[clap(long, value_parser)]
    dry_run: bool,
    /// Also remove location files (.uris)
    #[clap(long, value_parser)]
    remove_locations: bool,
}

pub fn prune(args: Prune) -> cmd::Result<Vec<bundle::Hash>> {
    let repo = git::repo::open_bare(&args.git_dir)?;
    let bundle_dir = if args.bundle_dir.is_relative() {
        repo.path().join(args.bundle_dir)
    } else {
        args.bundle_dir
    };

    let mut seen = BTreeSet::new();
    for short in &args.drop_refs {
        let drop_ref = repo.resolve_reference_from_short_name(short)?;
        let ref_name = drop_ref.name().expect("drop references to be valid utf8");
        info!("Collecting bundle hashes from {ref_name} ...");
        for record in dropped::records(&repo, ref_name) {
            let record = record?;
            seen.insert(*record.bundle_hash());
        }
    }

    info!("Traversing bundle dir {} ...", bundle_dir.display());
    let mut pruned = Vec::new();
    for entry in fs::read_dir(&bundle_dir)? {
        let entry = entry?;
        let path = entry.path();
        match path.extension() {
            Some(ext) if ext == bundle::FILE_EXTENSION => {
                let name = path.file_stem();
                match name
                    .and_then(|n| n.to_str())
                    .and_then(|s| bundle::Hash::from_str(s).ok())
                {
                    Some(hash) => {
                        if !seen.contains(&hash) {
                            if !args.dry_run {
                                fs::remove_file(&path)?;
                            }
                            pruned.push(hash);
                        }
                    },
                    None => warn!("Ignoring {}: file name not a bundle hash", path.display()),
                }
            },
            Some(ext) if ext == bundle::list::FILE_EXTENSION => {
                if args.remove_locations {
                    fs::remove_file(&path)?;
                }
            },
            _ => warn!("Ignoring {}: missing .bundle", path.display()),
        }
    }

    Ok(pruned)
}
