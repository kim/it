// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    borrow::Cow,
    mem,
    num::NonZeroUsize,
    path::PathBuf,
    sync::{
        Arc,
        Mutex,
    },
    time::{
        SystemTime,
        UNIX_EPOCH,
    },
};

use anyhow::anyhow;
use clap::ValueHint;
use either::Either::{
    Left,
    Right,
};
use threadpool::ThreadPool;
use url::Url;

use crate::{
    bundle,
    cfg,
    cmd::{
        self,
        drop::Common,
        ui::{
            debug,
            info,
            warn,
        },
    },
    git::{
        self,
        if_not_found_none,
    },
    patches::{
        self,
        iter::dropped,
        record,
        REF_IT_PATCHES,
    },
};

/// Max number of locations to store from the remote for which we don't know if
/// they'd succeed or not.
pub const MAX_UNTRIED_LOCATIONS: usize = 3;

#[derive(Debug, clap::Args)]
pub struct Sync {
    #[clap(flatten)]
    common: Common,
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
    /// Name of the git ref holding the drop metadata history
    #[clap(long = "drop", value_parser, value_name = "REF")]
    drop_ref: Option<String>,
    /// Base URL to fetch from
    #[clap(long, value_parser, value_name = "URL", value_hint = ValueHint::Url)]
    url: Url,
    /// Fetch via IPFS
    #[clap(
        long,
        value_parser,
        value_name = "URL",
        value_hint = ValueHint::Url,
        env = "IPFS_GATEWAY",
        default_value_t = Url::parse("https://ipfs.io").unwrap(),
    )]
    ipfs_gateway: Url,
    /// Fetch even if the bundle already exists locally
    #[clap(long, value_parser)]
    overwrite: bool,
    /// Ignore snapshots if encountered
    #[clap(long, value_parser)]
    no_snapshots: bool,
    /// Maximum number of concurrent downloads. Default is the number of
    /// available cores.
    #[clap(short, long, value_parser, default_value_t = def_jobs())]
    jobs: NonZeroUsize,
}

fn def_jobs() -> NonZeroUsize {
    NonZeroUsize::new(num_cpus::get()).unwrap_or_else(|| NonZeroUsize::new(1).unwrap())
}

pub fn sync(args: Sync) -> cmd::Result<Vec<bundle::Info>> {
    let repo = git::repo::open_bare(&args.common.git_dir)?;
    let bundle_dir = if args.bundle_dir.is_relative() {
        repo.path().join(args.bundle_dir)
    } else {
        args.bundle_dir
    };
    let drop_ref = match args.drop_ref {
        Some(rev) => if_not_found_none(repo.resolve_reference_from_short_name(&rev))?
            .ok_or_else(|| anyhow!("no ref matching {rev} found"))?
            .name()
            .ok_or_else(|| anyhow!("invalid drop"))?
            .to_owned(),
        None => REF_IT_PATCHES.to_owned(),
    };
    let base_url = args.url.join("bundles/")?;
    let fetcher = Arc::new(Fetcher {
        fetcher: bundle::Fetcher::default(),
        bundle_dir,
        base_url: base_url.clone(),
        ipfs_gateway: args.ipfs_gateway,
    });

    let pool = ThreadPool::new(args.jobs.get());

    let fetched = Arc::new(Mutex::new(Vec::new()));
    let mut chasing_snaphots = false;
    for record in dropped::records(&repo, &drop_ref) {
        let record = record?;
        let hexdig = record.bundle_hash().to_string();

        if record.is_snapshot() {
            if args.no_snapshots {
                info!("Skipping snapshot bundle {hexdig}");
                continue;
            } else {
                chasing_snaphots = true;
            }
        } else if chasing_snaphots && !record.is_mergepoint() {
            info!("Skipping non-snapshot bundle {hexdig}");
            continue;
        }

        if !args.overwrite && record.bundle_path(&fetcher.bundle_dir).exists() {
            info!("Skipping existing bundle {hexdig}");
            continue;
        }

        let record::BundleInfo {
            info: bundle::Info { len, hash, .. },
            prerequisites,
            ..
        } = record.bundle_info();
        let url = base_url.join(&hexdig)?;

        pool.execute({
            let len = *len;
            let hash = *hash;
            let fetched = Arc::clone(&fetched);
            let fetcher = Arc::clone(&fetcher);
            move || match fetcher.try_fetch(url, len, &hash) {
                Ok(hash) => fetched.lock().unwrap().push(hash),
                Err(e) => warn!("Download failed: {e}"),
            }
        });

        if record.is_snapshot() && prerequisites.is_empty() {
            info!("Full snapshot encountered, stopping here");
            break;
        }
    }

    pool.join();
    let fetched = {
        let mut guard = fetched.lock().unwrap();
        mem::take(&mut *guard)
    };

    Ok(fetched)
}

struct Fetcher {
    fetcher: bundle::Fetcher,
    bundle_dir: PathBuf,
    base_url: Url,
    ipfs_gateway: Url,
}

impl Fetcher {
    fn try_fetch(&self, url: Url, len: u64, hash: &bundle::Hash) -> cmd::Result<bundle::Info> {
        info!("Fetching {url} ...");

        let expect = bundle::Expect {
            len,
            hash,
            checksum: None,
        };
        let mut locations = Vec::new();
        let (fetched, origin) = self
            .fetcher
            .fetch(&url, &self.bundle_dir, expect)
            .and_then(|resp| match resp {
                Right(fetched) => Ok((fetched, url)),
                Left(lst) => {
                    info!("{url}: response was a bundle list, trying alternate locations");

                    let mut iter = lst.bundles.into_iter();
                    let mut found = None;

                    for bundle::Location { uri, .. } in &mut iter {
                        if let Some(url) = self.url_from_uri(uri) {
                            if let Ok(Right(info)) =
                                self.fetcher.fetch(&url, &self.bundle_dir, expect)
                            {
                                found = Some((info, url));
                                break;
                            }
                        }
                    }

                    // If there are bundle uris left, remember a few
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("backwards system clock")
                        .as_secs();
                    locations.extend(
                        iter
                            // Don't let the remote inflate the priority of
                            // unverified locations
                            .filter(|loc| loc.creation_token.map(|t| t < now).unwrap_or(true))
                            // Only known protocols, relative to base url
                            .filter_map(|loc| {
                                let url = loc.uri.abs(&self.base_url).ok()?;
                                matches!(url.scheme(), "http" | "https" | "ipfs").then(|| {
                                    bundle::Location {
                                        uri: url.into_owned().into(),
                                        ..loc
                                    }
                                })
                            })
                            .take(MAX_UNTRIED_LOCATIONS),
                    );

                    found.ok_or_else(|| anyhow!("{url}: no reachable location found"))
                },
            })?;

        info!("Downloaded {hash} from {origin}");
        let bundle = patches::Bundle::from_fetched(fetched)?;
        bundle.write_bundle_list(locations)?;

        Ok(bundle.into())
    }

    fn url_from_uri(&self, uri: bundle::Uri) -> Option<Url> {
        uri.abs(&self.base_url)
            .map_err(Into::into)
            .and_then(|url: Cow<Url>| -> cmd::Result<Url> {
                match url.scheme() {
                    "http" | "https" => Ok(url.into_owned()),
                    "ipfs" => {
                        let cid = url
                            .host_str()
                            .ok_or_else(|| anyhow!("{url}: host part not an IPFS CID"))?;
                        let url = self.ipfs_gateway.join(&format!("/ipfs/{cid}"))?;
                        Ok(url)
                    },
                    _ => Err(anyhow!("{url}: unsupported protocol")),
                }
            })
            .map_err(|e| debug!("discarding {}: {}", uri.as_str(), e))
            .ok()
    }
}
