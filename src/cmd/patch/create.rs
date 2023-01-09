// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    borrow::Cow,
    collections::BTreeMap,
    env,
    path::PathBuf,
};

use anyhow::anyhow;
use clap::ValueHint;
use globset::{
    GlobSet,
    GlobSetBuilder,
};
use once_cell::sync::Lazy;
use url::Url;

use super::prepare;
use crate::{
    cfg,
    cmd::{
        self,
        ui::{
            self,
            debug,
            info,
        },
        util::args::IdSearchPath,
        Aborted,
    },
    git::{
        self,
        Refname,
    },
    metadata::IdentityId,
    patches::{
        self,
        iter,
        DropHead,
        Topic,
        TrackingBranch,
        GLOB_IT_BUNDLES,
        GLOB_IT_IDS,
        GLOB_IT_TOPICS,
        REF_HEADS_PATCHES,
        REF_IT_BUNDLES,
        REF_IT_PATCHES,
        REF_IT_SEEN,
    },
    paths,
};

#[derive(Debug, clap::Args)]
pub struct Common {
    /// Path to the drop repository
    #[clap(from_global)]
    git_dir: PathBuf,
    /// Path to the source repository
    ///
    /// If set, the patch bundle will be created from objects residing in an
    /// external repository. The main use case for this is to allow a bare
    /// drop to pull in checkpoints from a local repo with a regular layout
    /// (ie. non it-aware).
    #[clap(
        long = "source-dir",
        alias = "src-dir",
        value_parser,
        value_name = "DIR",
        value_hint = ValueHint::DirPath,
    )]
    src_dir: Option<PathBuf>,
    /// Identity to assume
    ///
    /// If not set as an option nor in the environment, the value of `it.id` in
    /// the git config is tried.
    #[clap(short = 'I', long = "identity", value_name = "ID", env = "IT_ID")]
    id: Option<IdentityId>,
    /// A list of paths to search for identity repositories
    #[clap(
        long,
        value_parser,
        value_name = "PATH",
        env = "IT_ID_PATH",
        default_value_t,
        value_hint = ValueHint::DirPath,
    )]
    id_path: IdSearchPath,
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
    /// IPFS API to publish the patch bundle to
    ///
    /// Currently has no effect when submitting a patch to a remote drop. When
    /// running `ipfs daemon`, the default API address is 'http://127.0.0.1:5001'.
    #[clap(
        long,
        value_parser,
        value_name = "URL",
        value_hint = ValueHint::Url,
    )]
    ipfs_api: Option<Url>,
    /// Additional identities to include, eg. to allow commit verification
    #[clap(long = "add-id", value_parser, value_name = "ID")]
    ids: Vec<IdentityId>,
    /// Message to attach to the patch (cover letter, comment)
    ///
    /// If not set, $EDITOR will be invoked to author one.
    #[clap(short, long, value_parser, value_name = "STRING")]
    message: Option<String>,
    /// Create the patch, but stop short of submitting / recording it
    #[clap(long, value_parser)]
    dry_run: bool,
}

#[derive(Debug, clap::Args)]
pub struct Remote {
    /// Url to submit the patch to
    ///
    /// Usually one of the alternates from the drop metadata. If not set,
    /// GIT_DIR is assumed to contain a drop with which the patch can be
    /// recorded without any network access.
    #[clap(long, visible_alias = "submit-to", value_parser, value_name = "URL")]
    url: Url,
    /// Refname of the drop to record the patch with
    ///
    /// We need to pick a local (remote-tracking) drop history in order to
    /// compute delta bases for the patch. The value is interpreted
    /// according to "DWIM" rules, i.e. shorthand forms like 'it/patches',
    /// 'origin/patches' are attempted to be resolved.
    #[clap(long = "drop", value_parser, value_name = "STRING")]
    drop_ref: String,
}

#[derive(Debug, clap::Args)]
pub struct Patch {
    /// Base branch the patch is against
    ///
    /// If --topic is given, the branch must exist in the patch bundle
    /// --reply-to refers to, or the default entry to reply to on that
    /// topic. Otherwise, the branch must exist in the drop
    /// metadata. Shorthand branch names are accepted.
    ///
    /// If not given, "main" or "master" is tried, in that order.
    #[clap(long = "base", value_parser, value_name = "REF")]
    base: Option<String>,
    /// Head revision of the patch, in 'git rev-parse' syntax
    #[clap(
        long = "head",
        value_parser,
        value_name = "REVSPEC",
        default_value = "HEAD"
    )]
    head: String,
    /// Post the patch to a previously recorded topic
    #[clap(long, value_parser, value_name = "TOPIC")]
    topic: Option<Topic>,
    /// Reply to a particular entry within a topic
    ///
    /// Only considered if --topic is given.
    #[clap(long, value_parser, value_name = "ID")]
    reply_to: Option<git2::Oid>,
}

#[derive(Debug, clap::Args)]
pub struct Comment {
    /// The topic to comment on
    #[clap(value_parser, value_name = "TOPIC")]
    topic: Topic,
    /// Reply to a particular entry within the topic
    #[clap(long, value_parser, value_name = "ID")]
    reply_to: Option<git2::Oid>,
}

pub enum Kind {
    Merges {
        common: Common,
        remote: Option<Remote>,
        force: bool,
    },
    Snapshot {
        common: Common,
    },
    Comment {
        common: Common,
        remote: Option<Remote>,
        comment: Comment,
    },
    Patch {
        common: Common,
        remote: Option<Remote>,
        patch: Patch,
    },
}

impl Kind {
    fn common(&self) -> &Common {
        match self {
            Self::Merges { common, .. }
            | Self::Snapshot { common }
            | Self::Comment { common, .. }
            | Self::Patch { common, .. } => common,
        }
    }

    fn remote(&self) -> Option<&Remote> {
        match self {
            Self::Merges { remote, .. }
            | Self::Comment { remote, .. }
            | Self::Patch { remote, .. } => remote.as_ref(),
            Self::Snapshot { .. } => None,
        }
    }

    fn accept_options(&self, drop: &DropHead) -> patches::AcceptOptions {
        let mut options = patches::AcceptOptions::default();
        match self {
            Self::Merges { common, .. } => {
                options.allow_fat_pack = true;
                options.max_branches = drop.meta.roles.branches.len();
                options.max_refs = options.max_branches + common.ids.len() + 1;
                options.max_commits = 100_000;
            },
            Self::Snapshot { .. } => {
                options.allow_fat_pack = true;
                options.allowed_refs = SNAPSHOT_REFS.clone();
                options.max_branches = usize::MAX;
                options.max_refs = usize::MAX;
                options.max_commits = usize::MAX;
                options.max_notes = usize::MAX;
                options.max_tags = usize::MAX;
            },

            _ => {},
        }

        options
    }
}

struct Resolved {
    repo: prepare::Repo,
    signer_id: IdentityId,
    bundle_dir: PathBuf,
}

impl Common {
    fn resolve(&self) -> cmd::Result<Resolved> {
        let drp = git::repo::open(&self.git_dir)?;
        let ids = self.id_path.open_git();
        let src = match self.src_dir.as_ref() {
            None => {
                let cwd = env::current_dir()?;
                (cwd != self.git_dir).then_some(cwd)
            },
            Some(dir) => Some(dir.to_owned()),
        }
        .as_deref()
        .map(git::repo::open_bare)
        .transpose()?;

        debug!(
            "drop: {}, src: {:?}, ids: {:?}",
            drp.path().display(),
            src.as_ref().map(|r| r.path().display()),
            env::join_paths(ids.iter().map(|r| r.path()))
        );

        // IT_ID_PATH could differ from what was used at initialisation
        git::add_alternates(&drp, &ids)?;

        let repo = prepare::Repo::new(drp, ids, src);
        let signer_id = match self.id {
            Some(id) => id,
            None => cfg::git::identity(&repo.source().config()?)?
                .ok_or_else(|| anyhow!("no identity configured for signer"))?,
        };
        let bundle_dir = if self.bundle_dir.is_absolute() {
            self.bundle_dir.clone()
        } else {
            repo.target().path().join(&self.bundle_dir)
        };

        Ok(Resolved {
            repo,
            signer_id,
            bundle_dir,
        })
    }
}

static SNAPSHOT_REFS: Lazy<GlobSet> = Lazy::new(|| {
    GlobSetBuilder::new()
        .add(GLOB_IT_TOPICS.clone())
        .add(GLOB_IT_BUNDLES.clone())
        .add(GLOB_IT_IDS.clone())
        .build()
        .unwrap()
});

pub fn create(args: Kind) -> cmd::Result<patches::Record> {
    let Resolved {
        repo,
        signer_id,
        bundle_dir,
    } = args.common().resolve()?;
    let drop_ref: Cow<str> = match args.remote() {
        Some(remote) => {
            let full = repo
                .source()
                .resolve_reference_from_short_name(&remote.drop_ref)?;
            full.name()
                .ok_or_else(|| anyhow!("invalid drop ref"))?
                .to_owned()
                .into()
        },
        None if repo.target().is_bare() => REF_HEADS_PATCHES.into(),
        None => REF_IT_PATCHES.into(),
    };

    let mut signer = cfg::git::signer(&repo.source().config()?, ui::askpass)?;
    let drop = patches::DropHead::from_refname(repo.target(), &drop_ref)?;

    let spec = match &args {
        Kind::Merges { force, .. } => prepare::Kind::Mergepoint { force: *force },
        Kind::Snapshot { .. } => prepare::Kind::Snapshot { incremental: true },
        Kind::Comment { comment, .. } => prepare::Kind::Comment {
            topic: comment.topic.clone(),
            reply: comment.reply_to,
        },
        Kind::Patch { patch, .. } => {
            let (name, base_ref) = dwim_base(
                repo.target(),
                &drop,
                patch.topic.as_ref(),
                patch.reply_to,
                patch.base.as_deref(),
            )?
            .ok_or_else(|| anyhow!("unable to determine base branch"))?;
            let base = repo
                .target()
                .find_reference(&base_ref)?
                .peel_to_commit()?
                .id();
            let head = repo
                .source()
                .revparse_single(&patch.head)?
                .peel_to_commit()?
                .id();

            prepare::Kind::Patch {
                head,
                base,
                name,
                re: patch.topic.as_ref().map(|t| (t.clone(), patch.reply_to)),
            }
        },
    };

    let mut patch = prepare::Preparator::new(
        &repo,
        &drop,
        prepare::Submitter {
            signer: &mut signer,
            id: signer_id,
        },
    )
    .prepare_patch(
        &bundle_dir,
        spec,
        args.common().message.clone(),
        &args.common().ids,
    )?;

    if args.common().dry_run {
        info!("--dry-run given, stopping here");
        cmd::abort!();
    }

    match args.remote() {
        Some(remote) => patch.submit(remote.url.clone()),
        None => patch.try_accept(patches::AcceptArgs {
            unbundle_prefix: REF_IT_BUNDLES,
            drop_ref: &drop_ref,
            seen_ref: REF_IT_SEEN,
            repo: repo.target(),
            signer: &mut signer,
            ipfs_api: args.common().ipfs_api.as_ref(),
            options: args.accept_options(&drop),
        }),
    }
}

fn dwim_base(
    repo: &git2::Repository,
    drop: &DropHead,
    topic: Option<&Topic>,
    reply_to: Option<git2::Oid>,
    base: Option<&str>,
) -> cmd::Result<Option<(Refname, Refname)>> {
    let mut candidates = BTreeMap::new();
    match topic {
        Some(topic) => {
            let reply_to = reply_to.map(Ok).unwrap_or_else(|| {
                iter::topic::default_reply_to(repo, topic)?
                    .ok_or_else(|| anyhow!("topic {topic} not found"))
            })?;
            let mut patch_id = None;
            for note in iter::topic(repo, topic) {
                let note = note?;
                if note.header.id == reply_to {
                    patch_id = Some(note.header.patch.id);
                    break;
                }
            }
            let patch_id = patch_id.ok_or_else(|| {
                anyhow!("no patch found corresponding to topic: {topic}, reply-to: {reply_to}")
            })?;

            let prefix = format!("{REF_IT_BUNDLES}/{patch_id}/");
            let mut iter = repo.references_glob(&format!("{prefix}**"))?;
            for candidate in iter.names() {
                let candidate = candidate?;
                if let Some(suf) = candidate.strip_prefix(&prefix) {
                    if !suf.starts_with("it/") {
                        candidates.insert(format!("refs/{suf}"), candidate.parse()?);
                    }
                }
            }
        },

        None => candidates.extend(
            drop.meta
                .roles
                .branches
                .keys()
                .cloned()
                .map(|name| (name.to_string(), name)),
        ),
    };

    const FMTS: &[fn(&str) -> String] = &[
        |s| s.to_owned(),
        |s| format!("refs/{}", s),
        |s| format!("refs/heads/{}", s),
        |s| format!("refs/tags/{}", s),
    ];

    debug!("dwim candidates: {candidates:#?}");

    match base {
        Some(base) => {
            for (virt, act) in candidates {
                for f in FMTS {
                    let name = f(base);
                    if name == virt {
                        let refname = name.parse()?;
                        return Ok(Some((refname, act)));
                    }
                }
            }
            Ok(None)
        },

        // nb. biased towards "main" because we use a BTreeMap
        None => Ok(candidates.into_iter().find_map(|(k, _)| match k.as_str() {
            "refs/heads/main" => Some((Refname::main(), TrackingBranch::main().into_refname())),
            "refs/heads/master" => {
                Some((Refname::master(), TrackingBranch::master().into_refname()))
            },
            _ => None,
        })),
    }
}
