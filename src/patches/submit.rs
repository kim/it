// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    path::{
        Path,
        PathBuf,
    },
    str::FromStr,
};

use anyhow::{
    anyhow,
    bail,
    ensure,
    Context,
};
use globset::{
    Glob,
    GlobBuilder,
    GlobSet,
    GlobSetBuilder,
};
use log::info;
use once_cell::sync::Lazy;
use thiserror::Error;
use tiny_http::Request;
use url::Url;

use super::{
    bundle::Bundle,
    record::{
        self,
        Heads,
        Signature,
    },
    state,
    Record,
    Seen,
    Topic,
    HTTP_HEADER_SIGNATURE,
    MAX_LEN_BUNDLE,
    REF_IT_BUNDLES,
    REF_IT_TOPICS,
    TOPIC_MERGES,
};
use crate::{
    bundle,
    git::{
        self,
        if_not_found_none,
        refs,
    },
    metadata::{
        self,
        git::{
            FromGit,
            GitMeta,
            META_FILE_ID,
        },
        identity,
        ContentHash,
        Signed,
        Verified,
    },
    Result,
};

pub static GLOB_HEADS: Lazy<Glob> = Lazy::new(|| Glob::new("refs/heads/**").unwrap());
pub static GLOB_TAGS: Lazy<Glob> = Lazy::new(|| Glob::new("refs/tags/**").unwrap());
pub static GLOB_NOTES: Lazy<Glob> = Lazy::new(|| Glob::new("refs/notes/**").unwrap());

pub static GLOB_IT_TOPICS: Lazy<Glob> = Lazy::new(|| {
    GlobBuilder::new(&format!("{}/*", REF_IT_TOPICS))
        .literal_separator(true)
        .build()
        .unwrap()
});
pub static GLOB_IT_IDS: Lazy<Glob> = Lazy::new(|| {
    GlobBuilder::new("refs/it/ids/*")
        .literal_separator(true)
        .build()
        .unwrap()
});
pub static GLOB_IT_BUNDLES: Lazy<Glob> =
    Lazy::new(|| Glob::new(&format!("{}/**", REF_IT_BUNDLES)).unwrap());

pub static ALLOWED_REFS: Lazy<GlobSet> = Lazy::new(|| {
    GlobSetBuilder::new()
        .add(GLOB_HEADS.clone())
        .add(GLOB_TAGS.clone())
        .add(GLOB_NOTES.clone())
        .add(GLOB_IT_TOPICS.clone())
        .add(GLOB_IT_IDS.clone())
        .build()
        .unwrap()
});

pub struct AcceptArgs<'a, S> {
    /// The prefix under which to store the refs contained in the bundle
    pub unbundle_prefix: &'a str,
    /// The refname of the drop history
    pub drop_ref: &'a str,
    /// The refname anchoring the seen objects tree
    pub seen_ref: &'a str,
    /// The repo to operate on
    pub repo: &'a git2::Repository,
    /// The signer for the drop history
    pub signer: &'a mut S,
    /// IPFS API address
    pub ipfs_api: Option<&'a Url>,
    /// Options
    pub options: AcceptOptions,
}

pub struct AcceptOptions {
    /// Allow bundles to convey "fat" packs, ie. packs which do not have any
    /// prerequisites
    ///
    /// Default: false
    pub allow_fat_pack: bool,
    /// Allow encrypted bundles
    ///
    /// Default: false
    pub allow_encrypted: bool,
    /// Allowed ref name patterns
    ///
    /// Default:
    ///
    /// - refs/heads/**
    /// - refs/tags/**
    /// - refs/notes/**
    /// - refs/it/topics/*
    /// - refs/it/ids/*
    pub allowed_refs: GlobSet,
    /// Maximum number of branches the bundle is allowed to carry
    ///
    /// A branch is a ref which starts with `refs/heads/`.
    ///
    /// Default: 1
    pub max_branches: usize,
    /// Maximum number of tags the bundle is allowed to carry
    ///
    /// A tag is a ref which starts with `refs/tags/`.
    ///
    /// Default: 1
    pub max_tags: usize,
    /// Maximum number of git notes refs the bundle is allowed to carry
    ///
    /// A notes ref is a ref which starts with `refs/notes/`.
    ///
    /// Default: 1
    pub max_notes: usize,
    /// Maximum number of refs in the bundle, considering all refs
    ///
    /// Default: 10,
    pub max_refs: usize,
    /// Maximum number of commits a bundle ref can have
    ///
    /// Default: 20
    pub max_commits: usize,
}

impl Default for AcceptOptions {
    fn default() -> Self {
        Self {
            allow_fat_pack: false,
            allow_encrypted: false,
            allowed_refs: ALLOWED_REFS.clone(),
            max_branches: 1,
            max_tags: 1,
            max_notes: 1,
            max_refs: 10,
            max_commits: 20,
        }
    }
}

pub struct Submission {
    pub signature: Signature,
    pub bundle: Bundle,
}

impl Submission {
    pub fn from_http<P>(bundle_dir: P, req: &mut Request) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let len = req
            .body_length()
            .ok_or_else(|| anyhow!("chunked body not permitted"))?;
        ensure!(
            len <= MAX_LEN_BUNDLE,
            "submitted patch bundle exceeds {MAX_LEN_BUNDLE}",
        );

        let mut signature = None;

        for hdr in req.headers() {
            if hdr.field.equiv(HTTP_HEADER_SIGNATURE) {
                let sig = Signature::try_from(hdr)?;
                signature = Some(sig);
                break;
            }
        }

        #[derive(Debug, Error)]
        #[error("missing header {0}")]
        struct Missing(&'static str);

        let signature = signature.ok_or(Missing(HTTP_HEADER_SIGNATURE))?;
        let bundle = Bundle::copy(req.as_reader(), bundle_dir)?;

        Ok(Self { signature, bundle })
    }

    pub fn submit(self, mut base_url: Url) -> Result<Record> {
        base_url
            .path_segments_mut()
            .map_err(|()| anyhow!("invalid url"))?
            .push("patches");
        let tiny_http::Header {
            field: sig_hdr,
            value: sig,
        } = self.signature.into();
        let req = ureq::request_url("POST", &base_url)
            .set("Content-Length", &self.bundle.info.len.to_string())
            .set(sig_hdr.as_str().as_str(), sig.as_str());
        let res = req.send(self.bundle.reader()?)?;

        Ok(res.into_json()?)
    }

    pub fn try_accept<S>(
        &mut self,
        AcceptArgs {
            unbundle_prefix,
            drop_ref,
            seen_ref,
            repo,
            signer,
            ipfs_api,
            options,
        }: AcceptArgs<S>,
    ) -> Result<Record>
    where
        S: crate::keys::Signer,
    {
        ensure!(
            unbundle_prefix.starts_with("refs/"),
            "prefix must start with 'refs/'"
        );
        ensure!(
            !self.bundle.is_encrypted() || options.allow_encrypted,
            "encrypted bundle rejected"
        );

        let header = &self.bundle.header;

        ensure!(
            matches!(header.object_format, bundle::ObjectFormat::Sha1),
            "object-format {} not (yet) supported",
            header.object_format
        );
        ensure!(
            !header.prerequisites.is_empty() || options.allow_fat_pack,
            "thin pack required"
        );
        ensure!(
            header.references.len() <= options.max_refs,
            "max number of refs exceeded"
        );
        let topic = {
            let mut topic: Option<Topic> = None;

            let mut heads = 0;
            let mut tags = 0;
            let mut notes = 0;
            static GIT_IT: Lazy<GlobSet> = Lazy::new(|| {
                GlobSetBuilder::new()
                    .add(GLOB_HEADS.clone())
                    .add(GLOB_TAGS.clone())
                    .add(GLOB_NOTES.clone())
                    .add(GLOB_IT_TOPICS.clone())
                    .build()
                    .unwrap()
            });
            let mut matches = Vec::with_capacity(1);
            for r in header.references.keys() {
                let cand = globset::Candidate::new(r);
                ensure!(
                    options.allowed_refs.is_match_candidate(&cand),
                    "unconventional ref rejected: {r}"
                );
                GIT_IT.matches_candidate_into(&cand, &mut matches);
                match &matches[..] {
                    [] => {},
                    [0] => heads += 1,
                    [1] => tags += 1,
                    [2] => notes += 1,
                    [3] => {
                        ensure!(topic.is_none(), "more than one topic");
                        match r.split('/').next_back() {
                            None => bail!("invalid notes '{r}': missing topic"),
                            Some(s) => {
                                let t = Topic::from_str(s).context("invalid topic")?;
                                topic = Some(t);
                            },
                        }
                    },
                    x => unreachable!("impossible match: {x:?}"),
                }
            }
            ensure!(
                heads <= options.max_branches,
                "max number of git branches exceeded"
            );
            ensure!(tags <= options.max_tags, "max number of git tags exceeded");
            ensure!(
                notes <= options.max_notes,
                "max number of git notes exceeded"
            );

            topic.ok_or_else(|| anyhow!("missing '{}'", GLOB_IT_TOPICS.glob()))?
        };
        let heads = Heads::from(header);

        let mut tx = refs::Transaction::new(repo)?;
        let seen_ref = tx.lock_ref(seen_ref.parse()?)?;
        let seen_tree = match if_not_found_none(repo.find_reference(seen_ref.name()))? {
            Some(seen) => seen.peel_to_tree()?,
            None => git::empty_tree(repo)?,
        };
        ensure!(!heads.in_tree(&seen_tree)?, "submission already exists");

        // In a bare drop, indexing the pack is enough to detect missing
        // prerequisites (ie. delta bases). Otherwise, or if the bundle is
        // encrypted, we need to look for merge bases from the previously
        // accepted patches.
        if !repo.is_bare() || self.bundle.is_encrypted() {
            let mut prereqs = header
                .prerequisites
                .iter()
                .map(git2::Oid::try_from)
                .collect::<std::result::Result<Vec<_>, _>>()?;

            for r in repo.references_glob(GLOB_IT_BUNDLES.glob())? {
                let commit = r?.peel_to_commit()?.id();
                for (i, id) in prereqs.clone().into_iter().enumerate() {
                    if if_not_found_none(repo.merge_base(commit, id))?.is_some() {
                        prereqs.swap_remove(i);
                    }
                }
                if prereqs.is_empty() {
                    break;
                }
            }

            ensure!(
                prereqs.is_empty(),
                "prerequisite commits not found, try checkpointing a branch or \
                base the patch on a previous one: {}",
                prereqs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        let odb = repo.odb()?;
        if !self.bundle.is_encrypted() {
            let mut pack = self.bundle.packdata()?;
            pack.index(&odb)?;

            let prereqs = header
                .prerequisites
                .iter()
                .map(git2::Oid::try_from)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let mut walk = repo.revwalk()?;
            for (name, oid) in &header.references {
                walk.push(oid.try_into()?)?;
                for hide in &prereqs {
                    walk.hide(*hide)?;
                }
                let mut cnt = 0;
                for x in &mut walk {
                    let _ = x?;
                    cnt += 1;
                    ensure!(
                        cnt <= options.max_commits,
                        "{name} exceeds configured max number of commits ({})",
                        options.max_commits
                    );
                }
                walk.reset()?;
            }
        }

        if let Some(url) = ipfs_api {
            let ipfs = self.bundle.ipfs_add(url)?;
            info!("Published bundle to IPFS as {ipfs}");
        }

        let record = Record {
            topic,
            heads,
            meta: record::Meta {
                bundle: record::BundleInfo::from(&self.bundle),
                signature: self.signature.clone(),
            },
        };

        let drop_ref = tx.lock_ref(drop_ref.parse()?)?;
        let mut drop = state::DropHead::from_refname(repo, drop_ref.name())?;
        ensure!(
            drop.meta.roles.snapshot.threshold.get() == 1,
            "threshold signatures for drop snapshots not yet supported"
        );
        ensure!(
            is_signer_eligible(signer, repo, &drop.ids, &drop.meta)?,
            "supplied signer does not have the 'snapshot' role needed to record patches"
        );

        let submitter = {
            let mut id = Identity::find(repo, &drop.ids, &self.signature.signer)?;
            id.verify_signature(&record.signed_part(), &self.signature)?;
            if let Some(updated) = id.update(repo, &drop.ids)? {
                drop.ids = updated;
            }
            id.verified
        };

        let mut seen = repo.treebuilder(Some(&seen_tree))?;
        let new_head = record.commit(
            signer,
            repo,
            &drop.ids,
            Some(&drop.tip.peel_to_commit()?),
            Some(&mut seen),
        )?;
        drop_ref.set_target(new_head, format!("commit: {}", record.topic));
        seen_ref.set_target(seen.write()?, format!("it: update to record {}", new_head));

        if !self.bundle.is_encrypted() {
            state::unbundle(&odb, &mut tx, unbundle_prefix, &record)?;
            let topic_ref = tx.lock_ref(record.topic.as_refname())?;
            state::merge_notes(repo, &submitter, &topic_ref, &record)?;
            if record.topic == *TOPIC_MERGES {
                state::update_branches(repo, &mut tx, &submitter, &drop.meta, &record)?;
            }
        }

        tx.commit()?;

        Ok(record)
    }
}

fn is_signer_eligible<S>(
    signer: &S,
    repo: &git2::Repository,
    ids: &git2::Tree,
    meta: &Verified<metadata::Drop>,
) -> Result<bool>
where
    S: crate::keys::Signer,
{
    let signer_id = metadata::KeyId::from(signer.ident());
    for id in &meta.roles.snapshot.ids {
        let s = metadata::identity::find_in_tree(repo, ids, id)?;
        if s.identity().keys.contains_key(&signer_id) {
            return Ok(true);
        }
    }

    Ok(false)
}

struct Identity {
    verified: identity::Verified,
    to_update: Option<Signed<metadata::Identity>>,
}

impl Identity {
    fn find(repo: &git2::Repository, ids: &git2::Tree, hash: &ContentHash) -> Result<Self> {
        let find_parent = metadata::git::find_parent(repo);

        let (theirs_hash, theirs_signed, theirs) = metadata::Identity::from_content_hash(
            repo, hash,
        )
        .and_then(|GitMeta { hash, signed }| {
            let signed_dup = signed.clone();
            let verified = signed.verified(&find_parent)?;
            Ok((hash, signed_dup, verified))
        })?;

        let tree_path = PathBuf::from(theirs.id().to_string()).join(META_FILE_ID);
        let newer = match if_not_found_none(ids.get_path(&tree_path))? {
            None => Self {
                verified: theirs,
                to_update: Some(theirs_signed),
            },
            Some(in_tree) if theirs_hash == in_tree.id() => Self {
                verified: theirs,
                to_update: None,
            },
            Some(in_tree) => {
                let (ours_hash, ours) = metadata::Identity::from_blob(
                    &repo.find_blob(in_tree.id())?,
                )
                .and_then(|GitMeta { hash, signed }| {
                    let ours = signed.verified(&find_parent)?;
                    Ok((hash, ours))
                })?;

                if ours.identity().has_ancestor(&theirs_hash, &find_parent)? {
                    Self {
                        verified: ours,
                        to_update: None,
                    }
                } else if theirs.identity().has_ancestor(&ours_hash, &find_parent)? {
                    Self {
                        verified: theirs,
                        to_update: Some(theirs_signed),
                    }
                } else {
                    bail!(
                        "provided signer id at {} diverges from known id at {}",
                        theirs_hash,
                        ours_hash,
                    );
                }
            },
        };

        Ok(newer)
    }

    fn verify_signature(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        ensure!(
            self.verified.did_sign(msg, &sig.signature),
            "signature not valid for current keys in id {}, provided signer at {}",
            self.verified.id(),
            sig.signer
        );
        Ok(())
    }

    fn update<'a>(
        &mut self,
        repo: &'a git2::Repository,
        root: &git2::Tree,
    ) -> Result<Option<git2::Tree<'a>>> {
        if let Some(meta) = self.to_update.take() {
            let mut new_root = repo.treebuilder(Some(root))?;
            let mut id_tree = repo.treebuilder(None)?;
            metadata::identity::fold_to_tree(repo, &mut id_tree, meta)?;
            new_root.insert(
                self.verified.id().to_string().as_str(),
                id_tree.write()?,
                git2::FileMode::Tree.into(),
            )?;

            let oid = new_root.write()?;
            let tree = repo.find_tree(oid).map(Some)?;

            return Ok(tree);
        }

        Ok(None)
    }
}
