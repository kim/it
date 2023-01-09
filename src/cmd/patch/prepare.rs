// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::path::{
    Path,
    PathBuf,
};

use anyhow::{
    anyhow,
    bail,
    ensure,
};
use either::Either::Left;
use sha2::{
    Digest,
    Sha256,
};

use crate::{
    bundle,
    cmd::{
        self,
        ui::{
            debug,
            edit_comment,
            edit_cover_letter,
            info,
            warn,
        },
    },
    git::{
        self,
        if_not_found_none,
        Refname,
    },
    keys::Signer,
    metadata::{
        self,
        git::{
            FromGit,
            GitMeta,
            META_FILE_ID,
        },
        identity::{
            self,
            IdentityId,
        },
        ContentHash,
        KeyId,
    },
    patches::{
        self,
        iter::{
            dropped,
            topic,
        },
        notes,
        record,
        Topic,
        REF_IT_BUNDLES,
        REF_IT_PATCHES,
        TOPIC_MERGES,
        TOPIC_SNAPSHOTS,
    },
};

pub enum Kind {
    Mergepoint {
        force: bool,
    },
    Snapshot {
        incremental: bool,
    },
    Patch {
        head: git2::Oid,
        base: git2::Oid,
        name: Refname,
        re: Option<(Topic, Option<git2::Oid>)>,
    },
    Comment {
        topic: Topic,
        reply: Option<git2::Oid>,
    },
}

pub struct Submitter<'a, S: ?Sized> {
    pub signer: &'a mut S,
    pub id: IdentityId,
}

pub struct Repo {
    drp: git2::Repository,
    src: Option<git2::Repository>,
    ids: Vec<git2::Repository>,
}

impl Repo {
    pub fn new(
        drp: git2::Repository,
        ids: Vec<git2::Repository>,
        src: Option<git2::Repository>,
    ) -> Self {
        Self { drp, ids, src }
    }

    /// Repository containing the patch objects
    pub fn source(&self) -> &git2::Repository {
        self.src.as_ref().unwrap_or(&self.drp)
    }

    /// Repository containing the drop state
    pub fn target(&self) -> &git2::Repository {
        &self.drp
    }

    /// Repositories containing identity histories
    pub fn id_path(&self) -> &[git2::Repository] {
        &self.ids
    }
}

pub struct Preparator<'a, S: ?Sized> {
    repo: &'a Repo,
    drop: &'a patches::DropHead<'a>,
    submitter: Submitter<'a, S>,
}

impl<'a, S: Signer> Preparator<'a, S> {
    pub fn new(
        repo: &'a Repo,
        drop: &'a patches::DropHead<'a>,
        submitter: Submitter<'a, S>,
    ) -> Self {
        Self {
            repo,
            drop,
            submitter,
        }
    }

    pub fn prepare_patch(
        &mut self,
        bundle_dir: &Path,
        kind: Kind,
        message: Option<String>,
        additional_ids: &[IdentityId],
    ) -> cmd::Result<patches::Submission> {
        let mut header = bundle::Header::default();

        match kind {
            Kind::Mergepoint { force } => {
                mergepoint(self.repo, &self.drop.meta, &mut header, force)?;
                ensure!(
                    !header.references.is_empty(),
                    "refusing to create empty checkpoint"
                );
                self.annotate_checkpoint(&mut header, &TOPIC_MERGES, message)?;
            },
            Kind::Snapshot { incremental } => {
                snapshot(self.repo, &mut header, incremental)?;
                ensure!(
                    !header.references.is_empty(),
                    "refusing to create empty snapshot"
                );
                self.annotate_checkpoint(&mut header, &TOPIC_SNAPSHOTS, message)?;
            },
            Kind::Patch {
                head,
                base,
                name,
                re,
            } => {
                ensure!(base != head, "refusing to create empty patch");
                ensure!(
                    if_not_found_none(self.repo.source().merge_base(base, head))?.is_some(),
                    "{base} is not reachable from {head}"
                );
                info!("Adding patch for {name}: {base}..{head}");
                header.add_prerequisite(&base);
                header.add_reference(name, &head);
                self.annotate_patch(&mut header, message, re)?;
            },
            Kind::Comment { topic, reply } => {
                self.annotate_comment(&mut header, topic, message, reply)?;
            },
        }

        for id in additional_ids {
            Identity::find(
                self.repo.target(),
                &self.drop.ids,
                self.repo.id_path(),
                cmd::id::identity_ref(Left(id))?,
            )?
            .update(&mut header);
        }

        let signer_hash = {
            let keyid = self.submitter.signer.ident().keyid();
            let id_ref = cmd::id::identity_ref(Left(&self.submitter.id))?;
            let id = Identity::find(
                self.repo.target(),
                &self.drop.ids,
                self.repo.id_path(),
                id_ref,
            )?;
            ensure!(
                id.contains(&keyid),
                "signing key {keyid} not in identity {}",
                id.id()
            );
            id.update(&mut header);

            id.hash().clone()
        };

        let bundle = patches::Bundle::create(bundle_dir, self.repo.source(), header)?;
        let signature = bundle
            .sign(self.submitter.signer)
            .map(|signature| patches::Signature {
                signer: signer_hash,
                signature: signature.into(),
            })?;

        Ok(patches::Submission { signature, bundle })
    }

    fn annotate_checkpoint(
        &mut self,
        bundle: &mut bundle::Header,
        topic: &Topic,
        message: Option<String>,
    ) -> cmd::Result<()> {
        let kind = if topic == &*TOPIC_MERGES {
            notes::CheckpointKind::Merge
        } else if topic == &*TOPIC_SNAPSHOTS {
            notes::CheckpointKind::Snapshot
        } else {
            bail!("not a checkpoint topic: {topic}")
        };
        let note = notes::Simple::checkpoint(kind, bundle.references.clone(), message);
        let parent = topic::default_reply_to(self.repo.target(), topic)?
            .map(|id| self.repo.source().find_commit(id))
            .transpose()?;

        self.annotate(bundle, topic, parent, &note)
    }

    fn annotate_patch(
        &mut self,
        bundle: &mut bundle::Header,
        cover: Option<String>,
        re: Option<(Topic, Option<git2::Oid>)>,
    ) -> cmd::Result<()> {
        let cover = cover
            .map(notes::Simple::new)
            .map(Ok)
            .unwrap_or_else(|| edit_cover_letter(self.repo.source()))?;
        let (topic, parent) = match re {
            Some((topic, reply_to)) => {
                let parent = find_reply_to(self.repo, &topic, reply_to)?;
                (topic, Some(parent))
            },
            None => {
                // This is pretty arbitrary -- just use a random string instead?
                let topic = {
                    let mut hasher = Sha256::new();
                    hasher.update(record::Heads::from(bundle as &bundle::Header));
                    serde_json::to_writer(&mut hasher, &cover)?;
                    hasher.update(self.submitter.signer.ident().keyid());
                    Topic::from(hasher.finalize())
                };
                let parent = topic::default_reply_to(self.repo.target(), &topic)?
                    .map(|id| self.repo.source().find_commit(id))
                    .transpose()?;

                (topic, parent)
            },
        };

        self.annotate(bundle, &topic, parent, &cover)
    }

    fn annotate_comment(
        &mut self,
        bundle: &mut bundle::Header,
        topic: Topic,
        message: Option<String>,
        reply_to: Option<git2::Oid>,
    ) -> cmd::Result<()> {
        let parent = find_reply_to(self.repo, &topic, reply_to)?;
        let edit = || -> cmd::Result<notes::Simple> {
            let re = notes::Simple::from_commit(self.repo.target(), &parent)?;
            edit_comment(self.repo.source(), Some(&re))
        };
        let comment = message
            .map(notes::Simple::new)
            .map(Ok)
            .unwrap_or_else(edit)?;

        self.annotate(bundle, &topic, Some(parent), &comment)
    }

    fn annotate(
        &mut self,
        bundle: &mut bundle::Header,
        topic: &Topic,
        parent: Option<git2::Commit>,
        note: &notes::Simple,
    ) -> cmd::Result<()> {
        let repo = self.repo.source();
        let topic_ref = topic.as_refname();
        let tree = {
            let mut tb = repo.treebuilder(None)?;
            patches::to_tree(repo, &mut tb, note)?;
            repo.find_tree(tb.write()?)?
        };
        let msg = match note.subject() {
            Some(s) => format!("{}\n\n{}", s, topic.as_trailer()),
            None => topic.as_trailer(),
        };
        let commit = git::commit_signed(
            self.submitter.signer,
            repo,
            &msg,
            &tree,
            parent.as_ref().into_iter().collect::<Vec<_>>().as_slice(),
        )?;

        if let Some(commit) = parent {
            bundle.add_prerequisite(&commit.id());
        }
        bundle.add_reference(topic_ref, &commit);

        Ok(())
    }
}

fn mergepoint(
    repos: &Repo,
    meta: &metadata::drop::Verified,
    bundle: &mut bundle::Header,
    force: bool,
) -> git::Result<()> {
    for branch in meta.roles.branches.keys() {
        let sandboxed = match patches::TrackingBranch::try_from(branch) {
            Ok(tracking) => tracking,
            Err(e) => {
                warn!("Skipping invalid branch {branch}: {e}");
                continue;
            },
        };
        let head = {
            let local = repos.source().find_reference(branch)?;
            let head = local.peel_to_commit()?.id();
            if !force {
                if let Some(upstream) = if_not_found_none(git2::Branch::wrap(local).upstream())? {
                    let upstream_head = upstream.get().peel_to_commit()?.id();
                    if head != upstream_head {
                        warn!(
                            "Upstream {} is not even with {branch}; you may want to push first",
                            String::from_utf8_lossy(upstream.name_bytes()?)
                        );
                        info!("Skipping {branch}");
                        continue;
                    }
                }
            }

            head
        };
        match if_not_found_none(repos.target().find_reference(&sandboxed))? {
            Some(base) => {
                let base = base.peel_to_commit()?.id();
                if base == head {
                    info!("Skipping empty checkpoint");
                } else if if_not_found_none(repos.source().merge_base(base, head))?.is_some() {
                    info!("Adding thin checkpoint for branch {branch}: {base}..{head}");
                    bundle.add_prerequisite(&base);
                    bundle.add_reference(branch.clone(), &head);
                } else {
                    warn!(
                        "{branch} diverges from drop state: no merge base between {base}..{head}"
                    );
                }
            },

            None => {
                info!("Adding full checkpoint for branch {branch}: {head}");
                bundle.add_reference(branch.clone(), &head);
            },
        }
    }

    Ok(())
}

fn snapshot(repo: &Repo, bundle: &mut bundle::Header, incremental: bool) -> cmd::Result<()> {
    for record in dropped::records(repo.target(), REF_IT_PATCHES) {
        let record = record?;
        let bundle_hash = record.bundle_hash();
        if record.is_encrypted() {
            warn!("Skipping encrypted patch bundle {bundle_hash}",);
            continue;
        }

        if record.topic == *TOPIC_SNAPSHOTS {
            if !incremental {
                debug!("Full snapshot: skipping previous snapshot {bundle_hash}");
                continue;
            } else {
                info!("Incremental snapshot: found previous snapshot {bundle_hash}");
                for oid in record.meta.bundle.references.values().copied() {
                    info!("Adding prerequisite {oid} from {bundle_hash}");
                    bundle.add_prerequisite(oid);
                }
                break;
            }
        }

        info!("Including {bundle_hash} in snapshot");
        for (name, oid) in &record.meta.bundle.references {
            info!("Adding {oid} {name}");
            let name = patches::unbundled_ref(REF_IT_BUNDLES, &record, name)?;
            bundle.add_reference(name, *oid);
        }
    }

    Ok(())
}

fn find_reply_to<'a>(
    repo: &'a Repo,
    topic: &Topic,
    reply_to: Option<git2::Oid>,
) -> cmd::Result<git2::Commit<'a>> {
    let tip = if_not_found_none(repo.target().refname_to_id(&topic.as_refname()))?
        .ok_or_else(|| anyhow!("topic {topic} does not exist"))?;
    let id = match reply_to {
        Some(id) => {
            ensure!(
                repo.target().graph_descendant_of(tip, id)?,
                "{id} not found in topic {topic}, cannot reply"
            );
            id
        },
        None => topic::default_reply_to(repo.target(), topic)?.expect("impossible: empty topic"),
    };

    Ok(repo.source().find_commit(id)?)
}

struct Identity {
    hash: ContentHash,
    verified: identity::Verified,
    update: Option<Range>,
}

impl Identity {
    pub fn find(
        repo: &git2::Repository,
        ids: &git2::Tree,
        id_path: &[git2::Repository],
        refname: Refname,
    ) -> cmd::Result<Self> {
        let find_parent = metadata::git::find_parent(repo);

        struct Meta {
            hash: ContentHash,
            id: identity::Verified,
        }

        impl Meta {
            fn identity(&self) -> &metadata::Identity {
                self.id.identity()
            }
        }

        let (ours_in, ours) =
            metadata::Identity::from_search_path(id_path, &refname).and_then(|data| {
                let signer = data.meta.signed.verified(&find_parent)?;
                Ok((
                    data.repo,
                    Meta {
                        hash: data.meta.hash,
                        id: signer,
                    },
                ))
            })?;

        let tree_path = PathBuf::from(ours.id.id().to_string()).join(META_FILE_ID);
        let newer = match if_not_found_none(ids.get_path(&tree_path))? {
            None => {
                let start = ours_in.refname_to_id(&refname)?;
                let range = Range {
                    refname,
                    start,
                    end: None,
                };
                Self {
                    hash: ours.hash,
                    verified: ours.id,
                    update: Some(range),
                }
            },
            Some(in_tree) if ours.hash == in_tree.id() => Self {
                hash: ours.hash,
                verified: ours.id,
                update: None,
            },
            Some(in_tree) => {
                let theirs = metadata::Identity::from_blob(&repo.find_blob(in_tree.id())?)
                    .and_then(|GitMeta { hash, signed }| {
                        let signer = signed.verified(&find_parent)?;
                        Ok(Meta { hash, id: signer })
                    })?;

                if ours.identity().has_ancestor(&theirs.hash, &find_parent)? {
                    let range = Range::compute(ours_in, refname, theirs.hash.as_oid())?;
                    Self {
                        hash: ours.hash,
                        verified: ours.id,
                        update: range,
                    }
                } else if theirs.identity().has_ancestor(&ours.hash, &find_parent)? {
                    Self {
                        hash: theirs.hash,
                        verified: theirs.id,
                        update: None,
                    }
                } else {
                    bail!(
                        "provided identity at {} diverges from in-tree at {}",
                        ours.hash,
                        theirs.hash,
                    )
                }
            },
        };

        Ok(newer)
    }

    pub fn id(&self) -> &IdentityId {
        self.verified.id()
    }

    pub fn hash(&self) -> &ContentHash {
        &self.hash
    }

    pub fn contains(&self, key: &KeyId) -> bool {
        self.verified.identity().keys.contains_key(key)
    }

    pub fn update(&self, bundle: &mut bundle::Header) {
        if let Some(range) = &self.update {
            range.add_to_bundle(bundle);
        }
    }
}

struct Range {
    refname: Refname,
    start: git2::Oid,
    end: Option<git2::Oid>,
}

impl Range {
    fn compute(
        repo: &git2::Repository,
        refname: Refname,
        known: git2::Oid,
    ) -> cmd::Result<Option<Self>> {
        let start = repo.refname_to_id(&refname)?;

        let mut walk = repo.revwalk()?;
        walk.push(start)?;
        for oid in walk {
            let oid = oid?;
            let blob_id = repo
                .find_commit(oid)?
                .tree()?
                .get_name(META_FILE_ID)
                .ok_or_else(|| anyhow!("corrupt identity: missing {META_FILE_ID}"))?
                .id();

            if blob_id == known {
                return Ok(if oid == start {
                    None
                } else {
                    Some(Self {
                        refname,
                        start,
                        end: Some(oid),
                    })
                });
            }
        }

        Ok(Some(Self {
            refname,
            start,
            end: None,
        }))
    }

    fn add_to_bundle(&self, header: &mut bundle::Header) {
        header.add_reference(self.refname.clone(), &self.start);
        if let Some(end) = self.end {
            header.add_prerequisite(&end);
        }
    }
}
