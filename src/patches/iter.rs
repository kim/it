// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    collections::BTreeSet,
    rc::Rc,
    str::FromStr,
};

use anyhow::anyhow;
use time::{
    OffsetDateTime,
    UtcOffset,
};

use super::{
    notes,
    record::{
        Heads,
        Record,
    },
    Topic,
    GLOB_IT_TOPICS,
    TOPIC_MERGES,
};
use crate::{
    git::{
        self,
        Refname,
        EMPTY_TREE,
    },
    iter,
    patches::REF_IT_BUNDLES,
    Result,
};

pub mod dropped {
    use super::*;
    use crate::{
        error,
        patches::TOPIC_SNAPSHOTS,
    };

    pub fn topics<'a>(
        repo: &'a git2::Repository,
        drop_ref: &'a str,
    ) -> impl Iterator<Item = Result<(Topic, git2::Oid)>> + 'a {
        let topic = move |oid| -> Result<Option<(Topic, git2::Oid)>> {
            let commit = repo.find_commit(oid)?;
            Ok(Topic::from_commit(&commit)?.map(|topic| (topic, oid)))
        };
        let init = || {
            let mut walk = repo.revwalk()?;
            walk.push_ref(drop_ref)?;
            Ok(walk.map(|i| i.map_err(Into::into)))
        };

        iter::Iter::new(init, Some).filter_map(move |oid| oid.and_then(topic).transpose())
    }

    pub fn topic<'a>(
        repo: &'a git2::Repository,
        drop_ref: &'a str,
        topic: &'a Topic,
    ) -> impl Iterator<Item = Result<git2::Oid>> + 'a {
        topics(repo, drop_ref).filter_map(move |i| {
            i.map(|(top, oid)| (&top == topic).then_some(oid))
                .transpose()
        })
    }

    #[allow(unused)]
    pub fn merges<'a>(
        repo: &'a git2::Repository,
        drop_ref: &'a str,
    ) -> impl Iterator<Item = Result<git2::Oid>> + 'a {
        topic(repo, drop_ref, &TOPIC_MERGES)
    }

    #[allow(unused)]
    pub fn snapshots<'a>(
        repo: &'a git2::Repository,
        drop_ref: &'a str,
    ) -> impl Iterator<Item = Result<git2::Oid>> + 'a {
        topic(repo, drop_ref, &TOPIC_SNAPSHOTS)
    }

    pub fn records<'a>(
        repo: &'a git2::Repository,
        drop_ref: &'a str,
    ) -> impl Iterator<Item = Result<Record>> + 'a {
        _records(repo, drop_ref, false)
    }

    pub fn records_rev<'a>(
        repo: &'a git2::Repository,
        drop_ref: &'a str,
    ) -> impl Iterator<Item = Result<Record>> + 'a {
        _records(repo, drop_ref, true)
    }

    fn _records<'a>(
        repo: &'a git2::Repository,
        drop_ref: &'a str,
        rev: bool,
    ) -> impl Iterator<Item = Result<Record>> + 'a {
        let record = move |oid| -> Result<Option<Record>> {
            let commit = repo.find_commit(oid)?;
            match Record::from_commit(repo, &commit) {
                Ok(r) => Ok(Some(r)),
                Err(e) => match e.downcast_ref::<error::NotFound<&str, String>>() {
                    Some(error::NotFound { what: "topic", .. }) => Ok(None),
                    _ => Err(e),
                },
            }
        };
        let init = move || {
            let mut walk = repo.revwalk()?;
            walk.push_ref(drop_ref)?;
            if rev {
                walk.set_sorting(git2::Sort::REVERSE)?;
            }
            Ok(walk.map(|i| i.map_err(Into::into)))
        };

        iter::Iter::new(init, Some).filter_map(move |oid| oid.and_then(record).transpose())
    }
}

pub mod unbundled {
    use super::*;

    #[allow(unused)]
    pub fn topics(repo: &git2::Repository) -> impl Iterator<Item = Result<Topic>> + '_ {
        iter::Iter::new(
            move || {
                let refs = repo.references_glob(GLOB_IT_TOPICS.glob())?;
                Ok(git::ReferenceNames::new(refs, Topic::from_refname))
            },
            Some,
        )
    }

    pub fn topics_with_subject(
        repo: &git2::Repository,
    ) -> impl Iterator<Item = Result<(Topic, String)>> + '_ {
        let topic_and_subject = move |refname: &str| -> Result<(Topic, String)> {
            let topic = Topic::from_refname(refname)?;
            let subject = find_subject(repo, refname)?;
            Ok((topic, subject))
        };
        iter::Iter::new(
            move || {
                let refs = repo.references_glob(GLOB_IT_TOPICS.glob())?;
                Ok(git::ReferenceNames::new(refs, topic_and_subject))
            },
            Some,
        )
    }

    // TODO: cache this somewhere
    fn find_subject(repo: &git2::Repository, topic_ref: &str) -> Result<String> {
        let mut walk = repo.revwalk()?;
        walk.push_ref(topic_ref)?;
        walk.simplify_first_parent()?;
        walk.set_sorting(git2::Sort::TOPOLOGICAL | git2::Sort::REVERSE)?;
        match walk.next() {
            None => Ok(String::default()),
            Some(oid) => {
                let tree = repo.find_commit(oid?)?.tree()?;
                let note = notes::Note::from_tree(repo, &tree)?;
                let subj = match note {
                    notes::Note::Simple(n) => n
                        .checkpoint_kind()
                        .map(|k| {
                            match k {
                                notes::CheckpointKind::Merge => "Merges",
                                notes::CheckpointKind::Snapshot => "Snapshots",
                            }
                            .to_owned()
                        })
                        .unwrap_or_else(|| n.subject().unwrap_or_default().to_owned()),
                    _ => String::default(),
                };

                Ok(subj)
            },
        }
    }
}

#[derive(Eq, PartialEq, serde::Serialize)]
pub struct Subject {
    pub name: String,
    pub email: String,
}

impl TryFrom<git2::Signature<'_>> for Subject {
    type Error = std::str::Utf8Error;

    fn try_from(git: git2::Signature<'_>) -> std::result::Result<Self, Self::Error> {
        let utf8 = |bs| std::str::from_utf8(bs).map(ToOwned::to_owned);

        let name = utf8(git.name_bytes())?;
        let email = utf8(git.email_bytes())?;

        Ok(Self { name, email })
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NoteHeader {
    #[serde(with = "git::serde::oid")]
    pub id: git2::Oid,
    pub author: Subject,
    /// `Some` iff different from `author`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committer: Option<Subject>,
    /// Committer time
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    pub patch: Rc<PatchInfo>,
    #[serde(
        with = "git::serde::oid::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub in_reply_to: Option<git2::Oid>,
}

#[derive(serde::Serialize)]
pub struct PatchInfo {
    pub id: Heads,
    pub tips: BTreeSet<Refname>,
}

#[derive(serde::Serialize)]
pub struct Note {
    pub header: NoteHeader,
    pub message: notes::Note,
}

pub fn topic<'a>(
    repo: &'a git2::Repository,
    topic: &'a Topic,
) -> impl Iterator<Item = Result<Note>> + DoubleEndedIterator + 'a {
    let init = move || {
        let topic_ref = topic.as_refname();
        let mut walk = repo.revwalk()?;
        walk.push_ref(&topic_ref)?;
        walk.set_sorting(git2::Sort::TOPOLOGICAL)?;

        fn patch_id(c: &git2::Commit) -> Result<Option<Heads>> {
            let parse = || Heads::try_from(c);
            let is_merge = c.tree_id() == *EMPTY_TREE;
            is_merge.then(parse).transpose()
        }

        fn patch_info(repo: &git2::Repository, id: Heads) -> Result<PatchInfo> {
            let prefix = format!("{}/{}", REF_IT_BUNDLES, id);
            let glob = format!("{prefix}/**");
            let mut iter = repo.references_glob(&glob)?;
            let tips = iter
                .names()
                .filter_map(|i| match i {
                    Err(e) => Some(Err(e.into())),
                    Ok(name)
                        if name
                            .strip_prefix(&prefix)
                            .expect("glob yields prefix")
                            .starts_with("/it/") =>
                    {
                        None
                    },
                    Ok(name) => Refname::from_str(name)
                        .map_err(Into::into)
                        .map(Some)
                        .transpose(),
                })
                .collect::<Result<_>>()?;

            Ok(PatchInfo { id, tips })
        }

        let mut patches: Vec<Rc<PatchInfo>> = Vec::new();
        let mut commits: Vec<(git2::Tree<'a>, NoteHeader)> = Vec::new();

        if let Some(tip) = walk.next() {
            // ensure tip is a merge
            {
                let tip = repo.find_commit(tip?)?;
                let id = patch_id(&tip)?.ok_or_else(|| {
                    anyhow!("invalid topic '{topic_ref}': tip must be a merge commit")
                })?;
                let patch = patch_info(repo, id)?;
                patches.push(Rc::new(patch));
            }

            for id in walk {
                let commit = repo.find_commit(id?)?;
                match patch_id(&commit)? {
                    Some(id) => {
                        let patch = patch_info(repo, id)?;
                        patches.push(Rc::new(patch))
                    },
                    None => {
                        let id = commit.id();
                        let (author, committer) = {
                            let a = commit.author();
                            let c = commit.committer();

                            if a.name_bytes() != c.name_bytes()
                                && a.email_bytes() != c.email_bytes()
                            {
                                let author = Subject::try_from(a)?;
                                let committer = Subject::try_from(c).map(Some)?;

                                (author, committer)
                            } else {
                                (Subject::try_from(a)?, None)
                            }
                        };
                        let time = {
                            let t = commit.time();
                            let ofs = UtcOffset::from_whole_seconds(t.offset_minutes() * 60)?;
                            OffsetDateTime::from_unix_timestamp(t.seconds())?.replace_offset(ofs)
                        };
                        let tree = commit.tree()?;
                        let patch = Rc::clone(&patches[patches.len() - 1]);
                        let in_reply_to = commit.parent_ids().next();

                        let header = NoteHeader {
                            id,
                            author,
                            committer,
                            time,
                            patch,
                            in_reply_to,
                        };

                        commits.push((tree, header));
                    },
                }
            }
        }

        Ok(commits.into_iter().map(move |(tree, header)| {
            notes::Note::from_tree(repo, &tree).map(|message| Note { header, message })
        }))
    };

    iter::Iter::new(init, Some)
}

pub mod topic {
    use crate::git::if_not_found_none;

    use super::*;

    pub(crate) fn default_reply_to(
        repo: &git2::Repository,
        topic: &Topic,
    ) -> Result<Option<git2::Oid>> {
        let topic_ref = topic.as_refname();
        if if_not_found_none(repo.refname_to_id(&topic_ref))?.is_none() {
            return Ok(None);
        }

        let mut walk = repo.revwalk()?;
        walk.set_sorting(git2::Sort::TOPOLOGICAL | git2::Sort::REVERSE)?;
        walk.push_ref(&topic_ref)?;

        let first = walk
            .next()
            .expect("topic can't be empty, because {topic_ref} exists")?;
        let mut last = first;
        let mut seen = BTreeSet::<git2::Oid>::new();
        for id in walk {
            let id = id?;
            let commit = repo.find_commit(id)?;
            if commit.tree_id() != *EMPTY_TREE {
                let first_parent = commit
                    .parent_ids()
                    .next()
                    .expect("commit {id} must have a parent");
                if first_parent == first || !seen.contains(&first_parent) {
                    last = id;
                }
                seen.insert(id);
            }
        }

        Ok(Some(last))
    }
}
