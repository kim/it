// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::ops::Deref;

/// A read-only snapshot of a [`git2::Config`]
pub struct Snapshot(git2::Config);

impl Deref for Snapshot {
    type Target = git2::Config;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<git2::Config> for Snapshot {
    type Error = git2::Error;

    fn try_from(mut cfg: git2::Config) -> Result<Self, Self::Error> {
        cfg.snapshot().map(Self)
    }
}

impl TryFrom<&mut git2::Config> for Snapshot {
    type Error = git2::Error;

    fn try_from(cfg: &mut git2::Config) -> Result<Self, Self::Error> {
        cfg.snapshot().map(Self)
    }
}
