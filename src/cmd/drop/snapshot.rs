// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use crate::{
    cmd::{
        self,
        patch,
    },
    patches,
};

#[derive(Debug, clap::Args)]
pub struct Snapshot {
    #[clap(flatten)]
    common: patch::Common,
}

pub fn snapshot(Snapshot { common }: Snapshot) -> cmd::Result<patches::Record> {
    patch::create(patch::Kind::Snapshot { common })
}
