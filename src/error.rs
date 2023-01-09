// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

pub type Error = anyhow::Error;
pub type Result<T> = anyhow::Result<T>;

#[derive(Debug, thiserror::Error)]
#[error("{what} not found in {whence}")]
pub struct NotFound<T, U> {
    pub what: T,
    pub whence: U,
}
