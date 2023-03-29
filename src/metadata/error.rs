// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::io;

use thiserror::Error;

use super::KeyId;
use crate::json::canonical::error::Canonicalise;

#[derive(Debug, Error)]
pub enum SigId {
    #[error("payload not at root revision")]
    NotRoot,

    #[error("invalid payload: canonicalisation failed")]
    Canonical(#[from] Canonicalise),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Verification {
    #[error("incompatible format version")]
    IncompatibleVersion,

    #[error("canonicalisation failed")]
    Canonicalise(#[from] Canonicalise),

    #[error("required signature threshold not met")]
    SignatureThreshold,

    #[error("metadata past its expiry date")]
    Expired,

    #[error("duplicate key: key {0} appears in more than one identity")]
    DuplicateKey(KeyId),

    #[error(transparent)]
    Io(#[from] io::Error),
}
