// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use thiserror::Error;

use super::{
    ObjectFormat,
    ObjectId,
};
use crate::git::refs;

#[derive(Debug, Error)]
pub enum Header {
    #[error("invalid header: {0}")]
    Format(&'static str),

    #[error("unrecognised header {0}")]
    UnrecognisedHeader(String),

    #[error("object id {oid} not valid for object-format {fmt}")]
    ObjectFormat { fmt: ObjectFormat, oid: ObjectId },

    #[error("invalid reference name")]
    Refname(#[from] refs::error::RefFormat),

    #[error("invalid hex oid")]
    Oid(#[from] hex::FromHexError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
