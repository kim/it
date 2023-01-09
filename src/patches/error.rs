// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FromTree {
    #[error("'{name}' not found in tree")]
    NotFound { name: &'static str },

    #[error("expected '{name}' to be a blob, but found {kind:?}")]
    TypeMismatch {
        name: &'static str,
        kind: Option<git2::ObjectType>,
    },

    #[error("max blob size {max} exceeded: {found}")]
    BlobSize { max: usize, found: usize },

    #[error("type conversion from byte slice to T failed")]
    TypeConversion(#[source] crate::Error),

    #[error("invalid signature")]
    InvalidSignature(#[from] signature::Error),

    #[error(transparent)]
    Git(#[from] git2::Error),
}
