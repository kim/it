// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

mod bundle;
mod cfg;
mod fs;
mod git;
mod http;
mod io;
mod iter;
mod json;
mod keys;
mod metadata;
mod patches;
mod serde;
mod ssh;
mod str;

pub const SPEC_VERSION: metadata::SpecVersion = metadata::SpecVersion::current();

pub mod cmd;
pub use cmd::{
    ui::Output,
    Cmd,
};

pub mod error;
pub use error::{
    Error,
    Result,
};

pub use cfg::paths;
