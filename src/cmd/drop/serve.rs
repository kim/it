// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    fs::File,
    io::Read,
    path::PathBuf,
    str::FromStr,
};

use clap::ValueHint;
use url::Url;

use super::Common;
use crate::{
    cfg,
    cmd::{
        self,
        args::Refname,
    },
    http,
    patches::{
        REF_IT_BUNDLES,
        REF_IT_PATCHES,
        REF_IT_SEEN,
    },
};

#[derive(Debug, clap::Args)]
pub struct Serve {
    #[clap(flatten)]
    common: Common,
    /// The directory where to write the bundle to
    ///
    /// Unless this is an absolute path, it is treated as relative to $GIT_DIR.
    #[clap(
        long,
        value_parser,
        value_name = "DIR",
        default_value_os_t = cfg::paths::bundles().to_owned(),
        value_hint = ValueHint::DirPath,
    )]
    bundle_dir: PathBuf,
    /// Ref prefix under which to store the refs contained in patch bundles
    #[clap(
        long,
        value_parser,
        value_name = "REF",
        default_value_t = Refname::from_str(REF_IT_BUNDLES).unwrap()
    )]
    unbundle_prefix: Refname,
    /// The refname anchoring the seen objects tree
    #[clap(
        long,
        value_parser,
        value_name = "REF",
        default_value_t = Refname::from_str(REF_IT_SEEN).unwrap()
    )]
    seen_ref: Refname,
    /// 'host:port' to listen on
    #[clap(
        long,
        value_parser,
        value_name = "HOST:PORT",
        default_value = "127.0.0.1:8084"
    )]
    listen: String,
    /// Number of threads to use for the server
    ///
    /// If not set, the number of available cores is used.
    #[clap(long, value_parser, value_name = "INT")]
    threads: Option<usize>,
    /// PEM-encoded TLS certificate
    ///
    /// Requires 'tls-key'. If not set (the default), the server will not use
    /// TLS.
    #[clap(
        long,
        value_parser,
        value_name = "FILE",
        requires = "tls_key",
        value_hint = ValueHint::FilePath
    )]
    tls_cert: Option<PathBuf>,
    /// PEM-encoded TLS private key
    ///
    /// Requires 'tls-cert'. If not set (the default), the server will not use
    /// TLS.
    #[clap(
        long,
        value_parser,
        value_name = "FILE",
        requires = "tls_cert",
        value_hint = ValueHint::FilePath
    )]
    tls_key: Option<PathBuf>,
    /// IPFS API to publish received patch bundle to
    #[clap(
        long,
        value_parser,
        value_name = "URL",
        value_hint = ValueHint::Url,
    )]
    ipfs_api: Option<Url>,
}

#[derive(serde::Serialize)]
pub struct Output;

pub fn serve(args: Serve) -> cmd::Result<Output> {
    let tls = args
        .tls_cert
        .map(|cert_path| -> cmd::Result<http::SslConfig> {
            let mut certificate = Vec::new();
            let mut private_key = Vec::new();
            File::open(cert_path)?.read_to_end(&mut certificate)?;
            File::open(args.tls_key.expect("presence of 'tls-key' ensured by clap"))?
                .read_to_end(&mut private_key)?;

            Ok(http::SslConfig {
                certificate,
                private_key,
            })
        })
        .transpose()?;

    http::serve(
        args.listen,
        http::Options {
            git_dir: args.common.git_dir,
            bundle_dir: args.bundle_dir,
            unbundle_prefix: args.unbundle_prefix.into(),
            drop_ref: REF_IT_PATCHES.into(),
            seen_ref: args.seen_ref.into(),
            threads: args.threads,
            tls,
            ipfs_api: args.ipfs_api,
        },
    )
}
