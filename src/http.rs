// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    fs::File,
    io::Cursor,
    net::ToSocketAddrs,
    path::{
        Path,
        PathBuf,
    },
    sync::{
        Arc,
        Mutex,
    },
};

use digest::Digest;
use log::{
    debug,
    error,
};
use once_cell::sync::Lazy;
use sha2::Sha256;
use threadpool::ThreadPool;
use tiny_http::{
    Header,
    HeaderField,
    Method,
    Request,
    Response,
    ServerConfig,
    StatusCode,
};
use url::Url;

use crate::{
    bundle,
    git,
    keys,
    patches::{
        self,
        AcceptArgs,
        AcceptOptions,
    },
    ssh::agent,
};

pub use tiny_http::SslConfig;

pub struct Options {
    /// Directory of the drop repo
    pub git_dir: PathBuf,
    /// Directory from where to serve bundles
    ///
    /// Unless absolute, treated as relative to GIT_DIR.
    pub bundle_dir: PathBuf,
    /// Ref prefix under which to store the refs contained in patch bundles
    pub unbundle_prefix: String,
    /// The refname of the drop history
    pub drop_ref: String,
    /// The refname anchoring the seen objects tree
    pub seen_ref: String,
    /// Size of the server's threadpool
    ///
    /// If `None`, the number of available CPUs is used.
    pub threads: Option<usize>,
    /// Certificate and key for `serve`ing over TLS.
    ///
    /// It is generally recommended to proxy behind a terminating web server and
    /// set this to `None`.
    pub tls: Option<SslConfig>,
    /// IPFS API to publish received bundles to
    pub ipfs_api: Option<Url>,
}

pub fn serve<A>(addr: A, opts: Options) -> !
where
    A: ToSocketAddrs,
{
    let executor = ThreadPool::new(opts.threads.unwrap_or_else(num_cpus::get));
    let server = tiny_http::Server::new(ServerConfig {
        addr,
        ssl: opts.tls,
    })
    .unwrap();

    let repo = git::repo::open(&opts.git_dir).unwrap();
    let config = repo.config().unwrap();

    let git_dir = repo.path().to_owned();
    let bundle_dir = if opts.bundle_dir.is_relative() {
        git_dir.join(opts.bundle_dir)
    } else {
        opts.bundle_dir
    };

    let signer = keys::Agent::from_gitconfig(&config).unwrap();

    let handler = Arc::new(Handler {
        repo: Mutex::new(repo),
        signer: Mutex::new(signer),
        bundle_dir,
        unbundle_prefix: opts.unbundle_prefix,
        drop_ref: opts.drop_ref,
        seen_ref: opts.seen_ref,
        ipfs_api: opts.ipfs_api,
    });
    for req in server.incoming_requests() {
        let handler = Arc::clone(&handler);
        executor.execute(move || handler.route(req))
    }

    panic!("server died unexpectedly");
}

static CONTENT_TYPE: Lazy<HeaderField> = Lazy::new(|| "Content-Type".parse().unwrap());

static OCTET_STREAM: Lazy<Header> = Lazy::new(|| Header {
    field: CONTENT_TYPE.clone(),
    value: "application/octet-stream".parse().unwrap(),
});
static TEXT_PLAIN: Lazy<Header> = Lazy::new(|| Header {
    field: CONTENT_TYPE.clone(),
    value: "text/plain".parse().unwrap(),
});
static JSON: Lazy<Header> = Lazy::new(|| Header {
    field: CONTENT_TYPE.clone(),
    value: "application/json".parse().unwrap(),
});
static SERVER: Lazy<Header> = Lazy::new(|| Header {
    field: "Server".parse().unwrap(),
    value: format!("it/{}", env!("CARGO_PKG_VERSION", "unknown"))
        .parse()
        .unwrap(),
});

enum Resp {
    Empty {
        code: StatusCode,
    },
    Text {
        code: StatusCode,
        body: String,
    },
    File {
        file: File,
    },
    Json {
        code: StatusCode,
        body: Box<dyn erased_serde::Serialize>,
    },
}

impl Resp {
    const OK: Self = Self::Empty {
        code: StatusCode(200),
    };
    const NOT_FOUND: Self = Self::Empty {
        code: StatusCode(404),
    };
    const METHOD_NOT_ALLOWED: Self = Self::Empty {
        code: StatusCode(405),
    };
    const INTERNAL_SERVER_ERROR: Self = Self::Empty {
        code: StatusCode(500),
    };

    fn respond_to(self, req: Request) {
        let remote_addr = *req.remote_addr();
        let response = Response::empty(500).with_header(SERVER.clone());
        let res = match self {
            Self::Empty { code } => req.respond(response.with_status_code(code)),
            Self::Text { code, body } => {
                let len = body.len();
                req.respond(
                    response
                        .with_status_code(code)
                        .with_header(TEXT_PLAIN.clone())
                        .with_data(Cursor::new(body.into_bytes()), Some(len)),
                )
            },
            Self::File { file } => {
                let len = file.metadata().ok().and_then(|v| v.len().try_into().ok());
                req.respond(
                    response
                        .with_status_code(200)
                        .with_header(OCTET_STREAM.clone())
                        .with_data(file, len),
                )
            },
            Self::Json { code, body } => {
                let json = serde_json::to_vec(&body).unwrap();
                let len = json.len();
                req.respond(
                    response
                        .with_status_code(code)
                        .with_header(JSON.clone())
                        .with_data(Cursor::new(json), Some(len)),
                )
            },
        };

        if let Err(e) = res {
            error!("failed to send response to {remote_addr}: {e}");
        }
    }
}

impl From<StatusCode> for Resp {
    fn from(code: StatusCode) -> Self {
        Self::Empty { code }
    }
}

struct Handler {
    repo: Mutex<git2::Repository>,
    signer: Mutex<keys::Agent<agent::UnixStream>>,
    bundle_dir: PathBuf,
    unbundle_prefix: String,
    drop_ref: String,
    seen_ref: String,
    ipfs_api: Option<Url>,
}

impl Handler {
    fn route(&self, mut req: Request) {
        use Method::*;

        debug!("{} {}", req.method(), req.url());
        let resp = match req.method() {
            Get => match &request_target(&req)[..] {
                ["-", "status"] => Resp::OK,
                ["bundles", hash] => self.get_bundle(hash),
                _ => Resp::NOT_FOUND,
            },

            Post => match &request_target(&req)[..] {
                ["patches"] => self.post_patch(&mut req),
                _ => Resp::NOT_FOUND,
            },

            _ => Resp::METHOD_NOT_ALLOWED,
        };

        resp.respond_to(req)
    }

    fn get_bundle(&self, hash: &str) -> Resp {
        fn base_path(root: &Path, s: &str) -> Result<PathBuf, Resp> {
            bundle::Hash::is_valid(s)
                .then(|| root.join(s))
                .ok_or_else(|| Resp::Text {
                    code: 400.into(),
                    body: "invalid bundle hash".into(),
                })
        }

        if let Some(hash) = hash.strip_suffix(bundle::list::DOT_FILE_EXTENSION) {
            base_path(&self.bundle_dir, hash).map_or_else(
                |x| x,
                |base| {
                    let path = base.with_extension(bundle::list::FILE_EXTENSION);
                    if !path.exists() && base.with_extension(bundle::FILE_EXTENSION).exists() {
                        default_bundle_list(hash)
                    } else {
                        serve_file(path)
                    }
                },
            )
        } else if let Some(hash) = hash.strip_suffix(bundle::DOT_FILE_EXTENSION) {
            base_path(&self.bundle_dir, hash).map_or_else(
                |x| x,
                |mut path| {
                    path.set_extension(bundle::FILE_EXTENSION);
                    serve_file(path)
                },
            )
        } else {
            base_path(&self.bundle_dir, hash).map_or_else(
                |x| x,
                |mut base| {
                    base.set_extension(bundle::FILE_EXTENSION);
                    if !base.exists() {
                        base.set_extension(bundle::list::FILE_EXTENSION);
                    }
                    serve_file(base)
                },
            )
        }
    }

    fn post_patch(&self, req: &mut Request) -> Resp {
        patches::Submission::from_http(&self.bundle_dir, req)
            .and_then(|mut sub| {
                let repo = self.repo.lock().unwrap();
                let mut signer = self.signer.lock().unwrap();
                sub.try_accept(AcceptArgs {
                    unbundle_prefix: &self.unbundle_prefix,
                    drop_ref: &self.drop_ref,
                    seen_ref: &self.seen_ref,
                    repo: &repo,
                    signer: &mut *signer,
                    ipfs_api: self.ipfs_api.as_ref(),
                    options: AcceptOptions::default(),
                })
            })
            .map(|record| Resp::Json {
                code: 200.into(),
                body: Box::new(record),
            })
            .unwrap_or_else(|e| Resp::Text {
                code: 400.into(),
                body: e.to_string(),
            })
    }
}

// We've been calling this "request URL", but acc. to RFC7230 it is the
// "request-target".
fn request_target(req: &Request) -> Vec<&str> {
    req.url().split('/').filter(|s| !s.is_empty()).collect()
}

fn serve_file<P: AsRef<Path>>(path: P) -> Resp {
    let path = path.as_ref();
    if path.exists() {
        File::open(path)
            .map(|file| Resp::File { file })
            .unwrap_or_else(|e| {
                error!("failed to open file {}: {e}", path.display());
                Resp::INTERNAL_SERVER_ERROR
            })
    } else {
        Resp::NOT_FOUND
    }
}

fn default_bundle_list(hash: &str) -> Resp {
    let uri = bundle::Uri::Relative(format!("/bundle/{}.bundle", hash));
    let id = hex::encode(Sha256::digest(uri.as_str()));

    let body = bundle::List {
        bundles: vec![bundle::Location::new(id, uri)],
        ..bundle::List::any()
    }
    .to_str();

    Resp::Text {
        code: 200.into(),
        body,
    }
}
