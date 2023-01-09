// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    io,
    path::PathBuf,
};

use clap::ValueHint;
use clap_complete::Shell;

static OUTPUT: it::Output = it::Output;

fn main() -> it::Result<()> {
    use clap::Parser as _;

    log::set_logger(&OUTPUT)?;
    log::set_max_level(
        std::env::var("RUST_LOG")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(log::LevelFilter::Info),
    );

    let cli = It::parse();
    match cli.cmd {
        Cmd::Cmd(cmd) => cmd
            .run()
            .and_then(|o| render(o, cli.compact))
            .or_else(|e| e.downcast::<it::cmd::Aborted>().map(|_aborted| ())),
        Cmd::Hidden(cmd) => match cmd {
            Hidden::Man { out } => hidden::mangen(&out),
            Hidden::Completions { shell, out } => hidden::completions(shell, out.as_deref()),
        },
    }
}

/// it: zero-g git
#[derive(Debug, clap::Parser)]
#[clap(author, version, about, propagate_version = true, max_term_width = 100)]
struct It {
    /// Path to the git repository containing the drop state
    #[clap(
        long,
        value_parser,
        value_name = "DIR",
        env = "GIT_DIR",
        default_value_os_t = std::env::current_dir().unwrap(),
        value_hint = ValueHint::DirPath,
        global = true,
    )]
    git_dir: PathBuf,
    /// Do not pretty-print the output
    #[clap(long, value_parser, default_value_t = false, global = true)]
    compact: bool,
    #[clap(subcommand)]
    cmd: Cmd,
}

fn render(output: it::cmd::Output, compact: bool) -> it::Result<()> {
    use it::cmd::Output::*;

    let go = |v| {
        let out = io::stdout();
        if compact {
            serde_json::to_writer(out, &v)
        } else {
            serde_json::to_writer_pretty(out, &v)
        }
    };

    match output {
        Val(v) => go(v)?,
        Iter(i) => {
            for v in i {
                let v = v?;
                go(v)?;
                println!();
            }
        },
    }

    Ok(())
}

#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Cmd {
    #[clap(flatten)]
    Cmd(it::Cmd),
    #[clap(flatten)]
    Hidden(Hidden),
}

#[derive(Debug, clap::Subcommand)]
#[clap(hide = true)]
enum Hidden {
    /// Generate man pages
    #[clap(hide = true)]
    Man {
        /// Output to this directory
        #[clap(
            value_parser,
            default_value = "man",
            value_name = "DIR",
            value_hint = ValueHint::DirPath,
        )]
        out: PathBuf,
    },
    /// Generate shell completions
    #[clap(hide = true)]
    Completions {
        /// The shell to generate completions for
        #[clap(value_parser)]
        shell: Shell,
        /// Output file (stdout if not set)
        #[clap(value_parser, value_name = "FILE", value_hint = ValueHint::FilePath)]
        out: Option<PathBuf>,
    },
}

mod hidden {
    use std::{
        fs::File,
        io,
        path::Path,
    };

    use clap::CommandFactory as _;
    use clap_complete::Shell;
    use clap_mangen::Man;

    pub fn mangen(out: &Path) -> it::Result<()> {
        std::fs::create_dir_all(out)?;
        let it = super::It::command();
        for cmd in it.get_subcommands() {
            if cmd.get_name() == "dev" {
                continue;
            }
            for sub in cmd.get_subcommands() {
                let name = format!("{}-{}-{}", it.get_name(), cmd.get_name(), sub.get_name());
                let filename = out.join(&name).with_extension("1");

                let the_cmd = sub.clone().name(&name);
                let man = Man::new(the_cmd)
                    .title(name.to_uppercase())
                    .section("1")
                    .manual("It Manual");

                eprintln!("Generating {}...", filename.display());
                man.render(
                    &mut File::options()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&filename)?,
                )?;
            }
        }

        Ok(())
    }

    pub fn completions(shell: Shell, out: Option<&Path>) -> it::Result<()> {
        match out {
            Some(path) => {
                let mut out = File::options()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)?;
                clap_complete::generate(shell, &mut super::It::command(), "it", &mut out);
            },
            None => {
                clap_complete::generate(shell, &mut super::It::command(), "it", &mut io::stdout());
            },
        }

        Ok(())
    }
}
