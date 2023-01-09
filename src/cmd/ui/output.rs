// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

pub use log::{
    debug,
    error,
    info,
    warn,
};

pub struct Output;

impl log::Log for Output {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        let meta = record.metadata();
        if !self.enabled(meta) {
            return;
        }
        let level = meta.level();
        let style = {
            let s = console::Style::new().for_stderr();
            if level < log::Level::Info
                && console::user_attended_stderr()
                && console::colors_enabled_stderr()
            {
                match level {
                    log::Level::Error => s.red(),
                    log::Level::Warn => s.yellow(),
                    log::Level::Info | log::Level::Debug | log::Level::Trace => unreachable!(),
                }
            } else {
                s
            }
        };

        eprintln!("{}", style.apply_to(record.args()));
    }

    fn flush(&self) {}
}
