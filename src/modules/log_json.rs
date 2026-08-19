//! log_json — append the server-notice / log stream to a file as JSON, one object
//! per line (JSONL). Off unless `log_json = <path>` is set. Reuses the
//! `draft/json-log` object builder. The file handle is cached on the core thread
//! (snotice is single-threaded) and reopened if the path changes or a write fails —
//! so an external logrotate that renames the file is picked up on the next line.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::Write;

use crate::server::Server;

thread_local! {
    /// (configured path, open append handle or `None` if opening it failed) cached
    /// for reuse. Caching the failure stops us re-issuing an `open` syscall — and a
    /// silent drop — on every single notice when the path is misconfigured.
    static SINK: RefCell<Option<(String, Option<File>)>> = const { RefCell::new(None) };
}

/// Append `msg` as a JSON line to the configured log file. Called at the tail of
/// [`Server::snotice`].
pub fn tee(s: &Server, msg: &str) {
    let Some(path) = s.conf("log_json") else {
        SINK.with(|c| *c.borrow_mut() = None); // disabled: drop any handle
        return;
    };
    let line = crate::modules::jsonlog::json_line(s, msg);
    SINK.with(|cell| {
        let mut slot = cell.borrow_mut();
        let need_open = match slot.as_ref() {
            Some((p, _)) => p != path,
            None => true,
        };
        if need_open {
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(f) => *slot = Some((path.to_string(), Some(f))),
                Err(e) => {
                    // surface once (this branch only runs when the path changes),
                    // then remember the failure so we don't retry every notice
                    eprintln!("echoircd: log_json cannot open {path}: {e}");
                    *slot = Some((path.to_string(), None));
                }
            }
        }
        if let Some((_, Some(f))) = slot.as_mut() {
            if writeln!(f, "{line}").is_err() {
                *slot = None; // reopen next time (e.g. after a logrotate rename)
            }
        }
    });
}
