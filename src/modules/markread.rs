//! markread — InspIRCd's `m_ircv3_read_marker` (draft/read-marker). A client sets
//! or queries the "last read" timestamp per conversation; markers are keyed by
//! account when logged in (so they're shared across a user's devices and survive
//! reconnects) and echoed to every connection sharing that identity. Self-contained:
//! the marker store lives in `Server.ext`, cleaned up by the on_user_quit hook.

use std::collections::HashMap;

use crate::command::{CmdResult, Command};
use crate::module::Module;
use crate::server::{iso_time, parse_iso, Server};
use crate::Uid;

/// identity -> target (lowercased) -> read timestamp. Stored in `Server.ext`.
#[derive(Default)]
pub struct ReadMarkers(pub HashMap<String, HashMap<String, u64>>);

/// The read-marker identity for `uid`: their account when logged in (so markers
/// are shared across their devices and survive reconnects), else a per-session
/// key. The on_user_quit hook prunes the session key on disconnect.
pub fn marker_id(s: &Server, uid: Uid) -> String {
    s.users
        .get(&uid)
        .and_then(|u| u.account.clone())
        .unwrap_or_else(|| format!("~{uid}"))
}

/// Cleanup hook: drop a user's session markers on disconnect (account-keyed
/// markers are intentionally kept so they persist across reconnects).
pub struct MarkRead;
impl Module for MarkRead {
    fn name(&self) -> &'static str {
        "markread"
    }
    fn on_user_quit(&mut self, s: &mut Server, uid: Uid, _reason: &str) {
        if let Some(m) = s.ext.get_mut::<ReadMarkers>() {
            m.0.remove(&format!("~{uid}"));
        }
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(MarkReadCmd)]
}

/// MARKREAD — `MARKREAD <target> [timestamp=<iso>]`. With a timestamp it sets the
/// read marker (only ever advancing) and echoes it to every connection sharing the
/// user's identity (multi-device); without one it returns the stored marker (`*` if
/// unset).
struct MarkReadCmd;
impl Command for MarkReadCmd {
    fn name(&self) -> &'static str {
        "MARKREAD"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let target = params[0].clone();
        let tkey = target.to_ascii_lowercase();
        let id = marker_id(s, uid);
        match params.get(1).and_then(|p| p.strip_prefix("timestamp=")) {
            Some(ts_str) => {
                let cur = s
                    .ext
                    .get::<ReadMarkers>()
                    .and_then(|m| m.0.get(&id))
                    .and_then(|m| m.get(&tkey))
                    .copied()
                    .unwrap_or(0);
                let ts = parse_iso(ts_str).unwrap_or(0).max(cur); // markers only advance
                s.ext
                    .get_or_insert_with::<ReadMarkers>(ReadMarkers::default)
                    .0
                    .entry(id.clone())
                    .or_default()
                    .insert(tkey, ts);
                let line = format!(":{} MARKREAD {target} timestamp={}", s.name, iso_time(ts));
                let recips: Vec<Uid> = s
                    .users
                    .keys()
                    .copied()
                    .filter(|&p| marker_id(s, p) == id)
                    .collect();
                for p in recips {
                    s.send(p, line.clone());
                }
            }
            None => {
                let val = s
                    .ext
                    .get::<ReadMarkers>()
                    .and_then(|m| m.0.get(&id))
                    .and_then(|m| m.get(&tkey))
                    .copied()
                    .map(|t| format!("timestamp={}", iso_time(t)))
                    .unwrap_or_else(|| "*".to_string());
                s.send(uid, format!(":{} MARKREAD {target} {val}", s.name));
            }
        }
        CmdResult::Ok
    }
}
