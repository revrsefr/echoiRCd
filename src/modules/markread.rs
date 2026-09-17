//! markread — IRCv3 draft/read-marker. A client sets or queries the "last read"
//! timestamp per conversation; markers are keyed by account when logged in (shared
//! across a user's devices, surviving reconnects) and echoed to every connection
//! sharing that identity. The store lives in `Server.ext`, cleaned up by the
//! on_user_quit hook.

use crate::map::HashMap;

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

/// The read-marker database path: the `markread_database` conf key, or `<conf>.markread`.
fn db_path(s: &Server) -> String {
    match s.conf("markread_database") {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => format!("{}.markread", s.conf_path),
    }
}

/// Schema for the normalized read-marker store (used when `store_backend = pgsql`).
const MARKREAD_DDL: &str = "CREATE TABLE IF NOT EXISTS echoircd_markread \
     (identity text NOT NULL, target text NOT NULL, ts bigint NOT NULL)";

/// Serialise the durable (account-keyed) markers as `identity target ts` lines.
/// Session `~uid` keys are dropped — a uid doesn't outlive the connection, let
/// alone a restart. Output is sorted so it's stable across coalesced writes.
fn dump_markers(m: &ReadMarkers) -> String {
    let mut out = String::from("# echoircd read markers — auto-generated; account-keyed only\n");
    let mut ids: Vec<&String> = m.0.keys().filter(|k| !k.starts_with('~')).collect();
    ids.sort();
    for id in ids {
        if let Some(targets) = m.0.get(id) {
            let mut tk: Vec<&String> = targets.keys().collect();
            tk.sort();
            for t in tk {
                out.push_str(&format!("{id} {t} {}\n", targets[t]));
            }
        }
    }
    out
}

/// Parse the on-disk format back into a store (identity/target names carry no
/// spaces, so a 3-way split is unambiguous).
fn load_str(store: &mut ReadMarkers, text: &str) {
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(3, ' ');
        if let (Some(id), Some(target), Some(ts)) = (it.next(), it.next(), it.next()) {
            if let Ok(ts) = ts.parse::<u64>() {
                store
                    .0
                    .entry(id.to_string())
                    .or_default()
                    .insert(target.to_string(), ts);
            }
        }
    }
}

/// Persist the account-keyed markers (off-core). With the database backend each marker
/// is an `(identity, target, ts)` row in `echoircd_markread` (queryable, atomically
/// snapshot-replaced); with the file backend it stays one coalesced blob. Session
/// (`~uid`) identities are never durable.
pub fn save(s: &Server) {
    let Some(m) = s.ext.get::<ReadMarkers>() else {
        return;
    };
    if crate::database::stores_in_db(s) {
        let mut rows: Vec<Vec<Option<Vec<u8>>>> = Vec::new();
        for (id, targets) in &m.0 {
            if id.starts_with('~') {
                continue; // session key — not durable
            }
            for (t, ts) in targets {
                rows.push(vec![
                    Some(id.clone().into_bytes()),
                    Some(t.clone().into_bytes()),
                    Some((*ts as i64).to_string().into_bytes()),
                ]);
            }
        }
        crate::database::store_rows_replace(
            s,
            "echoircd_markread",
            "INSERT INTO echoircd_markread (identity, target, ts) VALUES ($1, $2, $3)",
            rows,
        );
        return;
    }
    crate::database::persist_save(s, "markread", &db_path(s), dump_markers(m));
}

/// Restore account-keyed markers at startup so read positions survive a restart.
/// Prefers the normalized table, migrating the legacy blob/file in if it's empty, and
/// falling back to the legacy text on any DB error.
pub fn load(s: &mut Server) {
    if crate::database::stores_in_db(s) {
        if let Some(rows) = crate::database::store_rows_load(
            s,
            MARKREAD_DDL,
            "SELECT identity, target, ts FROM echoircd_markread",
        ) {
            if rows.is_empty() {
                load_text(s); // migrate the legacy blob/file …
                save(s); // … and seed the table
            } else {
                let store = s
                    .ext
                    .get_or_insert_with::<ReadMarkers>(ReadMarkers::default);
                for r in &rows {
                    let id = r.first().and_then(|v| v.as_deref());
                    let t = r.get(1).and_then(|v| v.as_deref());
                    let ts = r
                        .get(2)
                        .and_then(|v| v.as_deref())
                        .and_then(|v| v.parse().ok());
                    if let (Some(id), Some(t), Some(ts)) = (id, t, ts) {
                        store
                            .0
                            .entry(id.to_string())
                            .or_default()
                            .insert(t.to_string(), ts);
                    }
                }
            }
            return;
        }
        // the database was unreachable — fall through to the legacy text
    }
    load_text(s);
}

/// Parse markers from the legacy text form (the central blob when pgsql, else the flat
/// file) into memory.
fn load_text(s: &mut Server) {
    let Some(text) = crate::database::persist_load(s, "markread", &db_path(s)) else {
        return;
    };
    let store = s
        .ext
        .get_or_insert_with::<ReadMarkers>(ReadMarkers::default);
    load_str(store, &text);
}

/// Cleanup hook: drop a user's session markers on disconnect (account-keyed
/// markers are intentionally kept so they persist across reconnects).
pub struct MarkRead;
impl Module for MarkRead {
    fn name(&self) -> &'static str {
        "markread"
    }
    fn description(&self) -> &'static str {
        "IRCv3 draft/read-marker: per-conversation last-read markers (account-shared)"
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
                // Sync the new marker to every connection under this identity that
                // negotiated draft/read-marker (multi-device); others never asked
                // for read-marker traffic.
                let recips: Vec<Uid> = s
                    .users
                    .iter()
                    .filter(|(&p, u)| u.caps.read_marker && marker_id(s, p) == id)
                    .map(|(&p, _)| p)
                    .collect();
                for p in recips {
                    s.send(p, line.clone());
                }
                if !id.starts_with('~') {
                    save(s); // account markers are durable — persist across restarts
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_round_trip_and_drop_session_keys() {
        let mut m = ReadMarkers::default();
        m.0.entry("alice".into())
            .or_default()
            .insert("#chan".into(), 1700);
        m.0.entry("alice".into())
            .or_default()
            .insert("bob".into(), 42);
        m.0.entry("~7".into())
            .or_default()
            .insert("#chan".into(), 9999); // session: ephemeral

        let text = dump_markers(&m);
        assert!(text.contains("alice #chan 1700"));
        assert!(text.contains("alice bob 42"));
        assert!(!text.contains("~7"), "session keys must not be persisted");

        // reload into a fresh store — the account markers come back, the session one doesn't
        let mut restored = ReadMarkers::default();
        load_str(&mut restored, &text);
        assert_eq!(
            restored.0.get("alice").and_then(|t| t.get("#chan")),
            Some(&1700)
        );
        assert_eq!(
            restored.0.get("alice").and_then(|t| t.get("bob")),
            Some(&42)
        );
        assert!(!restored.0.contains_key("~7"));
    }
}
