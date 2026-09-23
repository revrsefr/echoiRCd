//! Permanent-channel persistence. A `+P` channel already survives an empty
//! member list in memory (see `Channel::keep_alive`); this module makes it also
//! survive a restart by writing every `+P` channel — its creation TS, modes (with
//! parameters), topic and list modes — to a database file and recreating them at
//! startup, before any server link is established. The file is refreshed whenever
//! a mode/topic change touches a permanent channel (and on the timer as a backstop),
//! with an atomic temp-file+rename write so a crash mid-write can't corrupt it.
//!
//! Config: `permchannels_database` (path; default `<conf>.permchannels`).

use crate::channels::{Ban, Channel, Topic};
use crate::module::Module;
use crate::server::Server;
use crate::Uid;

/// The database path: the `permchannels_database` conf key, or `<conf>.permchannels`.
fn db_path(s: &Server) -> String {
    match s.conf("permchannels_database") {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => format!("{}.permchannels", s.conf_path),
    }
}

/// Serialise every permanent channel. Empty string when there are none, so the
/// caller can drop a stale database instead of leaving resurrectable channels.
/// Channels are emitted name-sorted so an unchanged network yields identical bytes
/// (the dirty check below then skips the write).
/// The per-channel body — modes, topic and list entries — everything but the `C`
/// header. Shared by the flat-file blob and the normalized `detail` column. List modes
/// skip timed (TBAN) entries: those are ephemeral and shouldn't be resurrected.
fn serialize_detail(c: &Channel) -> String {
    let mut out = format!("M {}\n", c.modes.render(true));
    if let Some(t) = &c.topic {
        if !t.text.is_empty() {
            out.push_str(&format!("T {} {} :{}\n", t.ts, t.setter, t.text));
        }
    }
    for (tag, list) in [
        ('b', &c.bans),
        ('e', &c.excepts),
        ('I', &c.invex),
        ('g', &c.filters),
        ('X', &c.exemptchanops),
        ('w', &c.autoop),
    ] {
        for b in list.iter().filter(|b| b.expires.is_none()) {
            out.push_str(&format!("{tag} {} {} {}\n", b.ts, b.setter, b.mask));
        }
    }
    out
}

/// Serialise every permanent channel to the flat blob. Empty string when there are
/// none, so the caller can drop a stale database. Channels are emitted name-sorted so
/// an unchanged network yields identical bytes (the dirty check then skips the write).
fn serialize(s: &Server) -> String {
    let mut chans: Vec<&Channel> = s.channels.values().filter(|c| c.modes.permanent).collect();
    if chans.is_empty() {
        return String::new();
    }
    chans.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = String::from(
        "# echoircd permanent channels — auto-generated; manual edits are overwritten\n",
    );
    for c in chans {
        out.push_str(&format!("C {} {}\n", c.name, c.created));
        out.push_str(&serialize_detail(c));
    }
    out
}

/// Schema for the normalized permanent-channel store (used when `store_backend =
/// pgsql`): one row per channel — `name`/`created` as queryable columns, with the
/// heterogeneous mode/topic/list body kept in a compact `detail` text column (the mode
/// set is open-ended, so decomposing it into rigid columns would be brittle).
const PERMCHANNELS_DDL: &str = "CREATE TABLE IF NOT EXISTS echoircd_permchannels \
     (name text NOT NULL, created bigint NOT NULL, detail text NOT NULL)";

/// One `(name, created, detail)` row per permanent channel, name-sorted for stable
/// snapshots.
fn normalized_rows(s: &Server) -> Vec<Vec<Option<Vec<u8>>>> {
    let mut chans: Vec<&Channel> = s.channels.values().filter(|c| c.modes.permanent).collect();
    chans.sort_by(|a, b| a.name.cmp(&b.name));
    chans
        .iter()
        .map(|c| {
            vec![
                Some(c.name.clone().into_bytes()),
                Some((c.created as i64).to_string().into_bytes()),
                Some(serialize_detail(c).into_bytes()),
            ]
        })
        .collect()
}

/// Atomically snapshot the permanent channels into the normalized table.
fn save_normalized(s: &Server) {
    crate::database::store_rows_replace(
        s,
        "echoircd_permchannels",
        "INSERT INTO echoircd_permchannels (name, created, detail) VALUES ($1, $2, $3)",
        normalized_rows(s),
    );
}

/// One channel record accumulated while parsing the database.
#[derive(Default)]
struct Record {
    name: String,
    created: u64,
    modes: String,
    topic: Option<Topic>,
    lists: Vec<(char, Ban)>,
}

/// Apply a rendered mode string (`+ntPl 50`) to an existing channel as the server,
/// bypassing the oper/rank gates and without propagating (there are no links yet
/// at load time). Mirrors the applier the MODE path uses, minus the side effects.
fn apply_modes(s: &mut Server, name: &str, key: &str, modes: &str) {
    let mut it = modes.split_whitespace();
    let Some(letters) = it.next() else {
        return;
    };
    let args: Vec<&str> = it.collect();
    s.mode_sudo = true;
    // Isolate a panicking mode handler: otherwise it would leave `mode_sudo` stuck
    // on, silently disabling rank/oper gating for every subsequent MODE.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut ai = 0usize;
        let mut adding = true;
        for c in letters.chars() {
            match c {
                '+' => {
                    adding = true;
                    continue;
                }
                '-' => {
                    adding = false;
                    continue;
                }
                _ => {}
            }
            let Some(h) = crate::mode::chan_mode(c) else {
                continue;
            };
            let param = if h.wants_param(adding) {
                let p = args.get(ai).copied();
                if p.is_some() {
                    ai += 1;
                }
                p
            } else {
                None
            };
            let _ = h.apply(s, name, key, 0, adding, param);
        }
    }));
    s.mode_sudo = false;
    if outcome.is_err() {
        eprintln!(
            "[permchannels] a mode handler panicked applying {name}; skipped its remaining modes"
        );
    }
}

/// Recreate one parsed record as a live (member-less) channel.
fn build(s: &mut Server, rec: Record) {
    if rec.name.is_empty() {
        return;
    }
    let key = rec.name.to_ascii_lowercase();
    if s.channels.contains_key(&key) {
        return; // never clobber a channel that already exists
    }
    let mut c = Channel::new(&rec.name);
    c.created = rec.created;
    c.topic = rec.topic;
    for (tag, ban) in rec.lists {
        match tag {
            'b' => c.bans.push(ban),
            'e' => c.excepts.push(ban),
            'I' => c.invex.push(ban),
            'g' => c.filters.push(ban),
            'X' => c.exemptchanops.push(ban),
            'w' => c.autoop.push(ban),
            _ => {}
        }
    }
    // Defensive: collapse any duplicate mask a dirty record could carry, so a
    // permanent channel never reloads with a doubled ban / except / … list.
    let dedup = |list: &mut Vec<Ban>| {
        let mut seen = std::collections::HashSet::new();
        list.retain(|b| seen.insert(b.mask.clone()));
    };
    dedup(&mut c.bans);
    dedup(&mut c.excepts);
    dedup(&mut c.invex);
    dedup(&mut c.filters);
    dedup(&mut c.exemptchanops);
    dedup(&mut c.autoop);
    s.channels.insert(key.clone(), c);
    apply_modes(s, &rec.name, &key, &rec.modes);
    // guarantee permanence even if the stored mode string somehow lost the 'P'
    if let Some(c) = s.channels.get_mut(&key) {
        c.modes.permanent = true;
    }
}

/// Fold one detail line (`M`/`T`/`b`/`e`/`I`/`g`/`X`/`w`) into the record being built.
/// Shared by the flat-file parser and the per-channel `detail` column.
fn accumulate(rec: &mut Record, tag: &str, rest: &str) {
    match tag {
        "M" => rec.modes = rest.to_string(),
        "T" => {
            // "<ts> <setter> :<text>"
            let mut it = rest.splitn(3, ' ');
            if let (Some(ts), Some(setter), Some(text)) = (it.next(), it.next(), it.next()) {
                if let Ok(ts) = ts.parse() {
                    rec.topic = Some(Topic {
                        text: text.strip_prefix(':').unwrap_or(text).to_string(),
                        setter: setter.to_string(),
                        ts,
                    });
                }
            }
        }
        "b" | "e" | "I" | "g" | "X" | "w" => {
            // "<ts> <setter> <mask>"
            let mut it = rest.splitn(3, ' ');
            if let (Some(ts), Some(setter), Some(mask)) = (it.next(), it.next(), it.next()) {
                if let Ok(ts) = ts.parse() {
                    rec.lists.push((
                        tag.chars().next().unwrap(),
                        Ban {
                            mask: mask.to_string(),
                            setter: setter.to_string(),
                            ts,
                            expires: None,
                        },
                    ));
                }
            }
        }
        _ => {}
    }
}

/// Restore permanent channels at startup, before links come up (so the TS we assign
/// can't desync a peer). Prefers the normalized table; if it's empty (first boot after
/// enabling pgsql) it migrates the legacy blob/file in and seeds the table; on any DB
/// error it falls back to the legacy text.
pub fn load(s: &mut Server) {
    if crate::database::stores_in_db(s) {
        if let Some(rows) = crate::database::store_rows_load(
            s,
            PERMCHANNELS_DDL,
            "SELECT name, created, detail FROM echoircd_permchannels",
        ) {
            if rows.is_empty() {
                load_text(s); // migrate the legacy blob/file …
                save_normalized(s); // … and seed the table
            } else {
                let mut count = 0usize;
                for r in &rows {
                    let name = r.first().and_then(|v| v.as_deref()).unwrap_or("");
                    if name.is_empty() {
                        continue;
                    }
                    let created = r
                        .get(1)
                        .and_then(|v| v.as_deref())
                        .and_then(|v| v.parse().ok())
                        .unwrap_or_else(crate::server::now);
                    let mut rec = Record {
                        name: name.to_string(),
                        created,
                        ..Record::default()
                    };
                    if let Some(Some(detail)) = r.get(2) {
                        for line in detail.lines() {
                            if let Some((tag, rest)) = line.split_once(' ') {
                                accumulate(&mut rec, tag, rest);
                            }
                        }
                    }
                    build(s, rec);
                    count += 1;
                }
                if count > 0 {
                    eprintln!("[permchannels] restored {count} permanent channel(s)");
                }
            }
            return;
        }
        // the database was unreachable — fall through to the legacy text
    }
    load_text(s);
}

/// Parse permanent channels from the legacy blob (the central store when pgsql, else
/// the flat file) into live channels.
fn load_text(s: &mut Server) {
    let Some(text) = crate::database::persist_load(s, "permchannels", &db_path(s)) else {
        return;
    };
    let mut cur: Option<Record> = None;
    let mut count = 0usize;
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((tag, rest)) = line.split_once(' ') else {
            continue;
        };
        if tag == "C" {
            if let Some(rec) = cur.take() {
                build(s, rec);
                count += 1;
            }
            let mut it = rest.split_whitespace();
            let name = it.next().unwrap_or_default().to_string();
            let created = it
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(crate::server::now);
            cur = Some(Record {
                name,
                created,
                ..Record::default()
            });
        } else if let Some(rec) = cur.as_mut() {
            accumulate(rec, tag, rest);
        }
    }
    if let Some(rec) = cur.take() {
        build(s, rec);
        count += 1;
    }
    if count > 0 {
        eprintln!("[permchannels] restored {count} permanent channel(s)");
    }
}

/// Timer/command-driven persister. Holds the last bytes written so an unchanged
/// network never rewrites the file.
#[derive(Default)]
pub struct PermChannels {
    last: String,
}

impl PermChannels {
    /// Re-serialise and, if anything changed, write the database (or remove it when
    /// the last permanent channel is gone).
    fn flush(&mut self, s: &Server) {
        // `serialize` doubles as the change-detector for both backends: identical bytes
        // ⇒ nothing changed ⇒ skip the write.
        let cur = serialize(s);
        if cur == self.last {
            return;
        }
        if crate::database::stores_in_db(s) {
            save_normalized(s); // one row per channel, atomically snapshot-replaced
        } else {
            crate::database::persist_save(s, "permchannels", &db_path(s), cur.clone());
        }
        self.last = cur;
    }
}

impl Module for PermChannels {
    fn name(&self) -> &'static str {
        "permchannels"
    }
    fn description(&self) -> &'static str {
        "Persists +P permanent channels (modes, topic, bans) across restarts"
    }

    fn on_post_command(&mut self, srv: &mut Server, _uid: Uid, cmd: &str) {
        // Persist promptly when a command could have changed a permanent channel's
        // stored state (its modes, incl. +P/-P itself, or its topic).
        if cmd.eq_ignore_ascii_case("MODE")
            || cmd.eq_ignore_ascii_case("SAMODE")
            || cmd.eq_ignore_ascii_case("TOPIC")
        {
            self.flush(srv);
        }
    }

    fn on_tick(&mut self, srv: &mut Server) {
        self.flush(srv); // backstop for changes that arrived off the command path (e.g. S2S)
    }
}
