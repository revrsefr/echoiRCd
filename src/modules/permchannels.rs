//! Permanent-channel persistence. A `+P` channel already survives an empty
//! member list in memory (see `Channel::keep_alive`); this module makes it also
//! survive a restart by writing every `+P` channel — its creation TS, modes (with
//! parameters), topic and list modes — to a database file and recreating them at
//! startup, before any server link is established. The file is refreshed whenever
//! a mode/topic change touches a permanent channel (and on the timer as a backstop),
//! with an atomic temp-file+rename write so a crash mid-write can't corrupt it.
//!
//! Config: `permchannels_database` (path; default `<conf>.permchannels`).

use std::fs;
use std::io;

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
fn serialize(s: &Server) -> String {
    let mut chans: Vec<&Channel> = s.channels.values().filter(|c| c.modes.permanent).collect();
    if chans.is_empty() {
        return String::new();
    }
    chans.sort_by(|a, b| a.name.cmp(&b.name));

    let mut out = String::from("# echoircd permanent channels — auto-generated; manual edits are overwritten\n");
    for c in chans {
        out.push_str(&format!("C {} {}\n", c.name, c.created));
        out.push_str(&format!("M {}\n", c.modes.render(true)));
        if let Some(t) = &c.topic {
            if !t.text.is_empty() {
                out.push_str(&format!("T {} {} :{}\n", t.ts, t.setter, t.text));
            }
        }
        // list modes: mask/setter/ts, skipping timed (TBAN) entries — those are
        // ephemeral and shouldn't be resurrected as permanent bans.
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
    }
    out
}

/// Atomic write: a full temp file then rename over the target, so a reader (or a
/// crash) never sees a half-written database.
fn atomic_write(path: &str, content: &str) -> io::Result<()> {
    let tmp = format!("{path}.tmp");
    fs::write(&tmp, content)?;
    fs::rename(&tmp, path)
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
    let mut ai = 0usize;
    let mut adding = true;
    s.mode_sudo = true;
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
    s.mode_sudo = false;
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
    s.channels.insert(key.clone(), c);
    apply_modes(s, &rec.name, &key, &rec.modes);
    // guarantee permanence even if the stored mode string somehow lost the 'P'
    if let Some(c) = s.channels.get_mut(&key) {
        c.modes.permanent = true;
    }
}

/// Restore permanent channels from disk. Called once at startup, before links come
/// up (so the TS we assign can't desync a peer, matching how the DB is written).
pub fn load(s: &mut Server) {
    let Ok(text) = fs::read_to_string(db_path(s)) else {
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
        match tag {
            "C" => {
                if let Some(rec) = cur.take() {
                    build(s, rec);
                    count += 1;
                }
                let mut it = rest.split_whitespace();
                let name = it.next().unwrap_or_default().to_string();
                let created = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(crate::server::now);
                cur = Some(Record {
                    name,
                    created,
                    ..Record::default()
                });
            }
            "M" => {
                if let Some(rec) = cur.as_mut() {
                    rec.modes = rest.to_string();
                }
            }
            "T" => {
                if let Some(rec) = cur.as_mut() {
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
            }
            "b" | "e" | "I" | "g" | "X" | "w" => {
                if let Some(rec) = cur.as_mut() {
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
            }
            _ => {}
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
        let cur = serialize(s);
        if cur == self.last {
            return;
        }
        let path = db_path(s);
        if cur.is_empty() {
            let _ = fs::remove_file(&path);
        } else if let Err(e) = atomic_write(&path, &cur) {
            eprintln!("[permchannels] cannot write {path}: {e}");
            return; // leave `last` stale so the next tick retries
        }
        self.last = cur;
    }
}

impl Module for PermChannels {
    fn name(&self) -> &'static str {
        "permchannels"
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
