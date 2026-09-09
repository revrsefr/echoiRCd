//! metadata — IRCv3 draft/metadata-2. Client METADATA GET/LIST/SET/CLEAR on users
//! and channels, op-gated, with change notices in a `metadata` batch. The store
//! lives in `Server.ext`, cleaned up by the on_user_quit hook.

use crate::map::HashMap;

use crate::channels::RANK_HALFOP;
use crate::command::{CmdResult, Command};
use crate::module::Module;
use crate::numeric::{RPL_KEYNOTSET, RPL_KEYVALUE};
use crate::server::Server;
use crate::Uid;

/// target key (`u<uid>` or `#chan`) -> key -> value. Stored in `Server.ext`.
#[derive(Default)]
pub struct MetaStore(pub HashMap<String, HashMap<String, String>>);

/// Resolve a METADATA target (a nick or `#channel`) to its store key. User keys
/// are `u<uid>` (stable across nick changes); channels are the lowercased name.
fn meta_key(s: &Server, target: &str) -> Option<String> {
    if let Some(chan) = target.strip_prefix('#') {
        let k = format!("#{}", chan.to_ascii_lowercase());
        s.channels.contains_key(&k).then_some(k)
    } else {
        s.find_nick(target).map(|u| format!("u{u}"))
    }
}

/// Cleanup hook: drop a user's metadata when they disconnect.
pub struct Metadata;
impl Module for Metadata {
    fn name(&self) -> &'static str {
        "metadata"
    }
    fn on_user_quit(&mut self, s: &mut Server, uid: Uid, _reason: &str) {
        if let Some(st) = s.ext.get_mut::<MetaStore>() {
            st.0.remove(&format!("u{uid}"));
        }
    }
    fn on_tick(&mut self, s: &mut Server) {
        // Free channel metadata (`#name` keys) once the channel is gone — user
        // entries are pruned on quit, and +P channels stay in s.channels so keep
        // theirs. Without this, metadata on a channel that empties leaks forever
        // (and is re-persisted to disk).
        let orphans: Vec<String> = match s.ext.get::<MetaStore>() {
            Some(st) => {
                st.0.keys()
                    .filter(|k| k.starts_with('#') && !s.channels.contains_key(k.as_str()))
                    .cloned()
                    .collect()
            }
            None => return,
        };
        if orphans.is_empty() {
            return;
        }
        if let Some(st) = s.ext.get_mut::<MetaStore>() {
            for k in &orphans {
                st.0.remove(k);
            }
        }
        save(s);
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(MetadataCmd)]
}

/// METADATA — `METADATA <target> <GET|LIST|SET|CLEAR> [args]`. `<target>` is `*`
/// (self), a nick, or a `#channel`. Anyone may GET/LIST; only the user themselves
/// or a channel op/oper may SET/CLEAR. Values are public (`*` visibility); a change
/// is pushed to metadata-capable viewers (self for a user, members for a channel).
struct MetadataCmd;
impl Command for MetadataCmd {
    fn name(&self) -> &'static str {
        "METADATA"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let target = params[0].clone();
        let sub = params[1].to_ascii_uppercase();
        let me_key = format!("u{uid}");
        let key = if target == "*" {
            me_key.clone()
        } else {
            match meta_key(s, &target) {
                Some(k) => k,
                None => {
                    s.fail(
                        uid,
                        "METADATA",
                        "INVALID_TARGET",
                        &format!("{target} invalid target"),
                    );
                    return CmdResult::Fail;
                }
            }
        };
        let reqnick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_else(|| "*".to_string());
        let disp = if target == "*" {
            reqnick.clone()
        } else {
            target.clone()
        };
        let can_set = key == me_key
            || (key.starts_with('#') && s.rank(uid, &key) >= RANK_HALFOP)
            || s.is_oper(uid);

        match sub.as_str() {
            "GET" | "LIST" => {
                // collect (key, value) pairs, then send — no store borrow held across send
                let pairs: Vec<(String, Option<String>)> = {
                    let store = s.ext.get::<MetaStore>();
                    let keys: Vec<String> = if sub == "LIST" {
                        store
                            .and_then(|st| st.0.get(&key))
                            .map(|m| m.keys().cloned().collect())
                            .unwrap_or_default()
                    } else {
                        params[2..].to_vec()
                    };
                    keys.into_iter()
                        .map(|k| {
                            let v = store
                                .and_then(|st| st.0.get(&key))
                                .and_then(|m| m.get(&k))
                                .cloned();
                            (k, v)
                        })
                        .collect()
                };
                let bref = s.next_msgid().replace('-', "");
                s.send(uid, format!(":{} BATCH +{bref} metadata", s.name));
                for (k, v) in pairs {
                    let line = match v {
                        Some(v) => format!(
                            "@batch={bref} :{} {RPL_KEYVALUE} {reqnick} {disp} {k} * :{v}",
                            s.name
                        ),
                        None => format!(
                            "@batch={bref} :{} {RPL_KEYNOTSET} {reqnick} {disp} {k} :key not set",
                            s.name
                        ),
                    };
                    s.send(uid, line);
                }
                s.send(uid, format!(":{} BATCH -{bref}", s.name));
            }
            "SET" => {
                if !can_set {
                    s.fail(
                        uid,
                        "METADATA",
                        "KEY_NO_PERMISSION",
                        &format!("{disp} permission denied"),
                    );
                    return CmdResult::Fail;
                }
                let Some(mkey) = params.get(2).cloned() else {
                    s.fail(uid, "METADATA", "KEY_INVALID", "missing key");
                    return CmdResult::Fail;
                };
                let value = params.get(3).cloned(); // no value => delete the key
                let maxval = s.conf_num("metadata_maxvalue", 512usize);
                let maxkeys = s.conf_num("metadata_maxkeys", 32usize);
                {
                    let st = s.ext.get_or_insert_with::<MetaStore>(MetaStore::default);
                    match &value {
                        Some(v) => {
                            // bound value length and per-target key count so a client
                            // can't grow the store without limit
                            let cur = st.0.get(&key);
                            let overlong = v.len() > maxval;
                            let too_many = cur
                                .map(|m| m.len() >= maxkeys && !m.contains_key(&mkey))
                                .unwrap_or(false);
                            if overlong || too_many {
                                s.fail(
                                    uid,
                                    "METADATA",
                                    "KEY_INVALID",
                                    "value too long or too many keys",
                                );
                                return CmdResult::Fail;
                            }
                            st.0.entry(key.clone())
                                .or_default()
                                .insert(mkey.clone(), v.clone());
                        }
                        None => {
                            if let Some(m) = st.0.get_mut(&key) {
                                m.remove(&mkey);
                            }
                        }
                    }
                }
                if key.starts_with('#') {
                    save(s); // persist channel metadata
                }
                let setter = s.users.get(&uid).map(|u| u.prefix()).unwrap_or_default();
                let note = match &value {
                    Some(v) => format!(":{setter} METADATA {disp} {mkey} * :{v}"),
                    None => format!(":{setter} METADATA {disp} {mkey} *"),
                };
                let recips: Vec<Uid> = if key.starts_with('#') {
                    s.channels
                        .get(&key)
                        .map(|c| c.members.keys().copied().collect())
                        .unwrap_or_default()
                } else {
                    vec![uid]
                };
                for r in recips {
                    if s.users.get(&r).map(|u| u.caps.metadata).unwrap_or(false) {
                        s.send(r, note.clone());
                    }
                }
            }
            "CLEAR" => {
                if !can_set {
                    s.fail(
                        uid,
                        "METADATA",
                        "KEY_NO_PERMISSION",
                        &format!("{disp} permission denied"),
                    );
                    return CmdResult::Fail;
                }
                if let Some(st) = s.ext.get_mut::<MetaStore>() {
                    st.0.remove(&key);
                }
                if key.starts_with('#') {
                    save(s);
                }
            }
            "SUB" | "UNSUB" => {} // all metadata is public here; subscriptions are a no-op
            _ => {
                s.fail(uid, "METADATA", "INVALID_SUBCOMMAND", &sub);
                return CmdResult::Fail;
            }
        }
        CmdResult::Ok
    }
}

/// Apply a metadata key pushed onto a local user from services (or another server)
/// and echo the change to that user if they negotiated the metadata cap. Backs the
/// profile keys (avatar/bio/pronouns/timezone/url) that NickServ SET populates, so
/// they surface over draft/metadata-2 instead of being dropped on the link.
pub fn apply_user(
    s: &mut Server,
    uid: Uid,
    nick: &str,
    mkey: &str,
    value: Option<&str>,
    setter: &str,
) {
    let sk = format!("u{uid}");
    {
        let st = s.ext.get_or_insert_with::<MetaStore>(MetaStore::default);
        match value {
            Some(v) => {
                st.0.entry(sk)
                    .or_default()
                    .insert(mkey.to_string(), v.to_string());
            }
            None => {
                if let Some(m) = st.0.get_mut(&sk) {
                    m.remove(mkey);
                }
            }
        }
    }
    if s.users.get(&uid).map(|u| u.caps.metadata).unwrap_or(false) {
        let note = match value {
            Some(v) => format!(":{setter} METADATA {nick} {mkey} * :{v}"),
            None => format!(":{setter} METADATA {nick} {mkey} *"),
        };
        s.send(uid, note);
    }
}

/// Where channel metadata is persisted (beside the config).
fn db_path(s: &Server) -> String {
    format!("{}.metadata", s.conf_path)
}

/// Persist channel metadata (the `#`-keyed entries) so it survives a restart.
/// Per-user metadata (`u<uid>`) is intentionally not saved: uids don't persist
/// across restarts.
pub fn save(s: &Server) {
    let mut out = String::new();
    if let Some(st) = s.ext.get::<MetaStore>() {
        for (key, kv) in &st.0 {
            if !key.starts_with('#') {
                continue;
            }
            for (mk, v) in kv {
                out.push_str(&format!("{key} {mk} {v}\n"));
            }
        }
    }
    s.disk_write(db_path(s), out); // off-core: a slow disk mustn't stall the event loop
}

/// Reload persisted channel metadata at startup.
pub fn load(s: &mut Server) {
    let Ok(text) = std::fs::read_to_string(db_path(s)) else {
        return;
    };
    let store = s.ext.get_or_insert_with::<MetaStore>(MetaStore::default);
    for line in text.lines() {
        let mut it = line.splitn(3, ' ');
        if let (Some(key), Some(mk), Some(v)) = (it.next(), it.next(), it.next()) {
            store
                .0
                .entry(key.to_string())
                .or_default()
                .insert(mk.to_string(), v.to_string());
        }
    }
}
