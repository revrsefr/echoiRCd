//! chathistory — InspIRCd's `m_chathistory` family (draft/chathistory +
//! draft/message-redaction). Recent PRIVMSG/NOTICE traffic is kept in a capped
//! per-conversation ring (channels and DM pairs) so clients can replay it on
//! demand or on join (the channel `+H` backlog lives in `channels::replay_chanhistory`).
//! Self-contained: the ring lives in `Server.ext`; the message path records into it
//! via [`record`], and the CHATHISTORY and REDACT commands read/edit it here.

use std::collections::{HashMap, VecDeque};

use crate::channels::RANK_HALFOP;
use crate::command::{CmdResult, Command};
use crate::server::{iso_time, now, parse_iso, Server};
use crate::Uid;

/// Recent messages CHATHISTORY keeps per conversation.
pub const HISTORY_CAP: usize = 256;

/// One stored message, replayed by CHATHISTORY / the `+H` backlog.
pub struct HistMsg {
    pub ts: u64,
    pub msgid: String,
    pub prefix: String,     // sender's nick!user@host at send time
    pub verb: &'static str, // "PRIVMSG" or "NOTICE"
    pub target: String,     // original target (channel, or the DM recipient)
    pub text: String,
}

/// conversation key (`#chan` or a DM-pair key) -> capped ring. Stored in `Server.ext`.
#[derive(Default)]
pub struct History(pub HashMap<String, VecDeque<HistMsg>>);

/// Record a message for CHATHISTORY replay (capped ring per conversation). Called
/// from the core message path once per delivered PRIVMSG/NOTICE.
pub fn record(
    s: &mut Server,
    key: &str,
    prefix: &str,
    verb: &'static str,
    target: &str,
    text: &str,
    msgid: &str,
) {
    let buf = s
        .ext
        .get_or_insert_with::<History>(History::default)
        .0
        .entry(key.to_string())
        .or_default();
    buf.push_back(HistMsg {
        ts: now(),
        msgid: msgid.to_string(),
        prefix: prefix.to_string(),
        verb,
        target: target.to_string(),
        text: text.to_string(),
    });
    while buf.len() > HISTORY_CAP {
        buf.pop_front();
    }
}

/// Canonical CHATHISTORY key for a DM between two nicks (order-independent; the
/// `\0` prefix keeps it from ever colliding with a `#channel` key).
pub fn dm_key(a: &str, b: &str) -> String {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    if a <= b {
        format!("\0{a}\0{b}")
    } else {
        format!("\0{b}\0{a}")
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(ChatHistory), Box::new(Redact)]
}

/// CHATHISTORY — replay recent messages (draft/chathistory), leveraging BATCH.
/// `CHATHISTORY <LATEST|BEFORE|AFTER|AROUND|BETWEEN> <#chan|nick> <selector..>
/// <limit>`; a `<selector>` is `*`, `timestamp=<iso>` or `msgid=<id>`. Channel
/// history is members-only; a nick target replays that DM conversation. The reply
/// is a `chathistory` batch of the original lines with their server-time + msgid.
struct ChatHistory;
impl Command for ChatHistory {
    fn name(&self) -> &'static str {
        "CHATHISTORY"
    }
    fn min_params(&self) -> usize {
        4
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let sub = params[0].to_ascii_uppercase();
        // CHATHISTORY TARGETS <t1> <t2> <limit> — list conversations with activity
        // in the window, newest-in-window timestamp each. No target param.
        if sub == "TARGETS" {
            let bound = |i: usize, dflt: u64| {
                params
                    .get(i)
                    .and_then(|s| s.strip_prefix("timestamp="))
                    .and_then(parse_iso)
                    .unwrap_or(dflt)
            };
            let (a, b) = (bound(1, 0), bound(2, u64::MAX));
            let (lo, hi) = (a.min(b), a.max(b));
            let limit = params
                .get(3)
                .and_then(|l| l.parse::<usize>().ok())
                .unwrap_or(50)
                .clamp(1, HISTORY_CAP);
            let me = s
                .users
                .get(&uid)
                .map(|u| u.nick.to_ascii_lowercase())
                .unwrap_or_default();
            let mut targets: Vec<(String, u64)> = Vec::new();
            if let Some(hist) = s.ext.get::<History>() {
                for (key, buf) in &hist.0 {
                    let Some(ts) = buf
                        .iter()
                        .rev()
                        .find(|m| m.ts >= lo && m.ts <= hi)
                        .map(|m| m.ts)
                    else {
                        continue;
                    };
                    if key.starts_with('#') {
                        if s.is_member(uid, key) {
                            let name = buf
                                .back()
                                .map(|m| m.target.clone())
                                .unwrap_or_else(|| key.clone());
                            targets.push((name, ts));
                        }
                    } else if let Some(rest) = key.strip_prefix('\0') {
                        let p: Vec<&str> = rest.split('\0').collect();
                        if p.len() == 2 && (p[0] == me || p[1] == me) {
                            let other = if p[0] == me { p[1] } else { p[0] };
                            targets.push((other.to_string(), ts));
                        }
                    }
                }
            }
            targets.sort_by_key(|(_, ts)| *ts);
            let start = targets.len().saturating_sub(limit);
            let bref = s.next_msgid().replace('-', "");
            s.send(
                uid,
                format!(":{} BATCH +{bref} draft/chathistory-targets", s.name),
            );
            for (t, ts) in &targets[start..] {
                s.send(
                    uid,
                    format!(
                        "@batch={bref} :{} CHATHISTORY TARGETS {t} {}",
                        s.name,
                        iso_time(*ts)
                    ),
                );
            }
            s.send(uid, format!(":{} BATCH -{bref}", s.name));
            return CmdResult::Ok;
        }
        let target = params[1].clone();
        // channel target → channel key (members only); a nick → the DM pair key
        // (the requester is inherently part of it, so no membership check)
        let is_channel = target.starts_with('#');
        let key = if is_channel {
            target.to_ascii_lowercase()
        } else {
            let me = s
                .users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            dm_key(&me, &target)
        };
        // BETWEEN takes two selectors then the limit; the rest take one + the limit
        let (sel, sel2, limit_s) = if sub == "BETWEEN" {
            (
                params[2].as_str(),
                params.get(3).map(|s| s.as_str()).unwrap_or("*"),
                params.get(4),
            )
        } else {
            (params[2].as_str(), "", params.get(3))
        };
        let limit = limit_s
            .and_then(|l| l.parse::<usize>().ok())
            .unwrap_or(50)
            .clamp(1, HISTORY_CAP);

        let bref = s.next_msgid().replace('-', "");
        let mut lines: Vec<String> = Vec::new();
        if !is_channel || s.is_member(uid, &key) {
            if let Some(buf) = s.ext.get::<History>().and_then(|h| h.0.get(&key)) {
                // Resolve the selector to a reference position. `msgid=` matches an
                // exact buffer index (so same-second messages aren't lost);
                // `timestamp=` and `*` fall back to a ts bound.
                let ref_idx = sel
                    .strip_prefix("msgid=")
                    .and_then(|id| buf.iter().position(|m| m.msgid == id));
                let ref_ts = sel.strip_prefix("timestamp=").and_then(parse_iso);
                // resolve any selector to a buffer index (for AROUND / BETWEEN)
                let idx_of = |sl: &str| -> Option<usize> {
                    if let Some(id) = sl.strip_prefix("msgid=") {
                        buf.iter().position(|m| m.msgid == id)
                    } else if let Some(iso) = sl.strip_prefix("timestamp=") {
                        parse_iso(iso).and_then(|b| buf.iter().position(|m| m.ts >= b))
                    } else {
                        None
                    }
                };
                let picked: Vec<&HistMsg> = match sub.as_str() {
                    "BEFORE" => {
                        let end = ref_idx.unwrap_or_else(|| {
                            let b = ref_ts.unwrap_or(u64::MAX);
                            buf.iter().position(|m| m.ts >= b).unwrap_or(buf.len())
                        });
                        let start = end.saturating_sub(limit);
                        buf.iter().take(end).skip(start).collect()
                    }
                    "AFTER" => {
                        let begin = match ref_idx {
                            Some(i) => i + 1,
                            None => {
                                let b = ref_ts.unwrap_or(0);
                                buf.iter().position(|m| m.ts > b).unwrap_or(buf.len())
                            }
                        };
                        buf.iter().skip(begin).take(limit).collect()
                    }
                    "AROUND" => {
                        // messages centred on the selector: half before, half after
                        let i = idx_of(sel).unwrap_or(buf.len() / 2);
                        let start = i.saturating_sub(limit / 2);
                        buf.iter().skip(start).take(limit).collect()
                    }
                    "BETWEEN" => {
                        // messages strictly between the two selector points
                        let a = idx_of(sel).unwrap_or(0);
                        let b = idx_of(sel2).unwrap_or(buf.len());
                        let (lo, hi) = (a.min(b), a.max(b));
                        buf.iter()
                            .skip(lo + 1)
                            .take(hi.saturating_sub(lo + 1))
                            .take(limit)
                            .collect()
                    }
                    _ => {
                        // LATEST: newest `limit`, optionally bounded below by the selector
                        let begin = match (ref_idx, ref_ts) {
                            (Some(i), _) => i + 1,
                            (None, Some(b)) => {
                                buf.iter().position(|m| m.ts > b).unwrap_or(buf.len())
                            }
                            _ => 0,
                        };
                        let n = buf.len() - begin;
                        let start = begin + n.saturating_sub(limit);
                        buf.iter().skip(start).collect()
                    }
                };
                for m in picked {
                    lines.push(format!(
                        "@time={};msgid={};batch={bref} :{} {} {} :{}",
                        iso_time(m.ts),
                        m.msgid,
                        m.prefix,
                        m.verb,
                        m.target,
                        m.text
                    ));
                }
            }
        }
        s.send(
            uid,
            format!(":{} BATCH +{bref} chathistory {target}", s.name),
        );
        for l in lines {
            s.send(uid, l);
        }
        s.send(uid, format!(":{} BATCH -{bref}", s.name));
        CmdResult::Ok
    }
}

/// REDACT — delete a previously-sent channel message (draft/message-redaction).
/// `REDACT <#chan> <msgid> [:reason]`. Allowed for the message's author, a channel
/// half-op-or-above, or an oper. Relayed to channel members who enabled the cap,
/// and the message is dropped from CHATHISTORY.
struct Redact;
impl Command for Redact {
    fn name(&self) -> &'static str {
        "REDACT"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let target = &params[0];
        let msgid = &params[1];
        let reason = params.get(2).cloned().unwrap_or_default();
        if !target.starts_with('#') {
            s.fail(
                uid,
                "REDACT",
                "INVALID_TARGET",
                "REDACT only supports channels",
            );
            return CmdResult::Fail;
        }
        let key = target.to_ascii_lowercase();
        let Some(author) = s
            .ext
            .get::<History>()
            .and_then(|h| h.0.get(&key))
            .and_then(|buf| {
                buf.iter().find(|m| m.msgid == *msgid).map(|m| {
                    m.prefix
                        .split('!')
                        .next()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                })
            })
        else {
            s.fail(
                uid,
                "REDACT",
                "UNKNOWN_MSGID",
                &format!("No such message id {msgid}"),
            );
            return CmdResult::Fail;
        };
        let my_nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.to_ascii_lowercase())
            .unwrap_or_default();
        if my_nick != author && s.rank(uid, &key) < RANK_HALFOP && !s.is_oper(uid) {
            s.fail(
                uid,
                "REDACT",
                "REDACT_FORBIDDEN",
                "You may only redact your own messages",
            );
            return CmdResult::Fail;
        }
        if let Some(buf) = s.ext.get_mut::<History>().and_then(|h| h.0.get_mut(&key)) {
            buf.retain(|m| m.msgid != *msgid);
        }
        let prefix = s.users.get(&uid).map(|u| u.prefix()).unwrap_or_default();
        let line = if reason.is_empty() {
            format!(":{prefix} REDACT {target} {msgid}")
        } else {
            format!(":{prefix} REDACT {target} {msgid} :{reason}")
        };
        let members: Vec<Uid> = s
            .channels
            .get(&key)
            .map(|c| c.members.keys().copied().collect())
            .unwrap_or_default();
        for m in members {
            if s.users
                .get(&m)
                .map(|u| u.caps.message_redaction)
                .unwrap_or(false)
            {
                s.send(m, line.clone());
            }
        }
        CmdResult::Ok
    }
}
