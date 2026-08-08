//! core_message — PRIVMSG and NOTICE (channel + user targets).

use crate::channels::{glob_match, RANK_HALFOP, RANK_VOICE};
use crate::command::{CmdResult, Command};
use crate::numeric::*;
use crate::server::{iso_time, parse_iso, HistMsg, Server, HISTORY_CAP};
use crate::Uid;

/// mIRC/IRC formatting control bytes (bold, colour, hex-colour, reset, …).
const FMT: [char; 9] = [
    '\u{02}', '\u{03}', '\u{04}', '\u{0F}', '\u{11}', '\u{16}', '\u{1D}', '\u{1E}', '\u{1F}',
];

fn is_ctcp(t: &str) -> bool {
    t.starts_with('\u{01}')
}
fn is_action(t: &str) -> bool {
    t.starts_with("\u{01}ACTION")
}
fn has_formatting(t: &str) -> bool {
    t.chars().any(|c| FMT.contains(&c))
}
/// Strip formatting/colour codes (drops \x03 colour specs and \x04 hex specs).
fn strip_formatting(t: &str) -> String {
    let cs: Vec<char> = t.chars().collect();
    let mut out = String::with_capacity(cs.len());
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            '\u{02}' | '\u{0F}' | '\u{11}' | '\u{16}' | '\u{1D}' | '\u{1E}' | '\u{1F}' => i += 1,
            '\u{03}' => {
                i += 1;
                let mut n = 0;
                while n < 2 && i < cs.len() && cs[i].is_ascii_digit() {
                    i += 1;
                    n += 1;
                }
                if n > 0 && i + 1 < cs.len() && cs[i] == ',' && cs[i + 1].is_ascii_digit() {
                    i += 1;
                    let mut m = 0;
                    while m < 2 && i < cs.len() && cs[i].is_ascii_digit() {
                        i += 1;
                        m += 1;
                    }
                }
            }
            '\u{04}' => {
                i += 1;
                let mut n = 0;
                while n < 6 && i < cs.len() && cs[i].is_ascii_hexdigit() {
                    i += 1;
                    n += 1;
                }
                if n == 6 && i + 1 < cs.len() && cs[i] == ',' && cs[i + 1].is_ascii_hexdigit() {
                    i += 1;
                    let mut m = 0;
                    while m < 6 && i < cs.len() && cs[i].is_ascii_hexdigit() {
                        i += 1;
                        m += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Case-insensitive substring test over chars (Unicode-safe, no byte slicing).
fn ci_contains(hay: &str, find: &str) -> bool {
    let h: Vec<char> = hay.chars().collect();
    let f: Vec<char> = find.chars().collect();
    if f.is_empty() || f.len() > h.len() {
        return false;
    }
    (0..=h.len() - f.len()).any(|i| (0..f.len()).all(|k| h[i + k].eq_ignore_ascii_case(&f[k])))
}

/// Case-insensitive replace-all over chars (Unicode-safe, no byte slicing).
fn ci_replace(hay: &str, find: &str, rep: &str) -> String {
    let h: Vec<char> = hay.chars().collect();
    let f: Vec<char> = find.chars().collect();
    if f.is_empty() {
        return hay.to_string();
    }
    let mut out = String::with_capacity(hay.len());
    let mut i = 0;
    while i < h.len() {
        let hit =
            i + f.len() <= h.len() && (0..f.len()).all(|k| h[i + k].eq_ignore_ascii_case(&f[k]));
        if hit {
            out.push_str(rep);
            i += f.len();
        } else {
            out.push(h[i]);
            i += 1;
        }
    }
    out
}

/// +G censor: replace each configured bad word in `body`. Returns `None` when a
/// matched word has an empty replacement (⇒ the message must be blocked).
fn apply_censor(body: &str, censor: &[(String, String)]) -> Option<String> {
    let mut out = body.to_string();
    for (find, replace) in censor {
        if find.is_empty() || !ci_contains(&out, find) {
            continue;
        }
        if replace.is_empty() {
            return None; // no replacement ⇒ block
        }
        out = ci_replace(&out, find, replace);
    }
    Some(out)
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(PrivMsg),
        Box::new(Notice),
        Box::new(TagMsg),
        Box::new(ChatHistory),
        Box::new(Redact),
    ]
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
        let Some(author) = s.history.get(&key).and_then(|buf| {
            buf.iter().find(|m| m.msgid == *msgid).map(|m| {
                m.prefix
                    .split('!')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
            })
        }) else {
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
        if let Some(buf) = s.history.get_mut(&key) {
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

/// Canonical CHATHISTORY key for a DM between two nicks (order-independent; the
/// `\0` prefix keeps it from ever colliding with a `#channel` key).
fn dm_key(a: &str, b: &str) -> String {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    if a <= b {
        format!("\0{a}\0{b}")
    } else {
        format!("\0{b}\0{a}")
    }
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
            for (key, buf) in &s.history {
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
            if let Some(buf) = s.history.get(&key) {
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

/// Shared PRIVMSG/NOTICE delivery. NOTICE never generates automatic replies.
fn deliver(s: &mut Server, uid: Uid, params: &[String], notice: bool) -> CmdResult {
    let cmd = if notice { "NOTICE" } else { "PRIVMSG" };
    if params.is_empty() {
        if !notice {
            s.numeric(
                uid,
                ERR_NORECIPIENT,
                &format!(":No recipient given ({cmd})"),
            );
        }
        return CmdResult::Fail;
    }
    if params.len() < 2 || params[1].is_empty() {
        if !notice {
            s.numeric(uid, ERR_NOTEXTTOSEND, ":No text to send");
        }
        return CmdResult::Fail;
    }
    let (target, text) = (&params[0], &params[1]);
    let Some(prefix) = s.users.get(&uid).map(|u| u.prefix()) else {
        return CmdResult::Fail;
    };
    if target.starts_with('#') {
        let key = target.to_ascii_lowercase();
        let member = s
            .channels
            .get(&key)
            .map(|c| c.members.contains_key(&uid))
            .unwrap_or(false);
        if !member {
            if !notice {
                s.numeric(
                    uid,
                    ERR_CANNOTSENDTOCHAN,
                    &format!("{target} :Cannot send to channel"),
                );
            }
            return CmdResult::Fail;
        }
        // +m: only voiced-or-above may speak
        let moderated = s
            .channels
            .get(&key)
            .map(|c| c.modes.moderated)
            .unwrap_or(false);
        if moderated && s.rank(uid, &key) < RANK_VOICE {
            if !notice {
                s.numeric(
                    uid,
                    ERR_CANNOTSENDTOCHAN,
                    &format!("{target} :Cannot send to channel (+m)"),
                );
            }
            return CmdResult::Fail;
        }
        // +M: only logged-in (account) users may speak (voiced-or-above exempt)
        let reg_moderated = s
            .channels
            .get(&key)
            .map(|c| c.modes.reg_moderated)
            .unwrap_or(false);
        if reg_moderated && s.rank(uid, &key) < RANK_VOICE && !s.is_logged_in(uid) {
            if !notice {
                s.numeric(
                    uid,
                    ERR_NEEDREGGEDNICK,
                    &format!("{target} :You must be logged into an account to speak here (+M)"),
                );
            }
            return CmdResult::Fail;
        }
        // extban `m:` mute — matched users can't speak unless voiced-or-above
        if s.extban_active(uid, &key, 'm') && s.rank(uid, &key) < RANK_VOICE {
            if !notice {
                s.numeric(
                    uid,
                    ERR_CANNOTSENDTOCHAN,
                    &format!("{target} :Cannot send to channel (you're muted, +b m:)"),
                );
            }
            return CmdResult::Fail;
        }
        // +f message flood — ops/half-ops and opers are exempt; others get kicked
        let flood_exempt = s.rank(uid, &key) >= RANK_HALFOP
            || s.users.get(&uid).map(|u| u.flags.oper).unwrap_or(false);
        if !flood_exempt {
            if let Some(ban) = s.messageflood_hit(uid, &key) {
                s.flood_kick(uid, &key, ban);
                return CmdResult::Fail;
            }
        }
        // content-based modes: +C no CTCP, +T no notices, +c no colour, +S strip
        let (no_ctcp, no_notice, no_color, strip) = s
            .channels
            .get(&key)
            .map(|c| {
                (
                    c.modes.no_ctcp,
                    c.modes.no_notice,
                    c.modes.no_color,
                    c.modes.strip_color,
                )
            })
            .unwrap_or_default();
        if notice && no_notice {
            return CmdResult::Fail; // +T — NOTICEs are silently dropped
        }
        if no_ctcp && is_ctcp(text) && !is_action(text) {
            if !notice {
                s.numeric(
                    uid,
                    ERR_CANNOTSENDTOCHAN,
                    &format!("{target} :CTCP is disabled (+C)"),
                );
            }
            return CmdResult::Fail;
        }
        if no_color && has_formatting(text) {
            if !notice {
                s.numeric(
                    uid,
                    ERR_CANNOTSENDTOCHAN,
                    &format!("{target} :Formatting/colour is disabled (+c)"),
                );
            }
            return CmdResult::Fail;
        }
        // extban `c:` no-colour — matched users can't send formatting
        if s.extban_active(uid, &key, 'c') && has_formatting(text) {
            if !notice {
                s.numeric(
                    uid,
                    ERR_CANNOTSENDTOCHAN,
                    &format!("{target} :Formatting/colour is disabled for you (+b c:)"),
                );
            }
            return CmdResult::Fail;
        }
        // +g channel filter — block messages matching any word/glob (use *word*)
        let filtered = s
            .channels
            .get(&key)
            .map(|c| c.filters.iter().any(|f| glob_match(&f.mask, text)))
            .unwrap_or(false);
        if filtered {
            if !notice {
                s.numeric(
                    uid,
                    ERR_CANNOTSENDTOCHAN,
                    &format!("{target} :Cannot send to channel (blocked by +g filter)"),
                );
            }
            return CmdResult::Fail;
        }
        let mut body = if strip {
            strip_formatting(text)
        } else {
            text.clone()
        };
        // +G censor — replace configured bad words (empty replacement ⇒ block)
        let censor_on = s
            .channels
            .get(&key)
            .map(|c| c.modes.censor)
            .unwrap_or(false);
        if censor_on && !s.censor.is_empty() {
            match apply_censor(&body, &s.censor) {
                Some(b) => body = b,
                None => {
                    if !notice {
                        s.numeric(
                            uid,
                            ERR_CANNOTSENDTOCHAN,
                            &format!("{target} :Cannot send to channel (+G censor)"),
                        );
                    }
                    return CmdResult::Fail;
                }
            }
        }
        // deliver to every member except the sender and +D (deaf) users, tagging
        // per-recipient (server-time + any client-only tags on the line)
        let line = format!(":{prefix} {cmd} {target} :{body}");
        let ctags = s.line_ctags.clone();
        let msgid = s.next_msgid(); // one id shared by every recipient of this message
        s.store_history(&key, &prefix, cmd, target, &body, &msgid); // for CHATHISTORY
        let members: Vec<Uid> = s
            .channels
            .get(&key)
            .map(|c| c.members.keys().copied().collect())
            .unwrap_or_default();
        for m in members {
            if m == uid || s.users.get(&m).map(|u| u.flags.deaf).unwrap_or(false) {
                continue;
            }
            s.send_tagged(m, uid, &ctags, &msgid, &line);
        }
        // echo-message: give the sender their own copy if they asked for one
        if s.users
            .get(&uid)
            .map(|u| u.caps.echo_message)
            .unwrap_or(false)
        {
            s.send_tagged(uid, uid, &ctags, &msgid, &line);
        }
        // propagate to linked servers that have members in this channel
        s.send_channel_to_links(uid, &key, target, cmd, &body);
    } else if let Some(tuid) = s.find_nick(target) {
        // user +R (regdeaf): drop messages from users not logged into an account
        if s.users
            .get(&tuid)
            .map(|u| u.flags.reg_only_pm)
            .unwrap_or(false)
            && !s.is_logged_in(uid)
        {
            if !notice {
                let tn = s
                    .users
                    .get(&tuid)
                    .map(|u| u.nick.clone())
                    .unwrap_or_default();
                s.numeric(
                    uid,
                    ERR_NEEDREGGEDNICK,
                    &format!("{tn} :You must be logged into an account to message this user (+R)"),
                );
            }
            return CmdResult::Fail;
        }
        // user +z (sslqueries): only TLS users may PM them
        if s.users.get(&tuid).map(|u| u.flags.ssl_pm).unwrap_or(false)
            && !s.users.get(&uid).map(|u| u.secure).unwrap_or(false)
        {
            if !notice {
                let (tn, sn) = (
                    s.users
                        .get(&tuid)
                        .map(|u| u.nick.clone())
                        .unwrap_or_default(),
                    s.users
                        .get(&uid)
                        .map(|u| u.nick.clone())
                        .unwrap_or_default(),
                );
                s.send(
                    uid,
                    format!(
                        ":{} NOTICE {sn} :Cannot message {tn}: a TLS connection is required (+z)",
                        s.name
                    ),
                );
            }
            return CmdResult::Fail;
        }
        // +g callerid: a +g user only accepts PMs from users on their ACCEPT list.
        // Others are blocked; the target is told someone tried (718), and a PRIVMSG
        // sender is told the target is in +g and has been informed (716 + 717).
        let sender_nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        let target_g = s
            .users
            .get(&tuid)
            .map(|u| u.flags.callerid)
            .unwrap_or(false);
        if target_g && uid != tuid && !s.is_accepted(tuid, &sender_nick) {
            let (tnick, sident, shost) = {
                let t = s.users.get(&tuid);
                let u = s.users.get(&uid);
                (
                    t.map(|x| x.nick.clone()).unwrap_or_default(),
                    u.map(|x| x.ident.clone()).unwrap_or_default(),
                    u.map(|x| x.host_display().to_string()).unwrap_or_default(),
                )
            };
            s.numeric(
                tuid,
                RPL_UMODEGMSG,
                &format!(
                    "{sender_nick} {sident}@{shost} :is messaging you, and you have umode +g."
                ),
            );
            if !notice {
                s.numeric(
                    uid,
                    RPL_TARGUMODEG,
                    &format!("{tnick} :is in +g mode (server-side ignore)."),
                );
                s.numeric(
                    uid,
                    RPL_TARGNOTIFY,
                    &format!("{tnick} :has been informed that you messaged them."),
                );
            }
            return CmdResult::Ok;
        }
        // SILENCE: if the recipient silenced the sender, drop it silently — the
        // sender is never told (that's the point), but still gets their own echo.
        let silenced = s.is_silenced(tuid, &prefix);
        let pm = format!(":{prefix} {cmd} {target} :{text}");
        let ctags = s.line_ctags.clone();
        let msgid = s.next_msgid();
        if !silenced {
            s.send_tagged(tuid, uid, &ctags, &msgid, &pm);
            // store for CHATHISTORY under the canonical pair key (both parties share it)
            let sender_nick = prefix.split('!').next().unwrap_or_default();
            s.store_history(
                &dm_key(sender_nick, target),
                &prefix,
                cmd,
                target,
                text,
                &msgid,
            );
        }
        if s.users
            .get(&uid)
            .map(|u| u.caps.echo_message)
            .unwrap_or(false)
        {
            s.send_tagged(uid, uid, &ctags, &msgid, &pm);
        }
        // if the recipient is away, tell the sender (PRIVMSG only, not if silenced)
        if !notice && !silenced {
            if let Some(msg) = s.users.get(&tuid).and_then(|u| u.flags.away.clone()) {
                s.numeric(uid, RPL_AWAY, &format!("{target} :{msg}"));
            }
        }
        // callerid convenience: if the SENDER is +g, auto-accept whoever they
        // message so that person can reply without being blocked.
        if s.users.get(&uid).map(|u| u.flags.callerid).unwrap_or(false) {
            let tnick = s
                .users
                .get(&tuid)
                .map(|u| u.nick.to_ascii_lowercase())
                .unwrap_or_default();
            if let Some(su) = s.users.get_mut(&uid) {
                if !tnick.is_empty() && !su.accept.contains(&tnick) {
                    su.accept.push(tnick);
                }
            }
        }
    } else if let Some((uuid, via)) = s.find_remote(target) {
        // the target is a user on another server — route it across the link
        s.send_to_remote(uid, &uuid, via, cmd, text);
        if s.users
            .get(&uid)
            .map(|u| u.caps.echo_message)
            .unwrap_or(false)
        {
            let ctags = s.line_ctags.clone();
            let msgid = s.next_msgid();
            s.send_tagged(
                uid,
                uid,
                &ctags,
                &msgid,
                &format!(":{prefix} {cmd} {target} :{text}"),
            );
        }
    } else if !notice {
        s.numeric(
            uid,
            ERR_NOSUCHNICK,
            &format!("{target} :No such nick/channel"),
        );
    }
    CmdResult::Ok
}

struct PrivMsg;
impl Command for PrivMsg {
    fn name(&self) -> &'static str {
        "PRIVMSG"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        deliver(s, uid, params, false)
    }
}

struct Notice;
impl Command for Notice {
    fn name(&self) -> &'static str {
        "NOTICE"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        deliver(s, uid, params, true)
    }
}

/// TAGMSG — an IRCv3 message that carries only client tags (typing, reactions, …)
/// and no text. Relayed to targets whose clients enabled `message-tags`; clients
/// without it never see it. Mirrors PRIVMSG's target / membership / +m rules.
struct TagMsg;
impl Command for TagMsg {
    fn name(&self) -> &'static str {
        "TAGMSG"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let ctags = s.line_ctags.clone();
        if ctags.is_empty() {
            return CmdResult::Ok; // no client tags -> nothing to relay
        }
        let target = &params[0];
        let Some(prefix) = s.users.get(&uid).map(|u| u.prefix()) else {
            return CmdResult::Fail;
        };
        let body = format!(":{prefix} TAGMSG {target}");
        let msgid = s.next_msgid(); // shared across this TAGMSG's recipients
        if target.starts_with('#') {
            let key = target.to_ascii_lowercase();
            if !s
                .channels
                .get(&key)
                .map(|c| c.members.contains_key(&uid))
                .unwrap_or(false)
            {
                return CmdResult::Fail;
            }
            // +m: only voiced-or-above may emit tags
            let moderated = s
                .channels
                .get(&key)
                .map(|c| c.modes.moderated)
                .unwrap_or(false);
            if moderated && s.rank(uid, &key) < RANK_VOICE {
                return CmdResult::Fail;
            }
            let echo = s
                .users
                .get(&uid)
                .map(|u| u.caps.echo_message)
                .unwrap_or(false);
            let members: Vec<Uid> = s
                .channels
                .get(&key)
                .map(|c| c.members.keys().copied().collect())
                .unwrap_or_default();
            for m in members {
                if (m == uid && !echo) || s.users.get(&m).map(|u| u.flags.deaf).unwrap_or(false) {
                    continue;
                }
                // only message-tags clients receive a TAGMSG
                if s.users
                    .get(&m)
                    .map(|u| u.caps.message_tags)
                    .unwrap_or(false)
                {
                    s.send_tagged(m, uid, &ctags, &msgid, &body);
                }
            }
        } else if let Some(tuid) = s.find_nick(target) {
            if s.users
                .get(&tuid)
                .map(|u| u.caps.message_tags)
                .unwrap_or(false)
            {
                s.send_tagged(tuid, uid, &ctags, &msgid, &body);
            }
            if s.users
                .get(&uid)
                .map(|u| u.caps.echo_message)
                .unwrap_or(false)
            {
                s.send_tagged(uid, uid, &ctags, &msgid, &body);
            }
        }
        CmdResult::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_drops_codes_but_keeps_text_and_bare_commas() {
        assert_eq!(strip_formatting("\u{03}04red\u{03} text"), "red text");
        assert_eq!(strip_formatting("\u{02}bold\u{02}"), "bold");
        assert_eq!(strip_formatting("\u{03}04,08fg"), "fg"); // colour,bg spec
        assert_eq!(strip_formatting("\u{03}4, hi"), ", hi"); // bare comma survives
        assert!(has_formatting("\u{03}4x") && !has_formatting("plain"));
        assert!(is_ctcp("\u{01}PING\u{01}") && !is_ctcp("hi"));
        assert!(is_action("\u{01}ACTION waves"));
    }
}
