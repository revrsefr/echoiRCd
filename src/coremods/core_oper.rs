//! core_oper — IRC operator commands: OPER, KILL, WALLOPS. Mirrors InspIRCd's
//! `coremods/core_oper/`. Oper blocks are configured with `oper = name pass`.

use crate::channels::Topic;
use crate::command::{CmdResult, Command};
use crate::coremods::core_mode::{apply_mode, svs_set_user_modes};
use crate::module::Hook;
use crate::numeric::*;
use crate::server::{now, Server};
use crate::users::{valid_host, valid_ident, valid_nick};
use crate::xline::{parse_duration, XKind};
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(Oper),
        Box::new(Kill),
        Box::new(Wallops),
        Box::new(SvsLogin),
        Box::new(SvsLogout),
        Box::new(SvsNick),
        Box::new(SvsJoin),
        Box::new(SvsPart),
        Box::new(SvsMode),
        Box::new(GlobOps),
        Box::new(SaJoin),
        Box::new(SaPart),
        Box::new(SaNick),
        Box::new(Die),
        Box::new(Restart),
        Box::new(Kline),
        Box::new(Gline),
        Box::new(Zline),
        Box::new(Eline),
        Box::new(Shun),
        Box::new(Qline),
        Box::new(ChgHost),
        Box::new(ChgIdent),
        Box::new(SetHost),
        Box::new(SetIdent),
        Box::new(SaMode),
        Box::new(SaTopic),
        Box::new(SaKick),
    ]
}

/// Reject non-opers with 481; returns whether the caller is an oper.
fn require_oper(s: &mut Server, uid: Uid) -> bool {
    if s.is_oper(uid) {
        return true;
    }
    s.numeric(
        uid,
        ERR_NOPRIVILEGES,
        ":Permission Denied- You're not an IRC operator",
    );
    false
}

struct Oper;
impl Command for Oper {
    fn name(&self) -> &'static str {
        "OPER"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let (name, pass) = (&params[0], &params[1]);
        if s.opers.iter().any(|(n, p)| n == name && p == pass) {
            s.oper_up(uid);
            CmdResult::Ok
        } else {
            s.numeric(uid, ERR_PASSWDMISMATCH, ":Password incorrect");
            CmdResult::Fail
        }
    }
}

struct Kill;
impl Command for Kill {
    fn name(&self) -> &'static str {
        "KILL"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- You're not an IRC operator",
            );
            return CmdResult::Fail;
        }
        let target = &params[0];
        let reason = params
            .get(1)
            .cloned()
            .unwrap_or_else(|| "Killed".to_string());
        let Some(tuid) = s.find_nick(target) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{target} :No such nick/channel"),
            );
            return CmdResult::Fail;
        };
        let killer = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        s.send(
            tuid,
            format!(":{} KILL {target} :{killer} ({reason})", s.name),
        );
        s.remove_user(tuid, &format!("Killed by {killer}: {reason}"));
        CmdResult::Ok
    }
}

/// SVSLOGIN / SVSLOGOUT — the **services interface** to the account layer
/// ([`crate::accounts`]). Over S2S these arrive from a services pseudoserver
/// (Anope/Atheme); until S2S exists an oper may invoke them to drive `+r` and the
/// account-gated channel modes. `SVSLOGIN <nick> <account>` logs a user in
/// (`account` of `*`/`0` logs out); `SVSLOGOUT <nick>` logs them out.
struct SvsLogin;
impl Command for SvsLogin {
    fn name(&self) -> &'static str {
        "SVSLOGIN"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- SVSLOGIN is a services command",
            );
            return CmdResult::Fail;
        }
        let (target, account) = (&params[0], &params[1]);
        let Some(tuid) = s.find_nick(target) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{target} :No such nick/channel"),
            );
            return CmdResult::Fail;
        };
        if account == "*" || account == "0" {
            s.logout(tuid);
        } else {
            s.set_login(tuid, account);
        }
        CmdResult::Ok
    }
}

struct SvsLogout;
impl Command for SvsLogout {
    fn name(&self) -> &'static str {
        "SVSLOGOUT"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- SVSLOGOUT is a services command",
            );
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(&params[0]) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{} :No such nick/channel", params[0]),
            );
            return CmdResult::Fail;
        };
        s.logout(tuid);
        CmdResult::Ok
    }
}

struct Wallops;
impl Command for Wallops {
    fn name(&self) -> &'static str {
        "WALLOPS"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- You're not an IRC operator",
            );
            return CmdResult::Fail;
        }
        let from = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        s.wallops(&from, &params[0]);
        CmdResult::Ok
    }
}

/// GLOBOPS — a message to every IRC operator.
struct GlobOps;
impl Command for GlobOps {
    fn name(&self) -> &'static str {
        "GLOBOPS"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let from = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        let opers: Vec<Uid> = s
            .users
            .iter()
            .filter(|(_, u)| u.flags.oper)
            .map(|(&u, _)| u)
            .collect();
        for o in opers {
            let nick = s.users.get(&o).map(|u| u.nick.clone()).unwrap_or_default();
            s.send(
                o,
                format!(
                    ":{} NOTICE {nick} :*** GLOBOPS from {from}: {}",
                    s.name, params[0]
                ),
            );
        }
        CmdResult::Ok
    }
}

/// SAJOIN — force a user into a channel.
struct SaJoin;
impl Command for SaJoin {
    fn name(&self) -> &'static str {
        "SAJOIN"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(&params[0]) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{} :No such nick/channel", params[0]),
            );
            return CmdResult::Fail;
        };
        s.join(tuid, &params[1], None);
        CmdResult::Ok
    }
}

/// SAPART — force a user out of a channel.
struct SaPart;
impl Command for SaPart {
    fn name(&self) -> &'static str {
        "SAPART"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(&params[0]) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{} :No such nick/channel", params[0]),
            );
            return CmdResult::Fail;
        };
        let reason = params
            .get(2)
            .cloned()
            .unwrap_or_else(|| "Removed".to_string());
        s.force_part(tuid, &params[1], &reason);
        CmdResult::Ok
    }
}

/// SANICK — force a user's nickname.
struct SaNick;
impl Command for SaNick {
    fn name(&self) -> &'static str {
        "SANICK"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(&params[0]) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{} :No such nick/channel", params[0]),
            );
            return CmdResult::Fail;
        };
        let newnick = &params[1];
        if !valid_nick(newnick) {
            s.numeric(
                uid,
                ERR_ERRONEUSNICKNAME,
                &format!("{newnick} :Erroneous nickname"),
            );
            return CmdResult::Fail;
        }
        if s.find_nick(newnick).is_some()
            || s.remote_nick.contains_key(&newnick.to_ascii_lowercase())
        {
            s.numeric(
                uid,
                ERR_NICKNAMEINUSE,
                &format!("{newnick} :Nickname is already in use"),
            );
            return CmdResult::Fail;
        }
        s.set_nick(tuid, newnick);
        CmdResult::Ok
    }
}

// --- SVS* : the services interface. Same enforcement as the SA* oper commands,
// under the names a services package speaks (like SVSLOGIN). Gated to opers/
// services; a linked services pseudoserver drives these once S2S routes them.

/// SVSNICK — force a nick change (nick-registration enforcement). An optional
/// third param is the new-nick TS, accepted and ignored (single-TS model).
struct SvsNick;
impl Command for SvsNick {
    fn name(&self) -> &'static str {
        "SVSNICK"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(&params[0]) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{} :No such nick/channel", params[0]),
            );
            return CmdResult::Fail;
        };
        let newnick = &params[1];
        if !valid_nick(newnick) {
            s.numeric(
                uid,
                ERR_ERRONEUSNICKNAME,
                &format!("{newnick} :Erroneous nickname"),
            );
            return CmdResult::Fail;
        }
        if s.find_nick(newnick).is_some()
            || s.remote_nick.contains_key(&newnick.to_ascii_lowercase())
        {
            s.numeric(
                uid,
                ERR_NICKNAMEINUSE,
                &format!("{newnick} :Nickname is already in use"),
            );
            return CmdResult::Fail;
        }
        s.set_nick(tuid, newnick);
        CmdResult::Ok
    }
}

/// SVSJOIN — force a user into a channel, bypassing +i/+k/+l/+b.
struct SvsJoin;
impl Command for SvsJoin {
    fn name(&self) -> &'static str {
        "SVSJOIN"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(&params[0]) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{} :No such nick/channel", params[0]),
            );
            return CmdResult::Fail;
        };
        s.join(tuid, &params[1], None);
        CmdResult::Ok
    }
}

/// SVSPART — force a user out of a channel.
struct SvsPart;
impl Command for SvsPart {
    fn name(&self) -> &'static str {
        "SVSPART"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(&params[0]) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{} :No such nick/channel", params[0]),
            );
            return CmdResult::Fail;
        };
        let reason = params
            .get(2)
            .cloned()
            .unwrap_or_else(|| "Services forced part".to_string());
        s.force_part(tuid, &params[1], &reason);
        CmdResult::Ok
    }
}

/// SVSMODE — set modes on a user (e.g. `+r` registered) or a channel with services
/// authority, bypassing the "own modes only" / rank checks a normal MODE enforces.
struct SvsMode;
impl Command for SvsMode {
    fn name(&self) -> &'static str {
        "SVSMODE"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        if params[0].starts_with('#') {
            // channel modes with services authority — same path as SAMODE
            s.mode_sudo = true;
            let r = apply_mode(s, uid, params);
            s.mode_sudo = false;
            return r;
        }
        let Some(tuid) = s.find_nick(&params[0]) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{} :No such nick/channel", params[0]),
            );
            return CmdResult::Fail;
        };
        svs_set_user_modes(s, tuid, &params[1]);
        CmdResult::Ok
    }
}

/// DIE — shut the server down (requires the server name as confirmation).
struct Die;
impl Command for Die {
    fn name(&self) -> &'static str {
        "DIE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        if params[0] != s.name {
            s.numeric(uid, ERR_NOPRIVILEGES, ":DIE requires the server name");
            return CmdResult::Fail;
        }
        let by = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        eprintln!("[oper] DIE by {by}");
        std::process::exit(0);
    }
}

/// RESTART — like DIE (a supervisor is expected to relaunch us).
struct Restart;
impl Command for Restart {
    fn name(&self) -> &'static str {
        "RESTART"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        if params[0] != s.name {
            s.numeric(uid, ERR_NOPRIVILEGES, ":RESTART requires the server name");
            return CmdResult::Fail;
        }
        let by = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        eprintln!("[oper] RESTART by {by}");
        std::process::exit(0);
    }
}

/// Shared KLINE/GLINE/ZLINE handling: the mask alone removes, mask+duration adds.
fn do_xline(s: &mut Server, uid: Uid, params: &[String], kind: XKind) -> CmdResult {
    if !require_oper(s, uid) {
        return CmdResult::Fail;
    }
    let mask = params[0].clone();
    let nick = s
        .users
        .get(&uid)
        .map(|u| u.nick.clone())
        .unwrap_or_default();
    if params.len() < 2 {
        let word = if s.remove_xline(kind, &mask) {
            "removed"
        } else {
            "not found"
        };
        s.send(
            uid,
            format!(
                ":{} NOTICE {nick} :{}-line {word}: {mask}",
                s.name,
                kind.tag()
            ),
        );
        return CmdResult::Ok;
    }
    let dur = parse_duration(&params[1]).unwrap_or(0);
    let reason = params
        .get(2)
        .cloned()
        .unwrap_or_else(|| "No reason given".to_string());
    s.add_xline(kind, &mask, dur, &nick, &reason);
    CmdResult::Ok
}

/// KLINE — ban a `user@host` mask on this server.
struct Kline;
impl Command for Kline {
    fn name(&self) -> &'static str {
        "KLINE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        do_xline(s, uid, params, XKind::Kline)
    }
}

/// GLINE — a network-wide `user@host` ban.
struct Gline;
impl Command for Gline {
    fn name(&self) -> &'static str {
        "GLINE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        do_xline(s, uid, params, XKind::Gline)
    }
}

/// ZLINE — ban an IP address (glob).
struct Zline;
impl Command for Zline {
    fn name(&self) -> &'static str {
        "ZLINE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        do_xline(s, uid, params, XKind::Zline)
    }
}

/// ELINE — exempt a `user@host` / ip glob from all K/G/Z-lines.
struct Eline;
impl Command for Eline {
    fn name(&self) -> &'static str {
        "ELINE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        do_xline(s, uid, params, XKind::Eline)
    }
}

/// SHUN — let a `user@host` connect but silently drop their commands.
struct Shun;
impl Command for Shun {
    fn name(&self) -> &'static str {
        "SHUN"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        do_xline(s, uid, params, XKind::Shun)
    }
}

/// QLINE — reserve/forbid a nick glob (opers bypass it).
struct Qline;
impl Command for Qline {
    fn name(&self) -> &'static str {
        "QLINE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        do_xline(s, uid, params, XKind::Qline)
    }
}

/// Resolve a nick to a uid, sending ERR_NOSUCHNICK if it's unknown.
fn oper_target(s: &mut Server, uid: Uid, nick: &str) -> Option<Uid> {
    match s.find_nick(nick) {
        Some(t) => Some(t),
        None => {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{nick} :No such nick/channel"),
            );
            None
        }
    }
}

/// A server NOTICE to the invoking oper (soft errors for the CHG*/SA* set).
fn onotice(s: &mut Server, uid: Uid, msg: &str) {
    let nick = s
        .users
        .get(&uid)
        .map(|u| u.nick.clone())
        .unwrap_or_else(|| "*".to_string());
    s.send(uid, format!(":{} NOTICE {nick} :{msg}", s.name));
}

/// The oper's nick, for audit snotices.
fn oper_nick(s: &Server, uid: Uid) -> String {
    s.users
        .get(&uid)
        .map(|u| u.nick.clone())
        .unwrap_or_default()
}

/// CHGHOST — change another user's displayed host.
struct ChgHost;
impl Command for ChgHost {
    fn name(&self) -> &'static str {
        "CHGHOST"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        if !valid_host(&params[1]) {
            onotice(s, uid, "*** CHGHOST: invalid characters in hostname");
            return CmdResult::Fail;
        }
        let Some(t) = oper_target(s, uid, &params[0]) else {
            return CmdResult::Fail;
        };
        s.change_host_ident(t, None, Some(&params[1]));
        let by = oper_nick(s, uid);
        s.snotice(&format!(
            "{by} used CHGHOST on {}: {}",
            params[0], params[1]
        ));
        CmdResult::Ok
    }
}

/// SETHOST — change your own displayed host.
struct SetHost;
impl Command for SetHost {
    fn name(&self) -> &'static str {
        "SETHOST"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        if !valid_host(&params[0]) {
            onotice(s, uid, "*** SETHOST: invalid characters in hostname");
            return CmdResult::Fail;
        }
        s.change_host_ident(uid, None, Some(&params[0]));
        CmdResult::Ok
    }
}

/// CHGIDENT — change another user's ident/username.
struct ChgIdent;
impl Command for ChgIdent {
    fn name(&self) -> &'static str {
        "CHGIDENT"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        if !valid_ident(&params[1]) {
            onotice(s, uid, "*** CHGIDENT: invalid characters in ident");
            return CmdResult::Fail;
        }
        let Some(t) = oper_target(s, uid, &params[0]) else {
            return CmdResult::Fail;
        };
        s.change_host_ident(t, Some(&params[1]), None);
        let by = oper_nick(s, uid);
        s.snotice(&format!(
            "{by} used CHGIDENT on {}: {}",
            params[0], params[1]
        ));
        CmdResult::Ok
    }
}

/// SETIDENT — change your own ident/username.
struct SetIdent;
impl Command for SetIdent {
    fn name(&self) -> &'static str {
        "SETIDENT"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        if !valid_ident(&params[0]) {
            onotice(s, uid, "*** SETIDENT: invalid characters in ident");
            return CmdResult::Fail;
        }
        s.change_host_ident(uid, Some(&params[0]), None);
        CmdResult::Ok
    }
}

/// SAMODE — apply a channel MODE as the server, bypassing the rank ladder.
struct SaMode;
impl Command for SaMode {
    fn name(&self) -> &'static str {
        "SAMODE"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        s.mode_sudo = true;
        let r = apply_mode(s, uid, params);
        s.mode_sudo = false;
        let by = oper_nick(s, uid);
        s.snotice(&format!("{by} used SAMODE: {}", params.join(" ")));
        r
    }
}

/// SATOPIC — set a channel topic as the server, bypassing +t / op checks.
struct SaTopic;
impl Command for SaTopic {
    fn name(&self) -> &'static str {
        "SATOPIC"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let chan = &params[0];
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        let text = params[1].clone();
        let (prefix, setter) = {
            let u = &s.users[&uid];
            (u.prefix(), u.nick.clone())
        };
        if let Some(ch) = s.channels.get_mut(&key) {
            ch.topic = Some(Topic {
                text: text.clone(),
                setter,
                ts: now(),
            });
        }
        s.to_channel(&key, &format!(":{prefix} TOPIC {chan} :{text}"), None);
        s.propagate_from_user(uid, &format!("TOPIC {chan} :{text}"));
        let by = oper_nick(s, uid);
        s.snotice(&format!("{by} used SATOPIC on {chan}"));
        CmdResult::Ok
    }
}

/// SAKICK — kick a user as the server, bypassing rank checks.
struct SaKick;
impl Command for SaKick {
    fn name(&self) -> &'static str {
        "SAKICK"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let (chan, victim) = (&params[0], &params[1]);
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(victim) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{victim} :No such nick/channel"),
            );
            return CmdResult::Fail;
        };
        if !s.channels[&key].members.contains_key(&tuid) {
            s.numeric(
                uid,
                ERR_USERNOTINCHANNEL,
                &format!("{victim} {chan} :They aren't on that channel"),
            );
            return CmdResult::Fail;
        }
        let reason = params
            .get(2)
            .cloned()
            .unwrap_or_else(|| "Kicked by services".to_string());
        let prefix = s.users[&uid].prefix();
        s.to_channel(
            &key,
            &format!(":{prefix} KICK {chan} {victim} :{reason}"),
            None,
        );
        s.propagate_from_user(uid, &format!("KICK {chan} {victim} :{reason}"));
        if let Some(ch) = s.channels.get_mut(&key) {
            ch.members.remove(&tuid);
        }
        if let Some(u) = s.users.get_mut(&tuid) {
            u.channels.remove(&key);
        }
        s.channels.retain(|_, c| !c.is_empty());
        s.events
            .push_back(Hook::Part(tuid, key, "kicked".to_string()));
        let by = oper_nick(s, uid);
        s.snotice(&format!("{by} used SAKICK on {victim} in {chan}"));
        CmdResult::Ok
    }
}
