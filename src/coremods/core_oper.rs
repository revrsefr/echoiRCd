//! IRC operator commands: OPER, KILL, WALLOPS, the SA*/SVS* set, X-lines, and
//! the oper CHG*/SET* tools. Oper blocks are configured with `oper = name pass`.

use crate::channels::Topic;
use crate::command::{CmdResult, Command};
use crate::coremods::core_mode::{apply_mode, svs_set_user_modes};
use crate::module::Hook;
use crate::numeric::*;
use crate::server::{iso_time, now, Server};
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
        Box::new(Cban),
        Box::new(Rline),
        Box::new(Connect),
        Box::new(Squit),
        Box::new(ChgHost),
        Box::new(ChgIdent),
        Box::new(SetHost),
        Box::new(SetIdent),
        Box::new(SaMode),
        Box::new(SaTopic),
        Box::new(SaKick),
        Box::new(SaQuit),
        Box::new(ChgName),
        Box::new(ClearChan),
        Box::new(Check),
        Box::new(AllTime),
        Box::new(SwhoisCmd),
        Box::new(SetIdle),
        Box::new(NickLock),
        Box::new(NickUnlock),
        Box::new(OperMotd),
    ]
}

/// OPERMOTD — show the IRC-operators' message of the day, configured with
/// repeated `opermotd = <line>` entries.
struct OperMotd;
impl Command for OperMotd {
    fn name(&self) -> &'static str {
        "OPERMOTD"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let nick = oper_nick(s, uid);
        let motd = s.conf_all("opermotd").to_vec();
        if motd.is_empty() {
            s.send(
                uid,
                format!(":{} NOTICE {nick} :No OPERMOTD is set", s.name),
            );
            return CmdResult::Ok;
        }
        s.send(
            uid,
            format!(
                ":{} NOTICE {nick} :- IRC Operators Message of the Day -",
                s.name
            ),
        );
        for line in motd {
            s.send(uid, format!(":{} NOTICE {nick} :- {line}", s.name));
        }
        s.send(
            uid,
            format!(":{} NOTICE {nick} :- End of OPERMOTD -", s.name),
        );
        CmdResult::Ok
    }
}

/// An oper-set WHOIS line, stored per-user in `User.ext` and rendered by WHOIS
/// (RPL_WHOISSPECIAL 320).
pub struct Swhois(pub String);

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
        let (name, pass) = (params[0].clone(), params[1].clone());
        let Some(block) = s.opers.iter().find(|o| o.name == name).cloned() else {
            s.numeric(uid, ERR_PASSWDMISMATCH, ":Password incorrect");
            return CmdResult::Fail;
        };
        let (hash, level) = (block.password.clone(), block.level);
        let otype = block.oper_type.clone();
        // fingerprint login: the block demands a specific TLS client-cert SHA-256
        // fingerprint, so the user must be on a matching certificate.
        if let Some(want_fp) = &block.fingerprint {
            let user_fp = s.users.get(&uid).and_then(|u| u.certfp.clone());
            if !user_fp
                .as_deref()
                .is_some_and(|f| f.eq_ignore_ascii_case(want_fp))
            {
                s.snotice_c(
                    'o',
                    &format!("Failed OPER for {name}: certificate fingerprint mismatch"),
                );
                s.numeric(
                    uid,
                    ERR_PASSWDMISMATCH,
                    ":Password incorrect (a matching TLS client certificate is required)",
                );
                return CmdResult::Fail;
            }
        }
        // `password = *` means cert-only: the fingerprint above is the whole check.
        if hash == "*" {
            s.oper_up(uid);
            crate::modules::operlevels::set(s, uid, level);
            crate::modules::opertypes::apply(s, uid, otype.as_deref());
            return CmdResult::Ok;
        }
        // a KDF password (bcrypt / pbkdf2) is slow — verify it off the core thread
        // (result arrives as OperAuth), so it can't freeze the server or be a DoS.
        if crate::modules::password_hash::is_slow(&hash) {
            let ot = otype.clone();
            let ok = s.spawn_crypto(move || {
                let ok = crate::modules::password_hash::verify(&hash, &pass);
                crate::ircd::Event::OperAuth { uid, ok, level, oper_type: ot }
            });
            if !ok {
                s.numeric(uid, ERR_PASSWDMISMATCH, ":Too many auth attempts, try again");
                return CmdResult::Fail;
            }
            return CmdResult::Ok; // pending; oper-up happens when the verify returns
        }
        // fast hashes (plaintext / sha*) verify inline
        if crate::modules::password_hash::verify(&hash, &pass) {
            s.oper_up(uid);
            crate::modules::operlevels::set(s, uid, level); // operlevels: KILL protection
            crate::modules::opertypes::apply(s, uid, otype.as_deref());
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
            // remote target: route the KILL toward the server that owns it
            if let Some((uuid, _)) = s.find_remote(target) {
                // servprotect (+k): a network service can't be killed, even remotely
                let protected = s.uuid_is_service(&uuid)
                    || s.remote_users
                        .get(&uuid)
                        .map(|r| r.modes.contains('k'))
                        .unwrap_or(false);
                if protected {
                    s.numeric(uid, ERR_NOPRIVILEGES, ":You cannot KILL a network service");
                    return CmdResult::Fail;
                }
                let (killer_uuid, killer) = s
                    .users
                    .get(&uid)
                    .map(|u| (u.uuid.clone(), u.nick.clone()))
                    .unwrap_or_default();
                s.route_kill(&killer_uuid, &uuid, &format!("{killer} ({reason})"));
                return CmdResult::Ok;
            }
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{target} :No such nick/channel"),
            );
            return CmdResult::Fail;
        };
        // servprotect (+k): a network service can't be killed
        if s.uid_servprotected(tuid) {
            s.numeric(uid, ERR_NOPRIVILEGES, ":You cannot KILL a network service");
            return CmdResult::Fail;
        }
        // operlevels: a lower-level oper can't KILL a higher-level oper
        if let Some(reason) = crate::modules::operlevels::deny_kill(s, uid, tuid) {
            s.numeric(uid, ERR_NOPRIVILEGES, &format!(":{reason}"));
            return CmdResult::Fail;
        }
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

/// SVSLOGIN / SVSLOGOUT — the services interface to the account layer
/// ([`crate::accounts`]). The live path is S2S: a U-lined services server sources
/// them (see `link_svslogin`, gated by `source_is_service`). The client-facing
/// oper form is an emergency stopgap for a network with no services linked — it can
/// forge any account login, so it is OFF unless `oper_svslogin = yes`.
/// `SVSLOGIN <nick> <account>` logs a user in (`account` of `*`/`0` logs out);
/// `SVSLOGOUT <nick>` logs them out.
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
        // The account layer is driven by services over S2S; the oper form can forge
        // any login, so it's an opt-in emergency stopgap (default off).
        if !s.conf_bool("oper_svslogin", false) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- account login is handled by services (set oper_svslogin to override)",
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
        if !s.conf_bool("oper_svslogin", false) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- account login is handled by services (set oper_svslogin to override)",
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
        if s.uid_servprotected(tuid) { s.numeric(uid, ERR_NOPRIVILEGES, ":Cannot use an SA command on a network service"); return CmdResult::Fail; }
        let newnick = &params[1];
        if !valid_nick(newnick, s.conf_num("maxnick", 30usize)) {
            s.numeric(
                uid,
                ERR_ERRONEUSNICKNAME,
                &format!("{newnick} :Erroneous nickname"),
            );
            return CmdResult::Fail;
        }
        // allow a case-only change: the in-use index would otherwise match the target itself
        let cur = s.users.get(&tuid).map(|u| u.nick.clone()).unwrap_or_default();
        if !newnick.eq_ignore_ascii_case(&cur)
            && (s.find_nick(newnick).is_some()
                || s.remote_nick.contains_key(&newnick.to_ascii_lowercase()))
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
// under the names a services package speaks. Gated to opers/services; a linked
// services pseudoserver drives these once S2S routes them.

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
        if !valid_nick(newnick, s.conf_num("maxnick", 30usize)) {
            s.numeric(
                uid,
                ERR_ERRONEUSNICKNAME,
                &format!("{newnick} :Erroneous nickname"),
            );
            return CmdResult::Fail;
        }
        // allow a case-only change: the in-use index would otherwise match the target itself
        let cur = s.users.get(&tuid).map(|u| u.nick.clone()).unwrap_or_default();
        if !newnick.eq_ignore_ascii_case(&cur)
            && (s.find_nick(newnick).is_some()
                || s.remote_nick.contains_key(&newnick.to_ascii_lowercase()))
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
            s.propagate_delline(kind.tag(), &mask);
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
    // <mask> <duration> :<reason>; tolerate the durationless form by taking an
    // unparseable second token as the reason (permanent ban).
    let (dur, reason) = match parse_duration(&params[1]) {
        Some(d) => (
            d,
            params
                .get(2)
                .cloned()
                .unwrap_or_else(|| "No reason given".to_string()),
        ),
        None => (0, params[1].clone()),
    };
    s.add_xline(kind, &mask, dur, &nick, &reason);
    s.propagate_addline(kind.tag(), &mask, &nick, dur, &reason);
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

/// CBAN — forbid a channel-name glob (opers bypass it). Mask alone removes; a
/// mask + duration adds.
struct Cban;
impl Command for Cban {
    fn name(&self) -> &'static str {
        "CBAN"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        do_xline(s, uid, params, XKind::Cban)
    }
}

/// RLINE — ban users whose `nick!user@host realname` matches a regular expression.
/// `RLINE <regex> [<duration>] :<reason>` adds; `RLINE <regex>` removes.
struct Rline;
impl Command for Rline {
    fn name(&self) -> &'static str {
        "RLINE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let pattern = params[0].clone();
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        if params.len() < 2 {
            let word = if s.remove_xline(XKind::Rline, &pattern) {
                s.propagate_delline("R", &pattern);
                "removed"
            } else {
                "not found"
            };
            s.send(
                uid,
                format!(":{} NOTICE {nick} :R-line {word}: {pattern}", s.name),
            );
            return CmdResult::Ok;
        }
        if let Err(e) = crate::regex::Regex::new(&pattern) {
            s.send(
                uid,
                format!(":{} NOTICE {nick} :Invalid RLINE regex: {e}", s.name),
            );
            return CmdResult::Fail;
        }
        let dur = parse_duration(&params[1]).unwrap_or(0);
        let reason = params
            .get(2)
            .cloned()
            .unwrap_or_else(|| "No reason given".to_string());
        s.add_xline(XKind::Rline, &pattern, dur, &nick, &reason);
        s.propagate_addline("R", &pattern, &nick, dur, &reason);
        s.enforce_rline(&pattern, &reason);
        CmdResult::Ok
    }
}

/// NICKLOCK — force a user's nick and lock it so they can't change it.
/// `NICKLOCK <nick> <newnick>`; opers/services still can.
struct NickLock;
impl Command for NickLock {
    fn name(&self) -> &'static str {
        "NICKLOCK"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(tuid) = oper_target(s, uid, &params[0]) else {
            return CmdResult::Fail;
        };
        let newnick = &params[1];
        if !valid_nick(newnick, s.conf_num("maxnick", 30usize)) {
            s.numeric(
                uid,
                ERR_ERRONEUSNICKNAME,
                &format!("{newnick} :Erroneous nickname"),
            );
            return CmdResult::Fail;
        }
        let cur = s
            .users
            .get(&tuid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        if !newnick.eq_ignore_ascii_case(&cur) {
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
        }
        if let Some(u) = s.users.get_mut(&tuid) {
            u.flags.nick_locked = true;
        }
        let by = oper_nick(s, uid);
        s.snotice_c('v', &format!("{by} used NICKLOCK on {newnick}"));
        CmdResult::Ok
    }
}

/// NICKUNLOCK — release a NICKLOCK so the user may change nick again.
struct NickUnlock;
impl Command for NickUnlock {
    fn name(&self) -> &'static str {
        "NICKUNLOCK"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(tuid) = oper_target(s, uid, &params[0]) else {
            return CmdResult::Fail;
        };
        if let Some(u) = s.users.get_mut(&tuid) {
            u.flags.nick_locked = false;
        }
        let by = oper_nick(s, uid);
        s.snotice_c('v', &format!("{by} used NICKUNLOCK on {}", params[0]));
        CmdResult::Ok
    }
}

/// CONNECT — dial a configured server link on demand. `CONNECT <servername>`.
struct Connect;
impl Command for Connect {
    fn name(&self) -> &'static str {
        "CONNECT"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let name = &params[0];
        let Some(b) = s
            .link_blocks
            .iter()
            .find(|b| b.name.eq_ignore_ascii_case(name))
            .cloned()
        else {
            onotice(s, uid, &format!("CONNECT: no link block named {name}"));
            return CmdResult::Fail;
        };
        if s.servers
            .values()
            .any(|sv| sv.name.eq_ignore_ascii_case(&b.name))
        {
            onotice(s, uid, &format!("CONNECT: {} is already linked", b.name));
            return CmdResult::Fail;
        }
        let addr = format!("{}:{}", b.ip, b.port);
        let (tx, counter) = (s.event_tx.clone(), s.conn_counter.clone());
        let max_line = s.conf_num("max_line", crate::socketengine::DEFAULT_MAX_LINE);
        std::thread::spawn(move || crate::socketengine::connect_link(&addr, tx, counter, max_line));
        let by = oper_nick(s, uid);
        s.snotice_c('l', &format!(
            "{by} used CONNECT to {} ({}:{})",
            b.name, b.ip, b.port
        ));
        CmdResult::Ok
    }
}

/// SQUIT <server> — disconnect a linked server (and everything behind it).
struct Squit;
impl Command for Squit {
    fn name(&self) -> &'static str {
        "SQUIT"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let name = &params[0];
        let Some(via) = s
            .servers
            .values()
            .find(|sv| sv.name.eq_ignore_ascii_case(name))
            .map(|sv| sv.via)
        else {
            s.numeric(uid, ERR_NOSUCHSERVER, &format!("{name} :No such server"));
            return CmdResult::Fail;
        };
        let by = oper_nick(s, uid);
        s.snotice_c('l', &format!("{by} used SQUIT on {name}"));
        s.close_link(via, &format!("SQUIT from {by}"));
        CmdResult::Ok
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
        s.snotice_c('v', &format!(
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
        s.snotice_c('v', &format!(
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
        s.snotice_c('v', &format!("{by} used SAMODE: {}", params.join(" ")));
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
        s.propagate_topic(uid, chan, &text);
        let by = oper_nick(s, uid);
        s.snotice_c('v', &format!("{by} used SATOPIC on {chan}"));
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
        if s.uid_servprotected(tuid) {
            s.numeric(uid, ERR_NOPRIVILEGES, ":Cannot use an SA command on a network service");
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
        s.propagate_kick(uid, chan, victim, &reason);
        if let Some(ch) = s.channels.get_mut(&key) {
            ch.members.remove(&tuid);
        }
        if let Some(u) = s.users.get_mut(&tuid) {
            u.channels.remove(&key);
        }
        s.channels.retain(|_, c| c.keep_alive());
        s.events
            .push_back(Hook::Part(tuid, key, "kicked".to_string()));
        let by = oper_nick(s, uid);
        s.snotice_c('v', &format!("{by} used SAKICK on {victim} in {chan}"));
        CmdResult::Ok
    }
}

/// SAQUIT — force a user to quit the network. Looks to everyone like a normal
/// client QUIT.
struct SaQuit;
impl Command for SaQuit {
    fn name(&self) -> &'static str {
        "SAQUIT"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(tuid) = oper_target(s, uid, &params[0]) else {
            return CmdResult::Fail;
        };
        let reason = params
            .get(1)
            .cloned()
            .unwrap_or_else(|| "Services forced quit".to_string());
        if s.uid_servprotected(tuid) { s.numeric(uid, ERR_NOPRIVILEGES, ":Cannot use an SA command on a network service"); return CmdResult::Fail; }
        s.send(tuid, format!("ERROR :Closing link: (SAQUIT: {reason})"));
        s.remove_user(tuid, &format!("Quit: {reason}"));
        let by = oper_nick(s, uid);
        s.snotice_c('v', &format!("{by} used SAQUIT on {}: {reason}", params[0]));
        CmdResult::Ok
    }
}

/// CHGNAME — change another user's real name (the oper-driven counterpart to
/// SETNAME); broadcast to `setname`-capable peers so clients update live.
struct ChgName;
impl Command for ChgName {
    fn name(&self) -> &'static str {
        "CHGNAME"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(t) = oper_target(s, uid, &params[0]) else {
            return CmdResult::Fail;
        };
        let realname = params[1].clone();
        let prefix = match s.users.get_mut(&t) {
            Some(u) => {
                u.realname = realname.clone();
                u.prefix()
            }
            None => return CmdResult::Fail,
        };
        let line = format!(":{prefix} SETNAME :{realname}");
        if s.users.get(&t).map(|u| u.caps.setname).unwrap_or(false) {
            s.send(t, line.clone());
        }
        s.notify_peers(t, &line, |c| c.setname);
        let by = oper_nick(s, uid);
        s.snotice_c('v', &format!("{by} used CHGNAME on {}: {realname}", params[0]));
        CmdResult::Ok
    }
}

/// CLEARCHAN — kick every user out of a channel. Each removal is a normal KICK,
/// propagated like SAKICK.
struct ClearChan;
impl Command for ClearChan {
    fn name(&self) -> &'static str {
        "CLEARCHAN"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let chan = params[0].clone();
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        let reason = params
            .get(1)
            .cloned()
            .unwrap_or_else(|| "Channel cleared by services".to_string());
        let prefix = s.users[&uid].prefix();
        let members: Vec<Uid> = s.channels[&key].members.keys().copied().collect();
        for tuid in members {
            let victim = s
                .users
                .get(&tuid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            if victim.is_empty() {
                continue;
            }
            s.to_channel(
                &key,
                &format!(":{prefix} KICK {chan} {victim} :{reason}"),
                None,
            );
            s.propagate_kick(uid, &chan, &victim, &reason);
            if let Some(ch) = s.channels.get_mut(&key) {
                ch.members.remove(&tuid);
            }
            if let Some(u) = s.users.get_mut(&tuid) {
                u.channels.remove(&key);
            }
            s.events
                .push_back(Hook::Part(tuid, key.clone(), "cleared".to_string()));
        }
        s.channels.retain(|_, c| c.keep_alive());
        let by = oper_nick(s, uid);
        s.snotice_c('v', &format!("{by} used CLEARCHAN on {chan}"));
        CmdResult::Ok
    }
}

/// CHECK — oper diagnostic dump for a nick or channel.
struct Check;
impl Command for Check {
    fn name(&self) -> &'static str {
        "CHECK"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let target = params[0].clone();
        if target.starts_with('#') {
            let key = target.to_ascii_lowercase();
            let (count, topic, members) = match s.channels.get(&key) {
                Some(ch) => (
                    ch.members.len(),
                    ch.topic
                        .as_ref()
                        .map(|t| t.text.clone())
                        .unwrap_or_default(),
                    ch.members
                        .keys()
                        .filter_map(|m| s.users.get(m).map(|u| u.nick.clone()))
                        .collect::<Vec<_>>(),
                ),
                None => {
                    s.numeric(
                        uid,
                        ERR_NOSUCHCHANNEL,
                        &format!("{target} :No such channel"),
                    );
                    return CmdResult::Fail;
                }
            };
            onotice(
                s,
                uid,
                &format!("*** CHECK {target}: channel, {count} members"),
            );
            if !topic.is_empty() {
                onotice(s, uid, &format!("*** topic: {topic}"));
            }
            onotice(s, uid, &format!("*** members: {}", members.join(" ")));
        } else if let Some(t) = s.find_nick(&target) {
            let lines = {
                let u = &s.users[&t];
                vec![
                    format!("*** CHECK {target}: {}", u.prefix()),
                    format!("*** realhost {} ip {}", u.host, u.addr.ip()),
                    format!("*** realname: {}", u.realname),
                    format!(
                        "*** account: {}  secure: {}",
                        u.account.clone().unwrap_or_else(|| "*".to_string()),
                        u.secure
                    ),
                    format!("*** umodes: +{}", u.flags.umodes()),
                    format!(
                        "*** signon {} idle {}s",
                        iso_time(u.signon),
                        now().saturating_sub(u.last_active)
                    ),
                    format!(
                        "*** channels: {}",
                        u.channels.iter().cloned().collect::<Vec<_>>().join(" ")
                    ),
                ]
            };
            for l in lines {
                onotice(s, uid, &l);
            }
        } else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{target} :No such nick/channel"),
            );
            return CmdResult::Fail;
        }
        CmdResult::Ok
    }
}

/// SWHOIS — attach (or clear) an extra WHOIS line on a user. `SWHOIS <nick>
/// :<text>`; an empty text removes it. Shown as RPL_WHOISSPECIAL.
struct SwhoisCmd;
impl Command for SwhoisCmd {
    fn name(&self) -> &'static str {
        "SWHOIS"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(t) = oper_target(s, uid, &params[0]) else {
            return CmdResult::Fail;
        };
        // everything after the nick is the line — works with or without a `:`
        let text = params[1..].join(" ");
        if let Some(u) = s.users.get_mut(&t) {
            if text.is_empty() {
                u.ext.take::<Swhois>();
            } else {
                u.ext.set(Swhois(text.clone()));
            }
        }
        let by = oper_nick(s, uid);
        s.snotice_c('v', &format!("{by} used SWHOIS on {}: {text}", params[0]));
        CmdResult::Ok
    }
}

/// SETIDLE — reset your own idle time. `SETIDLE <seconds>` backdates the
/// last-activity clock so WHOIS shows that idle time.
struct SetIdle;
impl Command for SetIdle {
    fn name(&self) -> &'static str {
        "SETIDLE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let secs: u64 = params[0].parse().unwrap_or(0);
        if let Some(u) = s.users.get_mut(&uid) {
            u.last_active = now().saturating_sub(secs);
        }
        onotice(s, uid, &format!("*** SETIDLE: idle time set to {secs}s"));
        CmdResult::Ok
    }
}

/// ALLTIME — show the current server time to the requesting oper (on a single
/// server there's just the one time to report).
struct AllTime;
impl Command for AllTime {
    fn name(&self) -> &'static str {
        "ALLTIME"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let msg = format!("ALLTIME: {} {}", s.name, iso_time(now()));
        onotice(s, uid, &msg);
        CmdResult::Ok
    }
}
