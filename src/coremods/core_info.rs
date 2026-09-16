//! core_info — informational commands: WHOIS, WHO, LUSERS, MOTD, VERSION.

use crate::command::{CmdResult, Command};
use crate::numeric::*;
use crate::server::{version_comment, Server, RELEASE};
use crate::users::User;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(Whois),
        Box::new(Who),
        Box::new(Lusers),
        Box::new(Motd),
        Box::new(VersionCmd),
        Box::new(Links),
        Box::new(SslInfo),
    ]
}

/// SSLINFO — report a user's TLS status and client-cert fingerprint. You may
/// query yourself; querying another user requires oper.
struct SslInfo;
impl Command for SslInfo {
    fn name(&self) -> &'static str {
        "SSLINFO"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let target = params[0].clone();
        let Some(tuid) = s.find_nick(&target) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{target} :No such nick/channel"),
            );
            return CmdResult::Fail;
        };
        if tuid != uid && !s.is_oper(uid) {
            s.numeric(uid, ERR_NOPRIVILEGES, ":You may only SSLINFO yourself");
            return CmdResult::Fail;
        }
        let asker = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_else(|| "*".to_string());
        let (nick, secure, certfp) = {
            let u = &s.users[&tuid];
            (u.nick.clone(), u.secure, u.certfp.clone())
        };
        let tls = if secure { "yes" } else { "no" };
        let fp = certfp.unwrap_or_else(|| "none".to_string());
        let m = s.trf(
            "SSLINFO {0}: TLS={1} certfp={2}",
            &[nick.as_str(), tls, fp.as_str()],
        );
        s.send(uid, format!(":{} NOTICE {asker} :{m}", s.name));
        CmdResult::Ok
    }
}

/// LINKS — the servers this one knows about (itself + every linked peer).
struct Links;
impl Command for Links {
    fn name(&self) -> &'static str {
        "LINKS"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        s.numeric(
            uid,
            RPL_LINKS,
            &format!("{} {} :0 {}", s.name, s.name, s.server_desc),
        );
        // hideservices: services (U-lined) servers are hidden from non-opers.
        let hide_svc = s.conf_bool("hideservices", false)
            && !crate::modules::opertypes::has_priv(
                s,
                uid,
                crate::modules::opertypes::privs::SERVERS_AUSPEX,
            );
        let mut rows: Vec<(String, String)> = s
            .servers
            .values()
            .filter(|sv| !(hide_svc && sv.is_service))
            .map(|sv| (sv.name.clone(), sv.desc.clone()))
            .collect();
        rows.sort();
        for (name, desc) in rows {
            s.numeric(uid, RPL_LINKS, &format!("{name} {} :1 {desc}", s.name));
        }
        s.numeric(uid, RPL_ENDOFLINKS, "* :End of /LINKS list");
        CmdResult::Ok
    }
}

struct Whois;
impl Command for Whois {
    fn name(&self) -> &'static str {
        "WHOIS"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let tnick = params[0]
            .split(',')
            .next()
            .unwrap_or(&params[0])
            .to_string();
        let Some(tuid) = s.find_nick(&tnick) else {
            // maybe they're on another server
            if let Some((uuid, _)) = s.find_remote(&tnick) {
                if let Some(ru) = s.remote_users.get(&uuid) {
                    let (srv, sdesc) = s
                        .servers
                        .get(&ru.sid)
                        .map(|sv| (sv.name.clone(), sv.desc.clone()))
                        .unwrap_or_else(|| (ru.sid.clone(), "remote server".to_string()));
                    s.numeric(
                        uid,
                        RPL_WHOISUSER,
                        &format!("{} {} {} * :{}", ru.nick, ru.ident, ru.host, ru.realname),
                    );
                    // 312: the user's server and its description (not a placeholder —
                    // the actual server info, so a services user reads as its server).
                    s.numeric(uid, RPL_WHOISSERVER, &format!("{} {srv} :{sdesc}", ru.nick));
                    // 313: a user on a U-lined services server is "a network service"
                    // — its oper line reads as a service, not an operator.
                    if s.server_is_service(&ru.sid) {
                        s.numeric(
                            uid,
                            RPL_WHOISOPERATOR,
                            &format!("{} :is a network service", ru.nick),
                        );
                    }
                    if let Some(a) = &ru.account {
                        s.numeric(
                            uid,
                            RPL_WHOISREGNICK,
                            &format!("{} :is a registered nick", ru.nick),
                        );
                        s.numeric(
                            uid,
                            RPL_WHOISACCOUNT,
                            &format!("{} {a} :is logged in as", ru.nick),
                        );
                    }
                    // 301: away status, if the remote user is marked away
                    if let Some(a) = &ru.away {
                        s.numeric(uid, RPL_AWAY, &format!("{} :{a}", ru.nick));
                    }
                    // 335: mark remote bots (+B), e.g. services / BotServ bots
                    if ru.modes.contains('B') {
                        s.numeric(uid, RPL_WHOISBOT, &format!("{} :is a bot", ru.nick));
                    }
                    // 379: a remote user's modes — opers only (self is impossible here)
                    if s.is_oper(uid) && !ru.modes.is_empty() {
                        s.numeric(
                            uid,
                            RPL_WHOISMODES,
                            &format!("{} :is using modes +{}", ru.nick, ru.modes),
                        );
                    }
                    // security groups this server's config places them in (opers see
                    // private ones too); enforcement of `g:` stays with the home server
                    let sg = crate::modules::securitygroups::remote_groups(s, &uuid, s.is_oper(uid));
                    if !sg.is_empty() {
                        s.numeric(
                            uid,
                            RPL_WHOISSPECIAL,
                            &format!(":is in security groups: {}", sg.join(", ")),
                        );
                    }
                    s.numeric(
                        uid,
                        RPL_ENDOFWHOIS,
                        &format!("{} :End of /WHOIS list", ru.nick),
                    );
                    return CmdResult::Ok;
                }
            }
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{tnick} :No such nick/channel"),
            );
            s.numeric(uid, RPL_ENDOFWHOIS, &format!("{tnick} :End of /WHOIS list"));
            return CmdResult::Fail;
        };
        let asker_oper = s.is_oper(uid);
        // auspex: see through user privacy (real host+IP, geo) / channel privacy (secret chans)
        let asker_auspex_u = crate::modules::opertypes::has_priv(
            s,
            uid,
            crate::modules::opertypes::privs::USERS_AUSPEX,
        );
        let asker_auspex_c = crate::modules::opertypes::has_priv(
            s,
            uid,
            crate::modules::opertypes::privs::CHANNELS_AUSPEX,
        );
        let is_self = tuid == uid;
        // hidewhois: hide sensitive lines from ordinary users (opers/self exempt per config)
        let hide = crate::modules::hidewhois::hide(s, uid, tuid, asker_oper);
        let keys: Vec<String> = s.users[&tuid].channels.iter().cloned().collect();
        // A named snapshot of the target for the WHOIS reply — a struct rather than a
        // 17-field positional tuple, so construction can't silently transpose fields.
        struct WhoisInfo {
            nick: String,
            ident: String,
            disp: String,
            realname: String,
            realhost: String,
            realip: String,
            secure: bool,
            oper: bool,
            bot: bool,
            hideoper: bool,
            hidechans: bool,
            account: Option<String>,
            last_msg: u64,
            signon: u64,
            certfp: Option<String>,
            tls_info: Option<String>,
            swhois: Option<String>,
            showwhois: bool,
        }
        let WhoisInfo {
            nick,
            ident,
            disp,
            realname,
            realhost,
            realip,
            secure,
            oper,
            bot,
            hideoper,
            hidechans,
            account,
            last_msg,
            signon,
            certfp,
            tls_info,
            swhois,
            showwhois,
        } = {
            let u = &s.users[&tuid];
            WhoisInfo {
                nick: u.nick.clone(),
                ident: u.ident.clone(),
                disp: u.host_display().to_string(),
                realname: u.realname.clone(),
                realhost: u.host.clone(),
                realip: u.addr.ip().to_string(),
                secure: u.secure,
                oper: u.flags.oper,
                bot: u.flags.bot,
                hideoper: u.flags.hideoper,
                hidechans: u.flags.hidechans,
                account: u.account.clone(),
                last_msg: u.last_msg,
                signon: u.signon,
                certfp: u.certfp.clone(),
                tls_info: u.tls_info.clone(),
                swhois: u
                    .ext
                    .get::<crate::coremods::core_oper::Swhois>()
                    .map(|w| w.0.clone()),
                showwhois: u.flags.showwhois,
            }
        };
        let chans: Vec<String> = keys
            .iter()
            .filter_map(|k| s.channels.get(k))
            .filter(|c| {
                // a +s/+p channel is shown only to the target itself, an oper, or a
                // fellow member — never leaked to an outside asker.
                is_self
                    || asker_auspex_c
                    || (!c.modes.secret && !c.modes.private)
                    || c.members.contains_key(&uid)
            })
            .map(|c| {
                let pfx = c.members.get(&tuid).map(|m| m.prefix_char()).unwrap_or("");
                format!("{pfx}{}", c.name)
            })
            .collect();
        s.numeric(
            uid,
            RPL_WHOISUSER,
            &format!("{nick} {ident} {disp} * :{realname}"),
        );
        if let Some(away) = s.users.get(&tuid).and_then(|u| u.flags.away.clone()) {
            s.numeric(uid, RPL_AWAY, &format!("{nick} :{away}"));
        }
        if bot {
            s.numeric(uid, RPL_WHOISBOT, &format!("{nick} :is a bot"));
        }
        if !(hide && crate::modules::hidewhois::hide_server(s)) {
            s.numeric(
                uid,
                RPL_WHOISSERVER,
                &format!("{nick} {} :echoIRCd", s.name),
            );
        }
        // +I hides the channel list from everyone but the user themselves + users/auspex
        if !chans.is_empty() && (is_self || asker_auspex_u || !hidechans) {
            // fold across multiple 319 lines so a user in many channels stays under 512
            let askern = s.users.get(&uid).map(|u| u.nick.len()).unwrap_or(1);
            let budget = 500usize.saturating_sub(s.name.len() + askern + nick.len() + 12);
            let mut line = String::new();
            for c in &chans {
                if !line.is_empty() && line.len() + 1 + c.len() > budget {
                    s.numeric(uid, RPL_WHOISCHANNELS, &format!("{nick} :{line}"));
                    line.clear();
                }
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(c);
            }
            if !line.is_empty() {
                s.numeric(uid, RPL_WHOISCHANNELS, &format!("{nick} :{line}"));
            }
        }
        // 313: is an IRC Operator (hidden by +H unless the asker is an oper). The
        // oper type sets capabilities, not this line — a custom title (e.g. "is a
        // Network Administrator") comes from the SWHOIS line (320) instead.
        if oper && (!hideoper || asker_oper) {
            s.numeric(
                uid,
                RPL_WHOISOPERATOR,
                &format!("{nick} :is an IRC Operator"),
            );
        }
        // 320: the oper type's title on its own line (bold + its colour), e.g. "is a
        // Network Administrator" — from the oper's type (hidden with +H like 313).
        if oper && (!hideoper || asker_oper) {
            if let Some(line) = crate::modules::opertypes::whois_line(s, tuid) {
                s.numeric(uid, RPL_WHOISSPECIAL, &format!(":{line}"));
            }
        }
        // 320: oper-set SWHOIS line. No redundant target-nick param — just the
        // text — so clients that don't special-case 320 don't echo the nick.
        if let Some(line) = &swhois {
            s.numeric(uid, RPL_WHOISSPECIAL, &format!(":{line}"));
        }
        // security groups (public ones to all; opers/self see private ones too)
        let groups = crate::modules::securitygroups::user_groups(s, tuid, is_self || asker_oper);
        if !groups.is_empty() {
            s.numeric(
                uid,
                RPL_WHOISSPECIAL,
                &format!(":is in security groups: {}", groups.join(", ")),
            );
        }
        // reputation score, subject to the configured whois visibility (all/opers/self/none)
        if crate::modules::reputation::whois_visible(s, uid, tuid) {
            let score = crate::modules::reputation::score_of(s, tuid);
            if score > 0 {
                s.numeric(uid, RPL_WHOISSPECIAL, &format!(":Score: {score}"));
            }
        }
        // profileLink: a profile URL for logged-in users (when configured)
        if let Some(line) = crate::modules::profilelink::line(s, &account) {
            s.numeric(uid, RPL_WHOISSPECIAL, &format!(":{line}"));
        }
        // helpmode: +h marks a user available for help (visible to everyone)
        if s.users.get(&tuid).map(|u| u.flags.helpop).unwrap_or(false) {
            s.numeric(uid, RPL_WHOISSPECIAL, ":is available for help.");
        }
        // customtitle: a claimed vanity title
        if let Some(line) = crate::modules::customtitle::line(s, tuid) {
            s.numeric(uid, RPL_WHOISSPECIAL, &format!(":{line}"));
        }
        // whoisport: the listener port — opers only
        if asker_oper {
            if let Some(line) = crate::modules::whoisport::line(s, tuid) {
                s.numeric(uid, RPL_WHOISSPECIAL, &format!(":{line}"));
            }
        }
        // geoip: where the user connects from — needs users/auspex (like the real host/ip)
        if asker_auspex_u {
            if let Some(line) = crate::modules::geoip::whois_line(s, tuid) {
                s.numeric(uid, RPL_WHOISSPECIAL, &format!(":{line}"));
            }
        }
        // users/auspex: see through the cloak to the real host/ip
        if asker_auspex_u && disp != realhost {
            s.numeric(
                uid,
                RPL_WHOISHOST,
                &format!("{nick} :is connecting from {ident}@{realhost} {realip}"),
            );
        }
        // 307: identified to a registered account (carries the +r registered umode)
        if account.is_some() {
            s.numeric(
                uid,
                RPL_WHOISREGNICK,
                &format!("{nick} :is a registered nick"),
            );
        }
        // 379: the user's active modes — visible to opers and to the user themselves.
        // When they carry a snomask (+s), it's appended as a second token.
        if is_self || asker_oper {
            let (modes, sno) = s
                .users
                .get(&tuid)
                .map(|u| (u.flags.umodes(), u.flags.snomask_cats.clone()))
                .unwrap_or_default();
            let line = if sno.is_empty() {
                format!("{nick} :is using modes {modes}")
            } else {
                format!("{nick} :is using modes {modes} +{sno}")
            };
            s.numeric(uid, RPL_WHOISMODES, &line);
        }
        // 330: logged in to a services account
        if let Some(acct) = &account {
            s.numeric(
                uid,
                RPL_WHOISACCOUNT,
                &format!("{nick} {acct} :is logged in as"),
            );
        }
        // sslinfo: advertise a secure (TLS) connection, with the negotiated
        // version/group/cipher (e.g. TLSv1.3/X25519MLKEM768/TLS_CHACHA20_POLY1305_SHA256)
        // when the backend could report it.
        if secure && !(hide && crate::modules::hidewhois::hide_secure(s)) {
            let detail = match &tls_info {
                Some(t) if !t.is_empty() => format!(" [{t}]"),
                _ => String::new(),
            };
            s.numeric(
                uid,
                RPL_WHOISSECURE,
                &format!("{nick} :is using a secure connection{detail}"),
            );
        }
        // client-cert fingerprint (CertFP) — visible to everyone; it's derived from
        // the certificate the client presents in the handshake, not a secret.
        if let Some(fp) = &certfp {
            s.numeric(
                uid,
                RPL_WHOISCERTFP,
                &format!("{nick} :has client certificate fingerprint {fp}"),
            );
        }
        // 317: idle time + signon time (hidewhois may suppress it)
        if !(hide && crate::modules::hidewhois::hide_idle(s)) {
            let idle = crate::server::now().saturating_sub(last_msg);
            s.numeric(
                uid,
                RPL_WHOISIDLE,
                &format!("{nick} {idle} {signon} :seconds idle, signon time"),
            );
        }
        // +W showwhois — tell the target that someone looked them up (users/secret-whois is silent)
        if showwhois
            && !is_self
            && !crate::modules::opertypes::has_priv(
                s,
                uid,
                crate::modules::opertypes::privs::USERS_SECRET_WHOIS,
            )
        {
            let by = s.users.get(&uid).map(|u| u.prefix()).unwrap_or_default();
            let m = s.trf("{0} did a /WHOIS on you", &[by.as_str()]);
            s.send(tuid, format!(":{} NOTICE {nick} :*** {m}", s.name));
        }
        s.numeric(uid, RPL_ENDOFWHOIS, &format!("{nick} :End of /WHOIS list"));
        CmdResult::Ok
    }
}

struct Who;
impl Command for Who {
    fn name(&self) -> &'static str {
        "WHO"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let target = &params[0];
        // WHOX: an options token containing '%' selects the reply fields (354).
        // `WHO <target> <filter>%<fields>[,<querytype>]`, e.g. `WHO #c %cuhnat,152`.
        let whox = params
            .get(1)
            .and_then(|o| o.split_once('%'))
            .map(|(_, spec)| {
                let (fields, qtype) = spec.split_once(',').unwrap_or((spec, ""));
                (fields.to_string(), qtype.to_string())
            });
        let asker_oper = s.is_oper(uid);
        // auspex: reveal secret/private channel members (channels/auspex) and +i users
        // who share no channel with the asker (users/auspex)
        let asker_auspex_u = crate::modules::opertypes::has_priv(
            s,
            uid,
            crate::modules::opertypes::privs::USERS_AUSPEX,
        );
        let asker_auspex_c = crate::modules::opertypes::has_priv(
            s,
            uid,
            crate::modules::opertypes::privs::CHANNELS_AUSPEX,
        );
        let multi = s
            .users
            .get(&uid)
            .map(|u| u.caps.multi_prefix)
            .unwrap_or(false);

        // (uid, channel-name-or-"*", prefix-string) for each user to report
        let rows: Vec<(Uid, String, String)> = if target.starts_with('#') {
            match s.channels.get(&target.to_ascii_lowercase()) {
                // +s/+p: don't reveal a secret/private channel's members to
                // non-members (opers excepted)
                Some(ch)
                    if (ch.modes.secret || ch.modes.private)
                        && !ch.members.contains_key(&uid)
                        && !asker_auspex_c =>
                {
                    Vec::new()
                }
                Some(ch) => {
                    let name = ch.name.clone();
                    // Mirror NAMES visibility: a non-op viewer of a +u (auditorium)
                    // channel sees only ops, and +D (delayjoin) members who haven't
                    // revealed themselves are hidden from everyone but themselves —
                    // otherwise WHO leaks members that JOIN/NAMES deliberately hide.
                    let hide = ch.modes.auditorium
                        && ch.members.get(&uid).map(|m| m.rank()).unwrap_or(0)
                            < crate::channels::RANK_OP;
                    ch.members
                        .iter()
                        .filter_map(|(&m, mem)| {
                            if m != uid
                                && ((hide && mem.rank() < crate::channels::RANK_OP) || mem.hidden)
                            {
                                return None;
                            }
                            let p = if multi {
                                mem.all_prefixes()
                            } else {
                                mem.prefix_char().to_string()
                            };
                            Some((m, name.clone(), p))
                        })
                        .collect()
                }
                None => Vec::new(),
            }
        } else if let Some(tuid) = s.find_nick(target) {
            // hide a +i (invisible) user from a WHO by someone who shares no channel
            // with them (self and opers always see them).
            let hidden = s
                .users
                .get(&tuid)
                .map(|u| u.flags.invisible)
                .unwrap_or(false)
                && tuid != uid
                && !asker_auspex_u
                && !s
                    .channels
                    .values()
                    .any(|c| c.members.contains_key(&uid) && c.members.contains_key(&tuid));
            if hidden {
                Vec::new()
            } else {
                vec![(tuid, "*".to_string(), String::new())]
            }
        } else {
            Vec::new()
        };

        let now = crate::server::now();
        for (m, chan, pfx) in rows {
            let (code, row) = {
                let Some(u) = s.users.get(&m) else { continue };
                // flags: H (here) / G (gone/away), then * for opers, then prefixes
                let mut flags = String::from(if u.flags.away.is_some() { "G" } else { "H" });
                if u.flags.oper && (!u.flags.hideoper || asker_oper) {
                    flags.push('*');
                }
                flags.push_str(&pfx);
                match &whox {
                    Some((fields, qtype)) => (
                        RPL_WHOSPCRPL,
                        whox_row(
                            &s.name,
                            u,
                            &chan,
                            &flags,
                            fields,
                            qtype,
                            asker_oper,
                            m == uid,
                            now,
                        ),
                    ),
                    None => (
                        RPL_WHOREPLY,
                        format!(
                            "{chan} {} {} {} {} {flags} :0 {}",
                            u.ident,
                            u.host_display(),
                            s.name,
                            u.nick,
                            u.realname
                        ),
                    ),
                }
            };
            s.numeric(uid, code, &row);
        }
        s.numeric(uid, RPL_ENDOFWHO, &format!("{target} :End of /WHO list"));
        CmdResult::Ok
    }
}

/// Build a WHOX (354) reply body: the requested `fields` in their fixed output
/// order (never the request order), realname always last. Unknown field letters
/// are ignored. The real IP (`i`) is shown only to opers or to the user
/// themselves, so host-cloaking isn't defeated.
#[allow(clippy::too_many_arguments)]
fn whox_row(
    server: &str,
    u: &User,
    chan: &str,
    flags: &str,
    fields: &str,
    qtype: &str,
    asker_oper: bool,
    is_self: bool,
    now: u64,
) -> String {
    let has = |c: char| fields.contains(c);
    let mut parts: Vec<String> = Vec::new();
    if has('t') {
        parts.push(if qtype.is_empty() {
            "0".to_string()
        } else {
            qtype.to_string()
        });
    }
    if has('c') {
        parts.push(chan.to_string());
    }
    if has('u') {
        parts.push(u.ident.clone());
    }
    if has('i') {
        parts.push(if asker_oper || is_self {
            u.addr.ip().to_string()
        } else {
            "255.255.255.255".to_string()
        });
    }
    if has('h') {
        parts.push(u.host_display().to_string());
    }
    if has('s') {
        parts.push(server.to_string());
    }
    if has('n') {
        parts.push(u.nick.clone());
    }
    if has('f') {
        parts.push(flags.to_string());
    }
    if has('d') {
        parts.push("0".to_string()); // hopcount (local users)
    }
    if has('l') {
        parts.push(now.saturating_sub(u.last_msg).to_string()); // idle seconds
    }
    if has('a') {
        parts.push(u.account.clone().unwrap_or_else(|| "0".to_string()));
    }
    if has('o') {
        parts.push("n/a".to_string()); // channel op-level
    }
    let mut row = parts.join(" ");
    if has('r') {
        if !row.is_empty() {
            row.push(' ');
        }
        row.push(':');
        row.push_str(&u.realname);
    }
    row
}

struct Lusers;
impl Command for Lusers {
    fn name(&self) -> &'static str {
        "LUSERS"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        s.send_lusers(uid);
        CmdResult::Ok
    }
}

struct Motd;
impl Command for Motd {
    fn name(&self) -> &'static str {
        "MOTD"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        s.send_motd(uid);
        CmdResult::Ok
    }
}

struct VersionCmd;
impl Command for VersionCmd {
    fn name(&self) -> &'static str {
        "VERSION"
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        let line = format!("echoircd-{RELEASE} {} :{}", s.name, version_comment());
        s.numeric(uid, RPL_VERSION, &line);
        CmdResult::Ok
    }
}
