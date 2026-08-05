//! core_info — informational commands: WHOIS, WHO, LUSERS, MOTD, VERSION.

use crate::command::{CmdResult, Command};
use crate::numeric::*;
use crate::server::{Server, VERSION};
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(Whois),
        Box::new(Who),
        Box::new(Lusers),
        Box::new(Motd),
        Box::new(VersionCmd),
        Box::new(Links),
    ]
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
        let mut rows: Vec<(String, String)> = s
            .servers
            .values()
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
                    let srv = s
                        .servers
                        .get(&ru.sid)
                        .map(|sv| sv.name.clone())
                        .unwrap_or_else(|| ru.sid.clone());
                    s.numeric(
                        uid,
                        RPL_WHOISUSER,
                        &format!("{} {} {} * :{}", ru.nick, ru.ident, ru.host, ru.realname),
                    );
                    s.numeric(
                        uid,
                        RPL_WHOISSERVER,
                        &format!("{} {srv} :remote user", ru.nick),
                    );
                    if let Some(a) = &ru.account {
                        s.numeric(
                            uid,
                            RPL_WHOISACCOUNT,
                            &format!("{} {a} :is logged in as", ru.nick),
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
        let is_self = tuid == uid;
        let keys: Vec<String> = s.users[&tuid].channels.iter().cloned().collect();
        let (
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
            last_active,
            signon,
        ) = {
            let u = &s.users[&tuid];
            (
                u.nick.clone(),
                u.ident.clone(),
                u.host_display().to_string(),
                u.realname.clone(),
                u.host.clone(),
                u.addr.ip().to_string(),
                u.secure,
                u.flags.oper,
                u.flags.bot,
                u.flags.hideoper,
                u.flags.hidechans,
                u.account.clone(),
                u.last_active,
                u.signon,
            )
        };
        let chans: Vec<String> = keys
            .iter()
            .filter_map(|k| s.channels.get(k).map(|c| c.name.clone()))
            .collect();
        s.numeric(
            uid,
            RPL_WHOISUSER,
            &format!("{nick} {ident} {disp} * :{realname}"),
        );
        if bot {
            s.numeric(uid, RPL_WHOISBOT, &format!("{nick} :is a bot"));
        }
        s.numeric(
            uid,
            RPL_WHOISSERVER,
            &format!("{nick} {} :echoIRCd", s.name),
        );
        // +I hides the channel list from everyone but the user themselves + opers
        if !chans.is_empty() && (is_self || asker_oper || !hidechans) {
            s.numeric(
                uid,
                RPL_WHOISCHANNELS,
                &format!("{nick} :{}", chans.join(" ")),
            );
        }
        // 313: is an IRC operator (hidden by +H unless the asker is an oper)
        if oper && (!hideoper || asker_oper) {
            s.numeric(
                uid,
                RPL_WHOISOPERATOR,
                &format!("{nick} :is an IRC operator"),
            );
        }
        // opers can see through the cloak to the real host/ip
        if asker_oper && disp != realhost {
            s.numeric(
                uid,
                RPL_WHOISHOST,
                &format!("{nick} :is connecting from {ident}@{realhost} {realip}"),
            );
        }
        // 330: logged in to a services account
        if let Some(acct) = &account {
            s.numeric(
                uid,
                RPL_WHOISACCOUNT,
                &format!("{nick} {acct} :is logged in as"),
            );
        }
        // sslinfo: advertise a secure (TLS) connection
        if secure {
            s.numeric(
                uid,
                RPL_WHOISSECURE,
                &format!("{nick} :is using a secure connection"),
            );
        }
        // 317: idle time + signon time
        let idle = crate::server::now().saturating_sub(last_active);
        s.numeric(
            uid,
            RPL_WHOISIDLE,
            &format!("{nick} {idle} {signon} :seconds idle, signon time"),
        );
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
        if target.starts_with('#') {
            let key = target.to_ascii_lowercase();
            let multi = s
                .users
                .get(&uid)
                .map(|u| u.caps.multi_prefix)
                .unwrap_or(false);
            let rows: Vec<(Uid, String, String)> = match s.channels.get(&key) {
                Some(ch) => {
                    let name = ch.name.clone();
                    ch.members
                        .iter()
                        .map(|(&m, mem)| {
                            let p = if multi {
                                mem.all_prefixes()
                            } else {
                                mem.prefix_char().to_string()
                            };
                            (m, name.clone(), p)
                        })
                        .collect()
                }
                None => Vec::new(),
            };
            for (m, name, pfx) in rows {
                if let Some(u) = s.users.get(&m) {
                    let row = format!(
                        "{name} {} {} {} {} H{pfx} :0 {}",
                        u.ident,
                        u.host_display(),
                        s.name,
                        u.nick,
                        u.realname
                    );
                    s.numeric(uid, RPL_WHOREPLY, &row);
                }
            }
        } else if let Some(tuid) = s.find_nick(target) {
            let u = &s.users[&tuid];
            let row = format!(
                "* {} {} {} {} H :0 {}",
                u.ident,
                u.host_display(),
                s.name,
                u.nick,
                u.realname
            );
            s.numeric(uid, RPL_WHOREPLY, &row);
        }
        s.numeric(uid, RPL_ENDOFWHO, &format!("{target} :End of /WHO list"));
        CmdResult::Ok
    }
}

struct Lusers;
impl Command for Lusers {
    fn name(&self) -> &'static str {
        "LUSERS"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        s.numeric(
            uid,
            RPL_LUSERCLIENT,
            &format!(":There are {} users on 1 server", s.users.len()),
        );
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
        s.send(
            uid,
            format!(":{} 351 * echoircd-{VERSION} {} :", s.name, s.name),
        );
        CmdResult::Ok
    }
}
