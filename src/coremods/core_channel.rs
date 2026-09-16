//! core_channel — channel membership commands: JOIN, PART, KICK, TOPIC, NAMES.

use crate::channels::{normalize_ban_mask, valid_chan, Ban, Topic, RANK_HALFOP, RANK_OP};
use crate::command::{CmdResult, Command};
use crate::numeric::*;
use crate::server::{now, Server};
use crate::xline::parse_duration;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(Join),
        Box::new(Part),
        Box::new(Rename),
        Box::new(Kick),
        Box::new(TopicCmd),
        Box::new(Names),
        Box::new(Invite),
        Box::new(Uninvite),
        Box::new(Knock),
        Box::new(Cycle),
        Box::new(Remove),
        Box::new(Tban),
    ]
}

/// TBAN — set a +b ban that lifts itself after a duration. `TBAN <#chan>
/// <duration> <mask>`; needs half-op or above. The background tick removes it and
/// announces `MODE -b` when it expires.
struct Tban;
impl Command for Tban {
    fn name(&self) -> &'static str {
        "TBAN"
    }
    fn min_params(&self) -> usize {
        3
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let chan = &params[0];
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        if s.rank(uid, &key) < RANK_HALFOP {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :You're not a channel operator"),
            );
            return CmdResult::Fail;
        }
        let Some(dur) = parse_duration(&params[1]).filter(|&d| d > 0) else {
            s.fail(
                uid,
                "TBAN",
                "INVALID_DURATION",
                "TBAN needs a positive duration",
            );
            return CmdResult::Fail;
        };
        let mask = normalize_ban_mask(&params[2]);
        let (nick, prefix) = {
            let u = &s.users[&uid];
            (u.nick.clone(), u.prefix())
        };
        if s.channels[&key].bans.iter().any(|b| b.mask == mask) {
            let m = s.trf(
                "{0} is already banned on {1}",
                &[mask.as_str(), chan.as_str()],
            );
            s.send(uid, format!(":{} NOTICE {nick} :{m}", s.name));
            return CmdResult::Fail;
        }
        if let Some(c) = s.channels.get_mut(&key) {
            c.bans.push(Ban {
                mask: mask.clone(),
                setter: nick,
                ts: now(),
                expires: Some(now() + dur),
            });
        }
        s.to_channel(&key, &format!(":{prefix} MODE {chan} +b {mask}"), None);
        // links: a channel mode must go out as a timestamped FMODE, not a plain
        // MODE (services ignore channel-targeted MODE)
        let src = s
            .users
            .get(&uid)
            .map(|u| u.uuid.clone())
            .unwrap_or_else(|| s.sid.clone());
        s.propagate_chan_mode(&src, chan, "+b", std::slice::from_ref(&mask));
        CmdResult::Ok
    }
}

/// KNOCK — ask for an invite to an invite-only channel.
struct Knock;
impl Command for Knock {
    fn name(&self) -> &'static str {
        "KNOCK"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let chan = &params[0];
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        let can = s.channels[&key].modes.invite_only && !s.is_member(uid, &key);
        if !can {
            s.fail(
                uid,
                "KNOCK",
                "CANNOT_KNOCK",
                &format!("Can't KNOCK on {chan} (not invite-only, or you're on it)"),
            );
            return CmdResult::Fail;
        }
        let reason = params
            .get(1)
            .cloned()
            .unwrap_or_else(|| "requesting an invite".to_string());
        let who = s.users[&uid].prefix();
        let m = s.trf("is knocking: {0}", &[reason.as_str()]);
        s.to_channel(
            &key,
            &format!(":{} {:03} {chan} {who} :{m}", s.name, RPL_KNOCK),
            None,
        );
        s.numeric(
            uid,
            RPL_KNOCKDLVR,
            &format!("{chan} :Your KNOCK has been delivered"),
        );
        CmdResult::Ok
    }
}

/// CYCLE — part and immediately rejoin a channel.
struct Cycle;
impl Command for Cycle {
    fn name(&self) -> &'static str {
        "CYCLE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let chan = &params[0];
        let key = chan.to_ascii_lowercase();
        if !s.is_member(uid, &key) {
            s.numeric(
                uid,
                ERR_NOTONCHANNEL,
                &format!("{chan} :You're not on that channel"),
            );
            return CmdResult::Fail;
        }
        let prefix = s.users[&uid].prefix();
        s.to_channel(&key, &format!(":{prefix} PART {chan} :cycling"), None);
        s.propagate_part(uid, chan, "cycling");
        if let Some(ch) = s.channels.get_mut(&key) {
            ch.members.remove(&uid);
        }
        if let Some(u) = s.users.get_mut(&uid) {
            u.channels.remove(&key);
        }
        s.channels.retain(|_, c| c.keep_alive());
        s.join(uid, chan, None);
        CmdResult::Ok
    }
}

/// REMOVE — like KICK, but the target sees a PART (a softer removal).
struct Remove;
impl Command for Remove {
    fn name(&self) -> &'static str {
        "REMOVE"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let (chan, victim) = (&params[0], &params[1]);
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        if s.rank(uid, &key) < RANK_HALFOP {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :You're not a channel operator"),
            );
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
        if s.rank(uid, &key) < s.rank(tuid, &key) {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :You cannot remove a user of higher rank"),
            );
            return CmdResult::Fail;
        }
        let by = s.users[&uid].nick.clone();
        let reason = match params.get(2) {
            Some(r) => format!("Removed by {by}: {r}"),
            None => format!("Removed by {by}"),
        };
        let prefix = s.users[&tuid].prefix();
        s.to_channel(&key, &format!(":{prefix} PART {chan} :{reason}"), None);
        s.propagate_part(tuid, chan, &reason);
        if let Some(ch) = s.channels.get_mut(&key) {
            ch.members.remove(&tuid);
        }
        if let Some(u) = s.users.get_mut(&tuid) {
            u.channels.remove(&key);
        }
        s.channels.retain(|_, c| c.keep_alive());
        CmdResult::Ok
    }
}

struct Invite;
impl Command for Invite {
    fn name(&self) -> &'static str {
        "INVITE"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let (tnick, chan) = (&params[0], &params[1]);
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        if !s.is_member(uid, &key) {
            s.numeric(
                uid,
                ERR_NOTONCHANNEL,
                &format!("{chan} :You're not on that channel"),
            );
            return CmdResult::Fail;
        }
        // only ops may invite into an +i channel — unless +A (allow anyone to invite)
        if s.channels[&key].modes.invite_only
            && !s.channels[&key].modes.allowinvite
            && !s.is_op(uid, &key)
        {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :You're not a channel operator"),
            );
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(tnick) else {
            // remote target: route the invite to the server that owns it
            if let Some((tuuid, _)) = s.find_remote(tnick) {
                let iuuid = s.users[&uid].uuid.clone();
                s.route_invite(&iuuid, &tuuid, chan);
                let rnick = s
                    .remote_users
                    .get(&tuuid)
                    .map(|r| r.nick.clone())
                    .unwrap_or_else(|| tnick.to_string());
                s.numeric(uid, RPL_INVITING, &format!("{rnick} {chan}"));
                return CmdResult::Ok;
            }
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{tnick} :No such nick/channel"),
            );
            return CmdResult::Fail;
        };
        if s.channels[&key].members.contains_key(&tuid) {
            s.numeric(
                uid,
                ERR_USERONCHANNEL,
                &format!("{tnick} {chan} :is already on channel"),
            );
            return CmdResult::Fail;
        }
        // cap the per-channel invite set — it only grows until the invitee joins, so
        // without a bound an op could grow it indefinitely (like maxbans caps +b).
        let maxinv = s.conf_num("maxinvites", 100usize);
        if s.channels[&key].invites.len() >= maxinv && !s.channels[&key].invites.contains(&tuid) {
            let nick = s
                .users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            let m = s.trf("Channel invite list is full", &[]);
            s.send(uid, format!(":{} NOTICE {nick} :{chan} :{m}", s.name));
            return CmdResult::Fail;
        }
        if let Some(ch) = s.channels.get_mut(&key) {
            ch.invites.insert(tuid);
        }
        if let Some(u) = s.users.get_mut(&tuid) {
            u.invited.insert(key.clone()); // reverse index for O(1) quit scrub
        }
        let who = s.users[&tuid].nick.clone();
        s.numeric(uid, RPL_INVITING, &format!("{who} {chan}"));
        let prefix = s.users[&uid].prefix();
        s.send(tuid, format!(":{prefix} INVITE {who} :{chan}"));
        // invite-notify: tell capable channel members about the invite
        let notify = format!(":{prefix} INVITE {who} {chan}");
        let members: Vec<Uid> = s.channels[&key].members.keys().copied().collect();
        for m in members {
            if m != uid
                && s.users
                    .get(&m)
                    .map(|u| u.caps.invite_notify)
                    .unwrap_or(false)
            {
                s.send(m, notify.clone());
            }
        }
        CmdResult::Ok
    }
}

/// UNINVITE — revoke a pending invite. `UNINVITE <nick> <#chan>`; a channel op
/// cancels an invite they (or another op) issued.
struct Uninvite;
impl Command for Uninvite {
    fn name(&self) -> &'static str {
        "UNINVITE"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let (tnick, chan) = (&params[0], &params[1]);
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        if !s.is_member(uid, &key) {
            s.numeric(
                uid,
                ERR_NOTONCHANNEL,
                &format!("{chan} :You're not on that channel"),
            );
            return CmdResult::Fail;
        }
        if !s.is_op(uid, &key) {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :You're not a channel operator"),
            );
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(tnick) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{tnick} :No such nick/channel"),
            );
            return CmdResult::Fail;
        };
        let removed = s
            .channels
            .get_mut(&key)
            .map(|ch| ch.invites.remove(&tuid))
            .unwrap_or(false);
        if let Some(u) = s.users.get_mut(&tuid) {
            u.invited.remove(&key); // keep the reverse index in sync
        }
        let who = s.users[&tuid].nick.clone();
        let word = if removed {
            "is no longer invited to"
        } else {
            "was not invited to"
        };
        let nick = s.users[&uid].nick.clone();
        s.send(
            uid,
            format!(":{} NOTICE {nick} :{who} {word} {chan}", s.name),
        );
        if removed {
            let m = s.trf("Your invite to {0} was revoked", &[chan.as_str()]);
            s.send(tuid, format!(":{} NOTICE {who} :{m}", s.name));
        }
        CmdResult::Ok
    }
}

struct Join;
impl Command for Join {
    fn name(&self) -> &'static str {
        "JOIN"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let keys: Vec<&str> = params
            .get(1)
            .map(|k| k.split(',').collect())
            .unwrap_or_default();
        for (i, name) in params[0].split(',').filter(|x| !x.is_empty()).enumerate() {
            s.join(uid, name, keys.get(i).copied());
        }
        CmdResult::Ok
    }
}

struct Part;
impl Command for Part {
    fn name(&self) -> &'static str {
        "PART"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let reason = params.get(1).cloned().unwrap_or_default();
        for target in params[0].split(',').filter(|x| !x.is_empty()) {
            if !s.part(uid, target, &reason) {
                s.numeric(
                    uid,
                    ERR_NOTONCHANNEL,
                    &format!("{target} :You're not on that channel"),
                );
            }
        }
        CmdResult::Ok
    }
}

/// RENAME `<old-channel> <new-channel> [<reason>]` — IRCv3 `draft/channel-rename`.
/// A channel operator renames a channel in place, keeping its membership, modes
/// and topic. Members that negotiated the cap see a `RENAME`; the rest are moved
/// with a PART/JOIN. Registered (+r) channels are managed by services, so a
/// client can't rename them — ChanServ does that over S2S.
struct Rename;
impl Command for Rename {
    fn name(&self) -> &'static str {
        "RENAME"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let (old, new) = (&params[0], &params[1]);
        let reason = params.get(2).cloned().unwrap_or_default();
        let oldkey = old.to_ascii_lowercase();
        let newkey = new.to_ascii_lowercase();
        let case_only = oldkey == newkey;
        if !s.channels.contains_key(&oldkey) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{old} :No such channel"));
            return CmdResult::Fail;
        }
        if !s.is_member(uid, &oldkey) {
            s.numeric(
                uid,
                ERR_NOTONCHANNEL,
                &format!("{old} :You're not on that channel"),
            );
            return CmdResult::Fail;
        }
        let is_oper = s.is_oper(uid);
        if s.rank(uid, &oldkey) < RANK_OP && !is_oper {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{old} :You're not a channel operator"),
            );
            return CmdResult::Fail;
        }
        // A registered channel's name is owned by services; renaming it moves the
        // registration, which only ChanServ (founder-authorised) may do.
        if s.channels[&oldkey].modes.registered && !is_oper {
            s.fail(
                uid,
                "RENAME",
                "CANNOT_RENAME",
                "This channel is registered — ask ChanServ to rename it.",
            );
            return CmdResult::Fail;
        }
        if !valid_chan(new, s.conf_num("maxchannel", 50usize)) {
            s.fail(
                uid,
                "RENAME",
                "CANNOT_RENAME",
                &format!("{new} is not a valid channel name."),
            );
            return CmdResult::Fail;
        }
        // A pure prefix-type change (e.g. # -> &) isn't a rename we support.
        if new.chars().next() != old.chars().next() {
            s.fail(
                uid,
                "RENAME",
                "CANNOT_RENAME",
                "The channel prefix can't be changed.",
            );
            return CmdResult::Fail;
        }
        if !case_only && s.channels.contains_key(&newkey) {
            s.fail(
                uid,
                "RENAME",
                "CHANNEL_NAME_IN_USE",
                &format!("{new} already exists."),
            );
            return CmdResult::Fail;
        }
        if !is_oper {
            if let Some(reason) = s.matched_cban(&newkey) {
                s.fail(
                    uid,
                    "RENAME",
                    "CANNOT_RENAME",
                    &format!("{new} is CBAN'd: {reason}"),
                );
                return CmdResult::Fail;
            }
        }
        // Capture the identity/TS before the move, then rename + propagate.
        let (prefix, uuid) = {
            let u = &s.users[&uid];
            (u.prefix(), u.uuid.clone())
        };
        let oldname = s.channels[&oldkey].name.clone();
        if s.rename_channel(&oldkey, new, &prefix, &reason).is_none() {
            s.fail(
                uid,
                "RENAME",
                "CANNOT_RENAME",
                "The channel cannot be renamed.",
            );
            return CmdResult::Fail;
        }
        let m = s.trf(
            "{0} renamed to {1} by {2}",
            &[oldname.as_str(), new.as_str(), prefix.as_str()],
        );
        s.snotice_c('a', &m);
        s.propagate_rename(&uuid, &oldname, new, &reason, None);
        CmdResult::Ok
    }
}

struct Kick;
impl Command for Kick {
    fn name(&self) -> &'static str {
        "KICK"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let (chan, victim) = (&params[0], &params[1]);
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        if s.rank(uid, &key) < RANK_HALFOP {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :You're not a channel operator"),
            );
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(victim) else {
            // remote victim: route the kick to its server and drop our view of it
            if let Some((vuuid, _)) = s.find_remote(victim) {
                if s.channels[&key].rmembers.contains_key(&vuuid) {
                    if s.nick_servprotected(victim) {
                        s.numeric(
                            uid,
                            ERR_CHANOPRIVSNEEDED,
                            &format!("{chan} :You cannot kick a network service"),
                        );
                        return CmdResult::Fail;
                    }
                    // can't kick a remote member who out-ranks you (as for local victims)
                    let vrank = s.channels[&key]
                        .rmembers
                        .get(&vuuid)
                        .map(|m| m.rank())
                        .unwrap_or(0);
                    if s.rank(uid, &key) < vrank {
                        s.numeric(
                            uid,
                            ERR_CHANOPRIVSNEEDED,
                            &format!("{chan} :You cannot kick a user of higher rank"),
                        );
                        return CmdResult::Fail;
                    }
                    let kicker = s.users[&uid].nick.clone();
                    let reason = params.get(2).cloned().unwrap_or(kicker);
                    let prefix = s.users[&uid].prefix();
                    let vnick = s
                        .remote_users
                        .get(&vuuid)
                        .map(|r| r.nick.clone())
                        .unwrap_or_else(|| victim.to_string());
                    let kline = format!(":{prefix} KICK {chan} {vnick} :{reason}");
                    crate::modules::chathistory::record_event(s, &key, &kline);
                    s.to_channel(&key, &kline, None);
                    s.propagate_kick(uid, chan, victim, &reason);
                    if let Some(ch) = s.channels.get_mut(&key) {
                        ch.rmembers.remove(&vuuid);
                    }
                    return CmdResult::Ok;
                }
            }
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
        // servprotect (+k): a network service can't be kicked
        if s.uid_servprotected(tuid) {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :You cannot kick a network service"),
            );
            return CmdResult::Fail;
        }
        // can't kick someone who out-ranks you
        if s.rank(uid, &key) < s.rank(tuid, &key) {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :You cannot kick a user of higher rank"),
            );
            return CmdResult::Fail;
        }
        // +Q — kicks disabled (IRC operators bypass; SAKICK is a separate path)
        if s.channels[&key].modes.nokicks && !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :Kicks are disabled here (+Q)"),
            );
            return CmdResult::Fail;
        }
        let kicker = s.users[&uid].nick.clone();
        let reason = params.get(2).cloned().unwrap_or(kicker);
        let prefix = s.users[&uid].prefix();
        let kickline = format!(":{prefix} KICK {chan} {victim} :{reason}");
        // record the KICK to history directly — event-playback has no kick hook, and a
        // Hook::Part would mis-record it as a voluntary PART (the remote path does this)
        crate::modules::chathistory::record_event(s, &key, &kickline);
        s.to_channel(&key, &kickline, None);
        s.propagate_kick(uid, chan, victim, &reason); // tell links
        if let Some(ch) = s.channels.get_mut(&key) {
            ch.members.remove(&tuid);
            if ch.modes.kicknorejoin.is_some() {
                ch.recent_kicks.insert(tuid, now()); // +J rejoin-delay clock
            }
        }
        if let Some(u) = s.users.get_mut(&tuid) {
            u.channels.remove(&key);
        }
        s.channels.retain(|_, c| c.keep_alive());
        CmdResult::Ok
    }
}

struct TopicCmd;
impl Command for TopicCmd {
    fn name(&self) -> &'static str {
        "TOPIC"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let target = &params[0];
        let key = target.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(
                uid,
                ERR_NOSUCHCHANNEL,
                &format!("{target} :No such channel"),
            );
            return CmdResult::Fail;
        }
        if params.len() < 2 {
            match s.channels[&key].topic.as_ref() {
                Some(t) => {
                    let text = t.text.clone();
                    let setter = t.setter.clone();
                    let ts = t.ts;
                    s.numeric(uid, RPL_TOPIC, &format!("{target} :{text}"));
                    s.numeric(uid, RPL_TOPICWHOTIME, &format!("{target} {setter} {ts}"));
                }
                None => s.numeric(uid, RPL_NOTOPIC, &format!("{target} :No topic is set")),
            }
            return CmdResult::Ok;
        }
        let on = s
            .users
            .get(&uid)
            .map(|u| u.channels.contains(&key))
            .unwrap_or(false);
        if !on {
            s.numeric(
                uid,
                ERR_NOTONCHANNEL,
                &format!("{target} :You're not on that channel"),
            );
            return CmdResult::Fail;
        }
        // +t: only ops may set the topic
        if s.channels[&key].modes.topic_ops && !s.is_op(uid, &key) {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{target} :You're not a channel operator"),
            );
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
        let tline = format!(":{prefix} TOPIC {target} :{text}");
        crate::modules::chathistory::record_event(s, &key, &tline);
        s.to_channel(&key, &tline, None);
        s.propagate_topic(uid, target, &text); // tell links
        CmdResult::Ok
    }
}

struct Names;
impl Command for Names {
    fn name(&self) -> &'static str {
        "NAMES"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        for target in params[0].split(',').filter(|x| !x.is_empty()) {
            s.send_names(uid, &target.to_ascii_lowercase());
        }
        CmdResult::Ok
    }
}
