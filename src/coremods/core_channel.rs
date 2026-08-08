//! core_channel — channel membership commands: JOIN, PART, KICK, TOPIC, NAMES.

use crate::channels::{Topic, RANK_HALFOP};
use crate::command::{CmdResult, Command};
use crate::module::Hook;
use crate::numeric::*;
use crate::server::{now, Server};
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(Join),
        Box::new(Part),
        Box::new(Kick),
        Box::new(TopicCmd),
        Box::new(Names),
        Box::new(Invite),
        Box::new(Knock),
        Box::new(Cycle),
        Box::new(Remove),
    ]
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
        s.to_channel(
            &key,
            &format!(
                ":{} NOTICE {chan} :[Knock] {who} is knocking: {reason}",
                s.name
            ),
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
        s.channels.retain(|_, c| !c.is_empty());
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
        s.channels.retain(|_, c| !c.is_empty());
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
        // only ops may invite into an +i channel
        if s.channels[&key].modes.invite_only && !s.is_op(uid, &key) {
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
        if s.channels[&key].members.contains_key(&tuid) {
            s.numeric(
                uid,
                ERR_USERONCHANNEL,
                &format!("{tnick} {chan} :is already on channel"),
            );
            return CmdResult::Fail;
        }
        if let Some(ch) = s.channels.get_mut(&key) {
            ch.invites.insert(tuid);
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
            let key = target.to_ascii_lowercase();
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
                continue;
            }
            let prefix = s.users[&uid].prefix();
            let line = if reason.is_empty() {
                format!(":{prefix} PART {target}")
            } else {
                format!(":{prefix} PART {target} :{reason}")
            };
            s.to_channel_vis(&key, &line, uid); // +u: only ops + self see the part
            s.propagate_part(uid, target, &reason); // tell linked servers
            if let Some(ch) = s.channels.get_mut(&key) {
                ch.members.remove(&uid);
            }
            if let Some(u) = s.users.get_mut(&uid) {
                u.channels.remove(&key);
            }
            s.channels.retain(|_, c| !c.is_empty());
            s.events.push_back(Hook::Part(uid, key, reason.clone()));
        }
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
        // can't kick someone who out-ranks you
        if s.rank(uid, &key) < s.rank(tuid, &key) {
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
        s.to_channel(
            &key,
            &format!(":{prefix} KICK {chan} {victim} :{reason}"),
            None,
        );
        s.propagate_from_user(uid, &format!("KICK {chan} {victim} :{reason}")); // tell links
        if let Some(ch) = s.channels.get_mut(&key) {
            ch.members.remove(&tuid);
        }
        if let Some(u) = s.users.get_mut(&tuid) {
            u.channels.remove(&key);
        }
        s.channels.retain(|_, c| !c.is_empty());
        s.events
            .push_back(Hook::Part(tuid, key, "kicked".to_string()));
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
                    s.numeric(uid, RPL_TOPIC, &format!("{target} :{text}"));
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
        s.to_channel(&key, &format!(":{prefix} TOPIC {target} :{text}"), None);
        s.propagate_from_user(uid, &format!("TOPIC {target} :{text}")); // tell links
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
