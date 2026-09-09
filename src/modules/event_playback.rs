//! draft/event-playback — replay channel *events* (JOIN/PART/QUIT/NICK/MODE/TOPIC/
//! KICK) in CHATHISTORY, interleaved with messages, for clients that negotiate the
//! cap. Without it, history stays messages-only (the classic behaviour).
//!
//! Events are recorded into the same per-conversation ring as messages
//! ([`crate::modules::chathistory::record_event`]) and replayed verbatim; the CHATHISTORY
//! command and the `+H` join-backlog filter them out for clients lacking the cap.
//! JOIN/PART/QUIT are captured here through the module lifecycle hooks; NICK/MODE/TOPIC/
//! KICK have no hook, so they call `record_event` directly from their command paths.
//! The whole feature is gated by `event_playback` (default on) inside `record_event`.

use crate::module::Module;
use crate::modules::chathistory::record_event;
use crate::server::Server;
use crate::Uid;

pub struct EventPlayback;

impl Module for EventPlayback {
    fn name(&self) -> &'static str {
        "event-playback"
    }

    fn on_join(&mut self, srv: &mut Server, uid: Uid, chan: &str) {
        let Some(prefix) = srv.users.get(&uid).map(|u| u.prefix()) else {
            return;
        };
        let key = chan.to_ascii_lowercase();
        record_event(srv, &key, &format!(":{prefix} JOIN {chan}"));
    }

    fn on_part(&mut self, srv: &mut Server, uid: Uid, chan: &str, reason: &str) {
        let Some(prefix) = srv.users.get(&uid).map(|u| u.prefix()) else {
            return;
        };
        let key = chan.to_ascii_lowercase();
        let line = if reason.is_empty() {
            format!(":{prefix} PART {chan}")
        } else {
            format!(":{prefix} PART {chan} :{reason}")
        };
        record_event(srv, &key, &line);
    }

    fn on_user_quit(&mut self, srv: &mut Server, uid: Uid, reason: &str) {
        // A QUIT isn't channel-scoped on the wire, so mirror it into every channel the
        // user still shares — that's where a scrolling client expects to see it.
        let Some((prefix, chans)) = srv.users.get(&uid).map(|u| {
            (
                u.prefix(),
                u.channels.iter().cloned().collect::<Vec<String>>(),
            )
        }) else {
            return;
        };
        let line = format!(":{prefix} QUIT :{reason}");
        for key in chans {
            record_event(srv, &key, &line);
        }
    }
}
