//! metricslog — the `draft/metrics` capability and the `METRICS` oper command.
//! Delivers the server's counters/gauges (the same data the OpenMetrics scrape
//! endpoint exposes) as a single structured JSON object over IRC — the same spirit as
//! `draft/json-log`. Two ways to get it: send `METRICS` (oper) for an on-demand
//! snapshot, or negotiate `draft/metrics` to be pushed one every `metrics_push_interval`
//! seconds. The JSON is the NOTICE body; a `draft/metrics` client also gets it as a
//! `draft/metrics=<json>` message tag so tooling can parse it without splitting the line.

use crate::command::{CmdResult, Command};
use crate::module::Module;
use crate::server::Server;
use crate::Uid;

#[derive(Default)]
pub struct MetricsLog {
    last_push: u64,
}

impl Module for MetricsLog {
    fn name(&self) -> &'static str {
        "metricslog"
    }
    fn description(&self) -> &'static str {
        "draft/metrics cap + METRICS command: server counters/gauges as JSON over IRC"
    }

    /// Push the snapshot to subscribed opers every `metrics_push_interval` seconds
    /// (0 disables the push; the `METRICS` command still works).
    fn on_tick(&mut self, srv: &mut Server) {
        let interval: u64 = srv.conf_num("metrics_push_interval", 60u64);
        if interval == 0 {
            return;
        }
        let now = crate::server::now();
        if now.saturating_sub(self.last_push) < interval {
            return;
        }
        self.last_push = now;
        let subs: Vec<Uid> = srv
            .users
            .iter()
            .filter(|(_, u)| u.flags.oper && u.caps.metrics)
            .map(|(&u, _)| u)
            .collect();
        for uid in subs {
            deliver(srv, uid);
        }
    }
}

/// The `METRICS` command.
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(MetricsCmd)]
}

struct MetricsCmd;
impl Command for MetricsCmd {
    fn name(&self) -> &'static str {
        "METRICS"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                crate::numeric::ERR_NOPRIVILEGES,
                ":Permission Denied- METRICS is for IRC operators",
            );
            return CmdResult::Fail;
        }
        deliver(s, uid);
        CmdResult::Ok
    }
}

/// Send the current metrics snapshot to `uid` as a NOTICE whose body is the JSON;
/// a `draft/metrics` client additionally gets it as a `draft/metrics=<json>` tag.
fn deliver(s: &mut Server, uid: Uid) {
    let json = crate::modules::metrics::snapshot_json(&crate::modules::metrics::handle(), &s.name);
    let Some(u) = s.users.get(&uid) else {
        return;
    };
    let nick = u.nick.clone();
    let server_time = u.caps.server_time;
    let want_tag = u.caps.message_tags && u.caps.metrics;
    let mut tags: Vec<String> = Vec::new();
    if server_time {
        tags.push(format!(
            "time={}",
            crate::server::iso_time(crate::server::now())
        ));
    }
    if want_tag {
        tags.push(format!(
            "draft/metrics={}",
            crate::modules::jsonlog::escape_tag(&json)
        ));
    }
    let base = format!(":{} NOTICE {nick} :{json}", s.name);
    let line = if tags.is_empty() {
        base
    } else {
        format!("@{} {base}", tags.join(";"))
    };
    s.send(uid, line);
}
