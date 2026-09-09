//! In-core protocol bridges: relay a channel to/from another chat network with no
//! external appservice or bouncer. The first backend is **Telegram** (pure Bot API
//! over the native `http.rs` async HTTP client). Presentation is currently
//! **relaymsg mode** — a remote sender shows as a spoofed `name/tg` source via the
//! same `send_tagged` path `draft/relaymsg` uses; a future **puppet mode** will
//! introduce real virtual members. The two are kept separable on purpose.
//!
//! Config (one line per bridged channel; token read from a file so it never lives in
//! the config or a repo):
//! ```text
//! bridge = telegram #chan /path/to/token_file <telegram_chat_id>
//! ```
//!
//! Flow, entirely on the existing async-HTTP→`Event::HttpResult` loop:
//! - **IRC → Telegram:** `on_pre_message` on a bridged channel → `spawn_http` POST
//!   `sendMessage`.
//! - **Telegram → IRC:** a self-perpetuating `spawn_http` `getUpdates` long-poll
//!   (tag `bridge:tg:poll:<idx>`); each result injects the message and re-issues the
//!   next poll. Injection uses `send_tagged` (NOT the command path), so it never
//!   re-triggers `on_pre_message` — the relay can't loop.

use crate::module::{ModResult, Module};
use crate::modules::rpc::json;
use crate::server::Server;
use crate::Uid;

/// One bridged channel ⇄ remote room. State lives in `Server.ext` so both the module
/// hooks and the free `on_http_result` fn share it.
struct Route {
    channel: String,      // lowercased key
    channel_disp: String, // original case for wire lines
    token: String,        // Telegram bot token
    chat: String,         // Telegram chat id
    offset: u64,          // next getUpdates offset
    polling: bool,        // a getUpdates is in flight for this route
}

#[derive(Default)]
pub struct BridgeState {
    routes: Vec<Route>,
    loaded: bool,
}

pub struct Bridge;

impl Module for Bridge {
    fn name(&self) -> &'static str {
        "bridge"
    }

    /// IRC → Telegram: forward a local user's channel message to the mapped chat.
    fn on_pre_message(&mut self, srv: &mut Server, uid: Uid, target: &str, text: &str) -> ModResult {
        if text.starts_with('\u{1}') {
            return ModResult::Passthru; // don't bridge CTCP/ACTION for now
        }
        let key = target.to_ascii_lowercase();
        let sender = srv.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        let out = srv.ext.get::<BridgeState>().and_then(|st| {
            st.routes.iter().find(|r| r.channel == key).map(|r| {
                let url = format!("https://api.telegram.org/bot{}/sendMessage", r.token);
                let body = format!(
                    "chat_id={}&text={}",
                    r.chat,
                    crate::http::urlencode(&format!("<{sender}> {text}"))
                );
                (url, body)
            })
        });
        if let Some((url, body)) = out {
            srv.spawn_http(uid, "bridge:tg:out".to_string(), url, body, Vec::new());
        }
        ModResult::Passthru
    }

    /// Load routes on first tick, then keep a getUpdates poll in flight per route.
    fn on_tick(&mut self, srv: &mut Server) {
        if !srv.ext.get::<BridgeState>().map(|s| s.loaded).unwrap_or(false) {
            load_routes(srv);
        }
        // collect the routes needing a poll kicked (immutable borrow), then act
        let kicks: Vec<(usize, String, String, u64)> = srv
            .ext
            .get::<BridgeState>()
            .map(|st| {
                st.routes
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| !r.polling)
                    .map(|(i, r)| (i, r.token.clone(), r.chat.clone(), r.offset))
                    .collect()
            })
            .unwrap_or_default();
        for (idx, token, _chat, offset) in kicks {
            let url = format!("https://api.telegram.org/bot{token}/getUpdates");
            let body = format!("offset={offset}&limit=1&timeout=5&allowed_updates=%5B%22message%22%5D");
            if srv.spawn_http(0, format!("bridge:tg:poll:{idx}"), url, body, Vec::new()) {
                if let Some(st) = srv.ext.get_mut::<BridgeState>() {
                    if let Some(r) = st.routes.get_mut(idx) {
                        r.polling = true;
                    }
                }
            }
        }
    }
}

/// Read `bridge = telegram #chan <token_file> <chat_id>` lines into `BridgeState`.
fn load_routes(srv: &mut Server) {
    // preserve poll offsets across a reload (matched by chat) so we don't re-inject a
    // backlog of already-seen Telegram messages when the config is re-read.
    let prev: std::collections::HashMap<String, u64> = srv
        .ext
        .get::<BridgeState>()
        .map(|st| st.routes.iter().map(|r| (r.chat.clone(), r.offset)).collect())
        .unwrap_or_default();
    let lines: Vec<String> = srv.conf_all("bridge").to_vec();
    let mut routes = Vec::new();
    for line in &lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 || !parts[0].eq_ignore_ascii_case("telegram") {
            continue;
        }
        let (chan, token_file, chat) = (parts[1], parts[2], parts[3]);
        let token = std::fs::read_to_string(token_file)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if token.is_empty() {
            srv.snotice_c('l', &format!("bridge: cannot read token file {token_file} for {chan}"));
            continue;
        }
        srv.snotice_c('l', &format!("bridge: telegram {chan} <-> chat {chat}"));
        routes.push(Route {
            channel: chan.to_ascii_lowercase(),
            channel_disp: chan.to_string(),
            token,
            offset: prev.get(chat).copied().unwrap_or(0),
            chat: chat.to_string(),
            polling: false,
        });
    }
    let st = srv.ext.get_or_insert_with::<BridgeState>(BridgeState::default);
    st.routes = routes;
    st.loaded = true;
}

/// Async HTTP result for a `bridge:tg:*` tag. `detail` is the part after `bridge:tg:`.
pub fn on_http_result(srv: &mut Server, _uid: Uid, detail: &str, _status: u16, body: &str) {
    let Some(idx) = detail.strip_prefix("poll:").and_then(|s| s.parse::<usize>().ok()) else {
        return; // "out" (sendMessage ack) — nothing to do
    };
    // this poll is done; free the slot so the tick can re-issue
    if let Some(st) = srv.ext.get_mut::<BridgeState>() {
        if let Some(r) = st.routes.get_mut(idx) {
            r.polling = false;
        }
    }
    // parse the single update (limit=1) and, if it's for this route's chat, inject it
    let result = json::get_raw(body, "result").unwrap_or_default();
    let Some(update) = first_object(&result) else {
        return; // empty result: no new message
    };
    let update_id: u64 = json::get_num(update, "update_id").unwrap_or(0);
    // advance the offset past this update regardless, so it isn't reprocessed
    let route = srv.ext.get_mut::<BridgeState>().and_then(|st| st.routes.get_mut(idx));
    let Some(route) = route else { return };
    if update_id >= route.offset {
        route.offset = update_id + 1;
    }
    let (channel, channel_disp, chat) =
        (route.channel.clone(), route.channel_disp.clone(), route.chat.clone());

    let Some(message) = json::get_raw(update, "message") else {
        return;
    };
    let text = json::get_str(&message, "text").unwrap_or_default();
    if text.is_empty() {
        return;
    }
    let msg_chat = json::get_raw(&message, "chat")
        .and_then(|c| json::get_raw(&c, "id"))
        .map(|id| id.trim().trim_matches('"').to_string())
        .unwrap_or_default();
    if msg_chat != chat {
        return; // an update for a different chat sharing this bot
    }
    let from = json::get_raw(&message, "from").unwrap_or_default();
    let name = json::get_str(&from, "username")
        .or_else(|| json::get_str(&from, "first_name"))
        .unwrap_or_else(|| "tg".to_string());
    let nick = mangle_nick(&name);
    // a real IRC nick already holding this name → don't spoof over them
    if srv.find_nick(&nick).is_some() || srv.remote_nick.contains_key(&nick.to_ascii_lowercase()) {
        return;
    }
    inject(srv, &channel, &channel_disp, &nick, &text);
}

/// Deliver a bridged message into the channel as a spoofed `name/tg` source, exactly
/// like `draft/relaymsg` (via `send_tagged`, so it never re-enters `on_pre_message`).
fn inject(srv: &mut Server, channel_key: &str, channel_disp: &str, nick: &str, text: &str) {
    let body = format!(":{nick}!telegram@telegram.bridge PRIVMSG {channel_disp} :{text}");
    let ctags = format!("draft/relaymsg={nick}");
    let msgid = srv.next_msgid();
    let members: Vec<Uid> = srv
        .channels
        .get(channel_key)
        .map(|c| c.members.keys().copied().collect())
        .unwrap_or_default();
    for m in members {
        srv.send_tagged(m, 0, &ctags, &msgid, &body);
    }
}

/// Map a remote display name to a valid, relaymsg-style IRC nick: keep sane chars,
/// append the `/tg` network separator (which also makes a collision with a real nick
/// unlikely). Empty → `tg`.
fn mangle_nick(name: &str) -> String {
    let base: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '[' | ']'))
        .take(20)
        .collect();
    let base = if base.is_empty() { "user".to_string() } else { base };
    format!("{base}/tg")
}

/// The first top-level `{...}` object inside a JSON array string, brace-depth + string
/// aware (so text containing `{`/`}`/`]` doesn't fool it). `None` if the array is empty.
fn first_object(arr: &str) -> Option<&str> {
    let b = arr.as_bytes();
    let start = arr.find('{')?;
    let (mut depth, mut in_str, mut esc) = (0i32, false, false);
    for i in start..b.len() {
        let c = b[i];
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&arr[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// BRIDGE — oper: list configured bridges, or `BRIDGE RELOAD` to re-read the config
/// and apply added/changed `bridge` lines without a restart (offsets are preserved).
pub fn commands() -> Vec<Box<dyn crate::command::Command>> {
    vec![Box::new(BridgeCmd)]
}

struct BridgeCmd;
impl crate::command::Command for BridgeCmd {
    fn name(&self) -> &'static str {
        "BRIDGE"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> crate::command::CmdResult {
        use crate::command::CmdResult;
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                crate::numeric::ERR_NOPRIVILEGES,
                ":Permission Denied- BRIDGE is for IRC operators",
            );
            return CmdResult::Fail;
        }
        let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        if params.first().is_some_and(|p| p.eq_ignore_ascii_case("reload")) {
            load_routes(s);
            let n = s.ext.get::<BridgeState>().map(|st| st.routes.len()).unwrap_or(0);
            s.send(uid, format!(":{} NOTICE {nick} :bridge: reloaded {n} route(s)", s.name));
            return CmdResult::Ok;
        }
        let list: Vec<String> = s
            .ext
            .get::<BridgeState>()
            .map(|st| {
                st.routes
                    .iter()
                    .map(|r| {
                        format!(
                            "telegram {} <-> chat {} (offset {}{})",
                            r.channel_disp,
                            r.chat,
                            r.offset,
                            if r.polling { ", polling" } else { "" }
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        if list.is_empty() {
            s.send(uid, format!(":{} NOTICE {nick} :bridge: no routes configured", s.name));
        } else {
            for l in list {
                s.send(uid, format!(":{} NOTICE {nick} :bridge {l}", s.name));
            }
        }
        CmdResult::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mangle_adds_separator_and_sanitises() {
        assert_eq!(mangle_nick("alice"), "alice/tg");
        assert_eq!(mangle_nick(""), "user/tg");
        assert_eq!(mangle_nick("Bob Smith!"), "BobSmith/tg");
        assert!(mangle_nick("Алиса").ends_with("/tg"));
    }

    #[test]
    fn first_object_extracts_single_update() {
        let arr = r#"[{"update_id":42,"message":{"text":"a } b","chat":{"id":-100}}}]"#;
        let obj = first_object(arr).unwrap();
        assert_eq!(json::get_num::<u64>(obj, "update_id"), Some(42));
        let msg = json::get_raw(obj, "message").unwrap();
        assert_eq!(json::get_str(&msg, "text").as_deref(), Some("a } b"));
        assert!(first_object("[]").is_none());
    }
}
