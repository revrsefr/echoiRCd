//! In-core protocol bridges: relay a channel to/from another chat network with no
//! external appservice or bouncer. Backends: **Telegram** (Bot API), **Matrix**
//! (client-server API) — both over the native async `http.rs` client — and **XMPP**
//! MUC (a persistent TLS XML-stream client, `crate::xmpp`).
//!
//! Two presentation modes, chosen per bridged channel:
//! - **relay** (default) — a remote sender shows as a spoofed `name/<net>` source via
//!   the `draft/relaymsg` `send_tagged` path. Zero per-sender state.
//! - **puppet** (`mode=puppet`) — each remote sender becomes a REAL virtual member
//!   (`mint_puppet`: socket-less +B user, nick `name[<net>]`), visible in WHO/NAMES;
//!   idle puppets are parted after `bridge_puppet_idle` seconds.
//!
//! Config (one line per bridged channel; every credential is read from a FILE so it
//! never lives in the config or a repo):
//! ```text
//! bridge = telegram #chan /path/token_file  <chat_id>            [mode=puppet]
//! bridge = matrix   #chan /path/cred_file   <!roomid:server>     [mode=puppet]
//! bridge = xmpp     #chan /path/cred_file   <room@conf.server>   [nick] [mode=puppet] [server=host:port]
//! ```
//! Telegram cred file = the bot token. Matrix cred file = homeserver URL on line 1,
//! access token on line 2. XMPP cred file = bare JID on line 1, password on line 2,
//! optional `host:port` on line 3.
//!
//! Injection always uses `send_tagged`/puppet paths (NOT the command path), so a
//! bridged message never re-enters `on_pre_message` — the bridge cannot loop.

use crate::module::{ModResult, Module};
use crate::modules::rpc::json;
use crate::server::Server;
use crate::Uid;
use std::collections::HashMap;

/// Which network a route bridges — supplies the relay separator, puppet host/ident and
/// display label so the delivery helpers stay backend-agnostic.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Net {
    Telegram,
    Matrix,
    Xmpp,
}
impl Net {
    fn sep(self) -> &'static str {
        match self {
            Net::Telegram => "tg",
            Net::Matrix => "mx",
            Net::Xmpp => "xmpp",
        }
    }
    fn host(self) -> &'static str {
        match self {
            Net::Telegram => "telegram.bridge",
            Net::Matrix => "matrix.bridge",
            Net::Xmpp => "xmpp.bridge",
        }
    }
    fn ident(self) -> &'static str {
        match self {
            Net::Telegram => "telegram",
            Net::Matrix => "matrix",
            Net::Xmpp => "xmpp",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Net::Telegram => "Telegram",
            Net::Matrix => "Matrix",
            Net::Xmpp => "XMPP",
        }
    }
}

/// Per-backend transport state.
enum Transport {
    Telegram {
        token: String,
        chat: String,
        offset: u64,   // next getUpdates offset
        polling: bool, // a getUpdates is in flight
    },
    Matrix {
        base: String,    // homeserver base URL, e.g. https://matrix.org
        token: String,   // access token
        room: String,    // internal room id (!abc:server)
        since: String,   // sync token; empty = not yet primed
        syncing: bool,   // a /sync is in flight
        txn: u64,        // send transaction counter
        self_id: String, // our own mxid, to suppress echoing our sends back
    },
    Xmpp {
        out: std::sync::mpsc::Sender<String>, // IRC -> XMPP worker
        room: String,                         // MUC room jid (display)
    },
}

/// One bridged channel ⇄ remote room.
struct Route {
    channel: String,      // irc key, lowercased
    channel_disp: String, // original case for wire lines
    net: Net,
    puppet: bool,
    puppets: HashMap<String, (Uid, u64)>, // remote sender -> (puppet uid, last_active)
    transport: Transport,
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

    /// IRC → remote: forward a local user's channel message to the mapped network.
    fn on_pre_message(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        target: &str,
        text: &str,
    ) -> ModResult {
        if text.starts_with('\u{1}') {
            return ModResult::Passthru; // don't bridge CTCP/ACTION for now
        }
        let key = target.to_ascii_lowercase();
        let sender = srv
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        // Build the outbound request inside a scoped &mut borrow (Matrix bumps its txn,
        // XMPP hands the line straight to its worker channel), then act on `srv`.
        let req = {
            let Some(st) = srv.ext.get_mut::<BridgeState>() else {
                return ModResult::Passthru;
            };
            let Some(r) = st.routes.iter_mut().find(|r| r.channel == key) else {
                return ModResult::Passthru;
            };
            let framed = format!("<{sender}> {text}");
            match &mut r.transport {
                Transport::Telegram { token, chat, .. } => {
                    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
                    let body = format!("chat_id={}&text={}", chat, crate::http::urlencode(&framed));
                    Some(SendReq::Post { url, body })
                }
                Transport::Matrix {
                    base,
                    token,
                    room,
                    txn,
                    ..
                } => {
                    *txn = txn.wrapping_add(1);
                    let url = format!(
                        "{base}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
                        crate::http::urlencode(room),
                        txn
                    );
                    let body = format!(
                        "{{\"msgtype\":\"m.text\",\"body\":{}}}",
                        json_quote(&framed)
                    );
                    Some(SendReq::MatrixPut {
                        url,
                        token: token.clone(),
                        body,
                    })
                }
                Transport::Xmpp { out, .. } => {
                    let _ = out.send(framed);
                    None
                }
            }
        };
        match req {
            Some(SendReq::Post { url, body }) => {
                srv.spawn_http(uid, "bridge:tg:out".into(), url, body, Vec::new());
            }
            Some(SendReq::MatrixPut { url, token, body }) => {
                let headers = vec![("Authorization".into(), format!("Bearer {token}"))];
                srv.spawn_http_full(
                    uid,
                    "bridge:mx:out".into(),
                    "PUT".into(),
                    url,
                    "application/json".into(),
                    body,
                    headers,
                );
            }
            None => {}
        }
        ModResult::Passthru
    }

    /// Load routes on first tick, then keep a poll in flight per HTTP-polled route.
    fn on_tick(&mut self, srv: &mut Server) {
        if !srv
            .ext
            .get::<BridgeState>()
            .map(|s| s.loaded)
            .unwrap_or(false)
        {
            load_routes(srv);
        }
        // Telegram getUpdates long-poll (one in flight per route).
        let tg_kicks: Vec<(usize, String, u64)> = srv
            .ext
            .get::<BridgeState>()
            .map(|st| {
                st.routes
                    .iter()
                    .enumerate()
                    .filter_map(|(i, r)| match &r.transport {
                        Transport::Telegram {
                            token,
                            offset,
                            polling: false,
                            ..
                        } => Some((i, token.clone(), *offset)),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (idx, token, offset) in tg_kicks {
            let url = format!("https://api.telegram.org/bot{token}/getUpdates");
            let body =
                format!("offset={offset}&limit=1&timeout=5&allowed_updates=%5B%22message%22%5D");
            if srv.spawn_http(0, format!("bridge:tg:poll:{idx}"), url, body, Vec::new()) {
                if let Some(st) = srv.ext.get_mut::<BridgeState>() {
                    if let Some(Transport::Telegram { polling, .. }) =
                        st.routes.get_mut(idx).map(|r| &mut r.transport)
                    {
                        *polling = true;
                    }
                }
            }
        }
        // Matrix /sync long-poll (one in flight per route). An empty `since` primes the
        // token only (backlog skipped in mx_sync); after that it's incremental.
        let mx_kicks: Vec<(usize, String, String, String)> = srv
            .ext
            .get::<BridgeState>()
            .map(|st| {
                st.routes
                    .iter()
                    .enumerate()
                    .filter_map(|(i, r)| match &r.transport {
                        Transport::Matrix {
                            base,
                            token,
                            since,
                            syncing: false,
                            ..
                        } => Some((i, base.clone(), token.clone(), since.clone())),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (idx, base, token, since) in mx_kicks {
            let url = if since.is_empty() {
                format!(
                    "{base}/_matrix/client/v3/sync?timeout=0&filter={}",
                    crate::http::urlencode("{\"room\":{\"timeline\":{\"limit\":1}}}")
                )
            } else {
                format!(
                    "{base}/_matrix/client/v3/sync?timeout=5000&since={}",
                    crate::http::urlencode(&since)
                )
            };
            let headers = vec![("Authorization".into(), format!("Bearer {token}"))];
            if srv.spawn_http_full(
                0,
                format!("bridge:mx:sync:{idx}"),
                "GET".into(),
                url,
                "application/json".into(),
                String::new(),
                headers,
            ) {
                if let Some(st) = srv.ext.get_mut::<BridgeState>() {
                    if let Some(Transport::Matrix { syncing, .. }) =
                        st.routes.get_mut(idx).map(|r| &mut r.transport)
                    {
                        *syncing = true;
                    }
                }
            }
        }
        // reap puppets idle past the timeout (default 1h): quit them; they rejoin on the
        // sender's next message.
        let timeout: u64 = srv.conf_num("bridge_puppet_idle", 3600u64);
        let now_s = crate::server::now();
        let dead: Vec<(usize, String, Uid)> = srv
            .ext
            .get::<BridgeState>()
            .map(|st| {
                st.routes
                    .iter()
                    .enumerate()
                    .flat_map(|(i, r)| {
                        r.puppets
                            .iter()
                            .filter(move |(_, (_, last))| now_s.saturating_sub(*last) > timeout)
                            .map(move |(k, (u, _))| (i, k.clone(), *u))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (i, key, u) in dead {
            srv.remove_user(u, "Idle bridge puppet");
            if let Some(st) = srv.ext.get_mut::<BridgeState>() {
                if let Some(r) = st.routes.get_mut(i) {
                    r.puppets.remove(&key);
                }
            }
        }
    }
}

enum SendReq {
    Post {
        url: String,
        body: String,
    },
    MatrixPut {
        url: String,
        token: String,
        body: String,
    },
}

/// Parse the `bridge` config lines into `BridgeState`. Quits existing puppets (they
/// rejoin on the next message) and stops old XMPP workers (their route — and its
/// outbound channel — is dropped), preserving Telegram offsets / Matrix sync tokens.
fn load_routes(srv: &mut Server) {
    let old_puppets: Vec<Uid> = srv
        .ext
        .get::<BridgeState>()
        .map(|st| {
            st.routes
                .iter()
                .flat_map(|r| r.puppets.values().map(|(u, _)| *u))
                .collect()
        })
        .unwrap_or_default();
    for u in old_puppets {
        srv.remove_user(u, "bridge reload");
    }
    // preserve poll state across a reload so we don't re-inject already-seen messages
    let (prev_off, prev_since, prev_self): (
        HashMap<String, u64>,
        HashMap<String, String>,
        HashMap<String, String>,
    ) = srv
        .ext
        .get::<BridgeState>()
        .map(|st| {
            let mut off = HashMap::new();
            let mut since = HashMap::new();
            let mut me = HashMap::new();
            for r in &st.routes {
                match &r.transport {
                    Transport::Telegram { chat, offset, .. } => {
                        off.insert(chat.clone(), *offset);
                    }
                    Transport::Matrix {
                        room,
                        since: s,
                        self_id,
                        ..
                    } => {
                        since.insert(room.clone(), s.clone());
                        me.insert(room.clone(), self_id.clone());
                    }
                    Transport::Xmpp { .. } => {}
                }
            }
            (off, since, me)
        })
        .unwrap_or_default();

    let lines: Vec<String> = srv.conf_all("bridge").to_vec();
    let default_nick = srv
        .conf("bridge_xmpp_nick")
        .unwrap_or("echobridge")
        .to_string();
    let event_tx = srv.event_tx.clone();
    let mut routes = Vec::new();
    for line in &lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let kind = parts[0].to_ascii_lowercase();
        let (chan, credfile, target) = (parts[1], parts[2], parts[3]);
        let puppet = parts[4..]
            .iter()
            .any(|p| p.eq_ignore_ascii_case("mode=puppet"));
        let creds = read_creds(credfile);
        let channel = chan.to_ascii_lowercase();
        let channel_disp = chan.to_string();

        let (net, transport) = match kind.as_str() {
            "telegram" => {
                let Some(token) = creds.first().cloned() else {
                    srv.snotice_c(
                        'l',
                        &format!("bridge: empty token file {credfile} for {chan}"),
                    );
                    continue;
                };
                (
                    Net::Telegram,
                    Transport::Telegram {
                        token,
                        offset: prev_off.get(target).copied().unwrap_or(0),
                        chat: target.to_string(),
                        polling: false,
                    },
                )
            }
            "matrix" => {
                let (Some(base), Some(token)) = (creds.first().cloned(), creds.get(1).cloned())
                else {
                    srv.snotice_c(
                        'l',
                        &format!("bridge: matrix cred file {credfile} needs homeserver + token"),
                    );
                    continue;
                };
                (
                    Net::Matrix,
                    Transport::Matrix {
                        base: base.trim_end_matches('/').to_string(),
                        token,
                        room: target.to_string(),
                        since: prev_since.get(target).cloned().unwrap_or_default(),
                        syncing: false,
                        txn: 0,
                        self_id: prev_self.get(target).cloned().unwrap_or_default(),
                    },
                )
            }
            "xmpp" => {
                let (Some(jid), Some(pass)) = (creds.first().cloned(), creds.get(1).cloned())
                else {
                    srv.snotice_c(
                        'l',
                        &format!("bridge: xmpp cred file {credfile} needs jid + password"),
                    );
                    continue;
                };
                let nick = parts[4..]
                    .iter()
                    .find(|p| !p.contains('='))
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| default_nick.clone());
                let server = parts[4..]
                    .iter()
                    .find_map(|p| p.strip_prefix("server="))
                    .map(|s| s.to_string())
                    .or_else(|| creds.get(2).cloned());
                let (tx, rx) = std::sync::mpsc::channel::<String>();
                crate::xmpp::spawn(crate::xmpp::Config {
                    jid,
                    password: pass,
                    server,
                    room: target.to_string(),
                    nick,
                    channel: channel.clone(),
                    core: event_tx.clone(),
                    rx,
                });
                (
                    Net::Xmpp,
                    Transport::Xmpp {
                        out: tx,
                        room: target.to_string(),
                    },
                )
            }
            _ => continue,
        };
        srv.snotice_c(
            'l',
            &format!(
                "bridge: {kind} {chan} <-> {target} ({})",
                if puppet { "puppet" } else { "relay" }
            ),
        );
        routes.push(Route {
            channel,
            channel_disp,
            net,
            puppet,
            puppets: HashMap::new(),
            transport,
        });
    }
    // kick a whoami for each Matrix route so we can suppress echoing our own sends
    let whoami: Vec<(usize, String, String)> = routes
        .iter()
        .enumerate()
        .filter_map(|(i, r)| match &r.transport {
            Transport::Matrix {
                base,
                token,
                self_id,
                ..
            } if self_id.is_empty() => Some((i, base.clone(), token.clone())),
            _ => None,
        })
        .collect();
    let st = srv
        .ext
        .get_or_insert_with::<BridgeState>(BridgeState::default);
    st.routes = routes;
    st.loaded = true;
    for (idx, base, token) in whoami {
        let url = format!("{base}/_matrix/client/v3/account/whoami");
        let headers = vec![("Authorization".into(), format!("Bearer {token}"))];
        srv.spawn_http_full(
            0,
            format!("bridge:mx:whoami:{idx}"),
            "GET".into(),
            url,
            "application/json".into(),
            String::new(),
            headers,
        );
    }
}

/// Async HTTP result for a `bridge:*` tag. `detail` is the part after `bridge:`, e.g.
/// `tg:poll:0`, `tg:out`, `mx:sync:0`, `mx:whoami:0`, `mx:out`.
pub fn on_http_result(srv: &mut Server, _uid: Uid, detail: &str, _status: u16, body: &str) {
    if let Some(d) = detail.strip_prefix("tg:") {
        tg_result(srv, d, body);
    } else if let Some(d) = detail.strip_prefix("mx:") {
        mx_result(srv, d, body);
    }
}

/// An XMPP worker delivered a groupchat message — inject it into the mapped channel.
pub fn on_bridge_in(srv: &mut Server, channel: &str, sender: &str, text: &str) {
    let key = channel.to_ascii_lowercase();
    let Some((idx, net, puppet, disp)) = srv.ext.get::<BridgeState>().and_then(|st| {
        st.routes
            .iter()
            .enumerate()
            .find(|(_, r)| r.channel == key)
            .map(|(i, r)| (i, r.net, r.puppet, r.channel_disp.clone()))
    }) else {
        return;
    };
    deliver(srv, idx, net, puppet, &key, &disp, sender, text);
}

fn tg_result(srv: &mut Server, detail: &str, body: &str) {
    let Some(idx) = detail
        .strip_prefix("poll:")
        .and_then(|s| s.parse::<usize>().ok())
    else {
        return; // "out" (sendMessage ack) — nothing to do
    };
    if let Some(st) = srv.ext.get_mut::<BridgeState>() {
        if let Some(Transport::Telegram { polling, .. }) =
            st.routes.get_mut(idx).map(|r| &mut r.transport)
        {
            *polling = false;
        }
    }
    let result = json::get_raw(body, "result").unwrap_or_default();
    let Some(update) = first_object(&result) else {
        return;
    };
    let update_id: u64 = json::get_num(update, "update_id").unwrap_or(0);
    let (net, puppet, channel, disp, chat) = {
        let Some(st) = srv.ext.get_mut::<BridgeState>() else {
            return;
        };
        let Some(r) = st.routes.get_mut(idx) else {
            return;
        };
        let Transport::Telegram { offset, chat, .. } = &mut r.transport else {
            return;
        };
        if update_id >= *offset {
            *offset = update_id + 1;
        }
        (
            r.net,
            r.puppet,
            r.channel.clone(),
            r.channel_disp.clone(),
            chat.clone(),
        )
    };
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
    deliver(srv, idx, net, puppet, &channel, &disp, &name, &text);
}

fn mx_result(srv: &mut Server, detail: &str, body: &str) {
    if let Some(i) = detail
        .strip_prefix("whoami:")
        .and_then(|s| s.parse::<usize>().ok())
    {
        let id = json::get_str(body, "user_id").unwrap_or_default();
        if !id.is_empty() {
            if let Some(st) = srv.ext.get_mut::<BridgeState>() {
                if let Some(Transport::Matrix { self_id, .. }) =
                    st.routes.get_mut(i).map(|r| &mut r.transport)
                {
                    *self_id = id;
                }
            }
        }
        return;
    }
    let Some(idx) = detail
        .strip_prefix("sync:")
        .and_then(|s| s.parse::<usize>().ok())
    else {
        return; // "out" (send ack)
    };
    let (net, puppet, channel, disp, room, self_id, had_since) = {
        let Some(st) = srv.ext.get_mut::<BridgeState>() else {
            return;
        };
        let Some(r) = st.routes.get_mut(idx) else {
            return;
        };
        let Transport::Matrix {
            since,
            syncing,
            room,
            self_id,
            ..
        } = &mut r.transport
        else {
            return;
        };
        *syncing = false;
        let had_since = !since.is_empty();
        if let Some(next) = json::get_str(body, "next_batch") {
            if !next.is_empty() {
                *since = next;
            }
        }
        (
            r.net,
            r.puppet,
            r.channel.clone(),
            r.channel_disp.clone(),
            room.clone(),
            self_id.clone(),
            had_since,
        )
    };
    if !had_since {
        return; // first sync just primed the token — skip backlog
    }
    let rooms = json::get_raw(body, "rooms").unwrap_or_default();
    let join = json::get_raw(&rooms, "join").unwrap_or_default();
    let roomobj = json::get_raw(&join, &room).unwrap_or_default();
    let timeline = json::get_raw(&roomobj, "timeline").unwrap_or_default();
    let events = json::get_raw(&timeline, "events").unwrap_or_default();
    for ev in objects(&events) {
        if json::get_str(ev, "type").as_deref() != Some("m.room.message") {
            continue;
        }
        let s = json::get_str(ev, "sender").unwrap_or_default();
        if !self_id.is_empty() && s == self_id {
            continue; // our own send, echoed back by /sync
        }
        let content = json::get_raw(ev, "content").unwrap_or_default();
        if json::get_str(&content, "msgtype").as_deref() != Some("m.text") {
            continue;
        }
        let text = json::get_str(&content, "body").unwrap_or_default();
        if text.is_empty() {
            continue;
        }
        deliver(
            srv,
            idx,
            net,
            puppet,
            &channel,
            &disp,
            &mx_display(&s),
            &text,
        );
    }
}

/// Shared inbound delivery: newline-split + control-strip, then relay or puppet.
fn deliver(
    srv: &mut Server,
    idx: usize,
    net: Net,
    puppet: bool,
    channel_key: &str,
    channel_disp: &str,
    name: &str,
    text: &str,
) {
    let lines: Vec<String> = text
        .split(['\n', '\r'])
        .map(clean_line)
        .filter(|l| !l.is_empty())
        .collect();
    if puppet {
        for line in &lines {
            deliver_puppet(srv, idx, net, channel_disp, name, line);
        }
    } else {
        let nick = mangle_nick(name, net.sep());
        if srv.find_nick(&nick).is_none()
            && !srv.remote_nick.contains_key(&nick.to_ascii_lowercase())
        {
            for line in &lines {
                inject(srv, net, channel_key, channel_disp, &nick, line);
            }
        }
    }
}

/// Sanitise one bridged line: drop control bytes (no raw IRC command injection), trim,
/// and cap the length to stay within the 512-byte line budget once the envelope is on.
fn clean_line(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| !c.is_control()).collect();
    let cleaned = cleaned.trim();
    let mut end = cleaned.len().min(400);
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    cleaned[..end].to_string()
}

/// Puppet mode: find (or mint+join) a virtual member for this remote sender, then speak.
fn deliver_puppet(
    srv: &mut Server,
    idx: usize,
    net: Net,
    chan_disp: &str,
    sender: &str,
    text: &str,
) {
    let now_s = crate::server::now();
    let existing = srv
        .ext
        .get::<BridgeState>()
        .and_then(|st| st.routes.get(idx))
        .and_then(|r| r.puppets.get(sender).map(|(u, _)| *u));
    let puid = match existing {
        Some(u) if srv.users.contains_key(&u) => u,
        _ => {
            let pnick = mangle_puppet_nick(sender, net.sep());
            if srv.find_nick(&pnick).is_some()
                || srv.remote_nick.contains_key(&pnick.to_ascii_lowercase())
            {
                return; // a real/remote user holds this nick — skip rather than clash
            }
            let realname = format!("{sender} (via {})", net.label());
            let u = srv.mint_puppet(&pnick, net.ident(), net.host(), &realname);
            srv.puppet_join(u, chan_disp);
            if let Some(st) = srv.ext.get_mut::<BridgeState>() {
                if let Some(r) = st.routes.get_mut(idx) {
                    r.puppets.insert(sender.to_string(), (u, now_s));
                }
            }
            u
        }
    };
    srv.puppet_speak(puid, chan_disp, text);
    if let Some(st) = srv.ext.get_mut::<BridgeState>() {
        if let Some(r) = st.routes.get_mut(idx) {
            if let Some(e) = r.puppets.get_mut(sender) {
                e.1 = now_s;
            }
        }
    }
}

/// Relay-mode injection: a spoofed `name/<net>` source via `send_tagged` (never
/// re-enters `on_pre_message`), like `draft/relaymsg`.
fn inject(
    srv: &mut Server,
    net: Net,
    channel_key: &str,
    channel_disp: &str,
    nick: &str,
    text: &str,
) {
    let body = format!(
        ":{nick}!{}@{} PRIVMSG {channel_disp} :{text}",
        net.ident(),
        net.host()
    );
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

/// Read a credential file into trimmed non-comment lines.
fn read_creds(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|s| {
            s.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect()
        })
        .unwrap_or_default()
}

/// Relay nick: sanitised base + `/<net>` separator (unlikely to collide with a real
/// nick). Empty → `user`.
fn mangle_nick(name: &str, sep: &str) -> String {
    let base: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '[' | ']'))
        .take(20)
        .collect();
    let base = if base.is_empty() {
        "user".to_string()
    } else {
        base
    };
    format!("{base}/{sep}")
}

/// Puppet nick: a real RFC-valid nick with a `[<net>]` provenance suffix.
fn mangle_puppet_nick(name: &str, tag: &str) -> String {
    let base: String = name
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '`' | '^' | '{' | '}' | '|')
        })
        .take(16)
        .collect();
    let base = if base.is_empty() {
        "user".to_string()
    } else {
        base
    };
    format!("{base}[{tag}]")
}

/// `@user:server` → `user`.
fn mx_display(mxid: &str) -> String {
    let s = mxid.strip_prefix('@').unwrap_or(mxid);
    s.split(':').next().unwrap_or(s).to_string()
}

/// Escape a string as a JSON string literal (including the surrounding quotes).
fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The first top-level `{...}` object in a JSON array string. `None` if empty.
fn first_object(arr: &str) -> Option<&str> {
    objects(arr).into_iter().next()
}

/// All top-level `{...}` objects in a JSON array string, brace-depth + string aware.
fn objects(arr: &str) -> Vec<&str> {
    let b = arr.as_bytes();
    let mut out = Vec::new();
    let (mut depth, mut in_str, mut esc, mut start) = (0i32, false, false, 0usize);
    for (i, &c) in b.iter().enumerate() {
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
            b'{' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    out.push(&arr[start..=i]);
                }
            }
            _ => {}
        }
    }
    out
}

/// BRIDGE — oper: list configured bridges, or `BRIDGE RELOAD` to re-read the config
/// and apply added/changed `bridge` lines without a restart.
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
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        if params
            .first()
            .is_some_and(|p| p.eq_ignore_ascii_case("reload"))
        {
            load_routes(s);
            let n = s
                .ext
                .get::<BridgeState>()
                .map(|st| st.routes.len())
                .unwrap_or(0);
            s.send(
                uid,
                format!(":{} NOTICE {nick} :bridge: reloaded {n} route(s)", s.name),
            );
            return CmdResult::Ok;
        }
        let list: Vec<String> = s
            .ext
            .get::<BridgeState>()
            .map(|st| {
                st.routes
                    .iter()
                    .map(|r| {
                        let (kind, target, extra) = match &r.transport {
                            Transport::Telegram {
                                chat,
                                offset,
                                polling,
                                ..
                            } => (
                                "telegram",
                                chat.clone(),
                                format!(
                                    "offset {offset}{}",
                                    if *polling { ", polling" } else { "" }
                                ),
                            ),
                            Transport::Matrix { room, syncing, .. } => (
                                "matrix",
                                room.clone(),
                                if *syncing {
                                    "syncing".into()
                                } else {
                                    "idle".into()
                                },
                            ),
                            Transport::Xmpp { room, .. } => ("xmpp", room.clone(), "live".into()),
                        };
                        format!(
                            "{kind} {} <-> {target} [{}] ({extra}{})",
                            r.channel_disp,
                            if r.puppet { "puppet" } else { "relay" },
                            if r.puppet {
                                format!(", {} puppet(s)", r.puppets.len())
                            } else {
                                String::new()
                            }
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        if list.is_empty() {
            s.send(
                uid,
                format!(":{} NOTICE {nick} :bridge: no routes configured", s.name),
            );
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
        assert_eq!(mangle_nick("alice", "tg"), "alice/tg");
        assert_eq!(mangle_nick("", "mx"), "user/mx");
        assert_eq!(mangle_nick("Bob Smith!", "tg"), "BobSmith/tg");
        assert!(mangle_nick("Алиса", "xmpp").ends_with("/xmpp"));
    }

    #[test]
    fn puppet_nick_is_rfc_valid_and_marked() {
        assert_eq!(mangle_puppet_nick("alice", "tg"), "alice[tg]");
        assert_eq!(mangle_puppet_nick("", "mx"), "user[mx]");
        assert_eq!(mangle_puppet_nick("Bob Smith!", "tg"), "BobSmith[tg]");
        assert!(!mangle_puppet_nick("anyone", "xmpp").contains('/'));
    }

    #[test]
    fn clean_line_strips_control_bytes() {
        assert_eq!(
            clean_line("hello\r\nPRIVMSG #x :owned"),
            "helloPRIVMSG #x :owned"
        );
        assert_eq!(clean_line("a\0b\x07c"), "abc");
        assert!(clean_line("  spaced  ").starts_with('s'));
        let long = "é".repeat(500);
        let out = clean_line(&long);
        assert!(out.len() <= 400 && out.is_char_boundary(out.len()));
    }

    #[test]
    fn objects_extracts_all_and_first() {
        let arr =
            r#"[{"update_id":42,"message":{"text":"a } b","chat":{"id":-100}}},{"update_id":43}]"#;
        let all = objects(arr);
        assert_eq!(all.len(), 2);
        assert_eq!(json::get_num::<u64>(all[0], "update_id"), Some(42));
        assert_eq!(json::get_num::<u64>(all[1], "update_id"), Some(43));
        assert_eq!(
            json::get_num::<u64>(first_object(arr).unwrap(), "update_id"),
            Some(42)
        );
        assert!(first_object("[]").is_none());
    }

    #[test]
    fn json_quote_escapes() {
        assert_eq!(json_quote("hi \"there\"\n"), "\"hi \\\"there\\\"\\n\"");
        assert_eq!(json_quote("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn mx_display_strips_mxid() {
        assert_eq!(mx_display("@alice:matrix.org"), "alice");
        assert_eq!(mx_display("bob"), "bob");
    }
}
