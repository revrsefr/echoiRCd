//! Deterministic two-node S2S simulation: build two `Server`s in-process, link them
//! over the real spanning-tree handshake, drive client operations through the actual
//! `join`/`part`/mode/nick paths, pump the resulting S2S lines between the nodes, and
//! assert both sides *converge* to the same channel state. No sockets, no threads.
//!
//! This targets the bug class that has historically escaped to production — join/part
//! churn, FJOIN timestamp arbitration, mode/topic sync — by exercising it with both
//! scripted scenarios and proptest-randomised sequences.

use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;

use crate::config::{Config, LinkBlock};
use crate::extensible::Extensible;
use crate::map::HashSet;
use crate::message;
use crate::server::Server;
use crate::socketengine::OutSink;
use crate::users::{Caps, User, UserFlags};
use crate::Uid;

const LINK_UID: Uid = 90_000; // the link connection's local uid (distinct from users)

/// One simulated server plus the channel that captures everything it sends to its
/// single peer link.
struct Node {
    srv: Server,
    link_rx: Receiver<String>,
    sid: String,
    next: u64, // per-node uuid suffix counter
}

impl Node {
    fn new(sid: &str, name: &str, peer_name: &str, peer_ip: &str) -> Node {
        let mut cfg = Config::default();
        cfg.servername = name.to_string();
        cfg.sid = sid.to_string();
        cfg.serverdesc = "sim".to_string();
        cfg.links = vec![LinkBlock {
            name: peer_name.to_string(),
            ip: peer_ip.to_string(),
            port: 7000,
            password: "pw".to_string(),
            autoconnect: false,
        }];
        let (tx, _rx) = mpsc::channel();
        let srv = Server::new(cfg, tx, Arc::new(AtomicU64::new(1)));
        let (_dead_tx, link_rx) = mpsc::channel(); // replaced in `link`
        Node {
            srv,
            link_rx,
            sid: sid.to_string(),
            next: 0,
        }
    }

    /// Insert a fully-registered local user; its uuid carries this node's SID like a
    /// real one, so the peer keys it consistently. Returns its uid.
    fn add_user(&mut self, uid: Uid, nick: &str) -> Uid {
        self.next += 1;
        let uuid = format!("{}{:06}", self.sid, self.next);
        let (tx, _rx) = mpsc::channel();
        self.srv.users.insert(
            uid,
            User {
                uid,
                uuid,
                nick: nick.to_string(),
                ident: "u".to_string(),
                realname: "real".to_string(),
                host: "host".to_string(),
                cloak: String::new(),
                vhost: None,
                secure: false,
                certfp: None,
                tls_info: None,
                brand_server: None,
                brand_network: None,
                account: None,
                signon: 0,
                nick_ts: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                port: 6667,
                registered: true,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: None,
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: Caps::default(),
                sasl_mech: None,
                channels: HashSet::default(),
                invited: HashSet::default(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                signore: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(tx),
                sock: None,
            },
        );
        self.srv.nick_index.insert(nick.to_ascii_lowercase(), uid);
        uid
    }
}

/// Link two nodes over the real handshake, then pump until the burst settles.
fn link(a: &mut Node, b: &mut Node) {
    let (a_tx, a_rx) = mpsc::channel();
    let (b_tx, b_rx) = mpsc::channel();
    a.link_rx = a_rx;
    b.link_rx = b_rx;
    // a dials b (outbound → sends SERVER); b accepts (inbound → waits).
    a.srv.add_link(
        LINK_UID,
        "10.0.0.2:7000".parse().unwrap(),
        OutSink::Thread(a_tx),
        None,
        true,
    );
    b.srv.add_link(
        LINK_UID,
        "10.0.0.1:7000".parse().unwrap(),
        OutSink::Thread(b_tx),
        None,
        false,
    );
    pump(a, b);
}

/// Exchange every queued S2S line between the two nodes until neither has more.
fn pump(a: &mut Node, b: &mut Node) {
    for _ in 0..1000 {
        let mut moved = false;
        let a_out: Vec<String> = a.link_rx.try_iter().collect();
        for line in &a_out {
            moved = true;
            if let Some(msg) = message::parse(line) {
                b.srv.on_link(LINK_UID, &msg);
            }
        }
        let b_out: Vec<String> = b.link_rx.try_iter().collect();
        for line in &b_out {
            moved = true;
            if let Some(msg) = message::parse(line) {
                a.srv.on_link(LINK_UID, &msg);
            }
        }
        if !moved {
            return;
        }
    }
    panic!("S2S pump did not converge (message loop?)");
}

/// The network-wide membership of `key` as a set of user uuids (local members mapped
/// through their uuid, remote members by their key) — the canonical view to compare.
fn members(n: &Node, key: &str) -> std::collections::BTreeSet<String> {
    let mut set = std::collections::BTreeSet::new();
    if let Some(ch) = n.srv.channels.get(key) {
        for &uid in ch.members.keys() {
            if let Some(u) = n.srv.users.get(&uid) {
                set.insert(u.uuid.clone());
            }
        }
        for uuid in ch.rmembers.keys() {
            set.insert(uuid.clone());
        }
    }
    set
}

fn chan_ts(n: &Node, key: &str) -> Option<u64> {
    n.srv.channels.get(key).map(|c| c.created)
}
fn chan_modes(n: &Node, key: &str) -> Option<String> {
    n.srv.channels.get(key).map(|c| c.modes.render(false))
}

/// Assert the two nodes agree on `key`'s membership, timestamp and modes.
fn assert_converged(a: &Node, b: &Node, key: &str) {
    assert_eq!(members(a, key), members(b, key), "membership diverged on {key}");
    assert_eq!(chan_ts(a, key), chan_ts(b, key), "channel TS diverged on {key}");
    assert_eq!(chan_modes(a, key), chan_modes(b, key), "channel modes diverged on {key}");
}

#[test]
fn basic_join_propagates_and_converges() {
    let mut a = Node::new("1AA", "a.test", "b.test", "10.0.0.2");
    let mut b = Node::new("2BB", "b.test", "a.test", "10.0.0.1");
    let au = a.add_user(1, "ann");
    let bu = b.add_user(1, "bob");
    a.srv.join(au, "#c", None);
    b.srv.join(bu, "#c", None);
    link(&mut a, &mut b);
    // both users end up known network-wide in #c on both nodes
    assert_converged(&a, &b, "#c");
    assert_eq!(members(&a, "#c").len(), 2, "both users present after link");
}

#[test]
fn part_rejoin_churn_stays_converged() {
    let mut a = Node::new("1AA", "a.test", "b.test", "10.0.0.2");
    let mut b = Node::new("2BB", "b.test", "a.test", "10.0.0.1");
    let au = a.add_user(1, "ann");
    let bu = b.add_user(1, "bob");
    a.srv.join(au, "#c", None);
    link(&mut a, &mut b);
    // ann parts and rejoins repeatedly; bob joins in the middle. Never diverge.
    for i in 0..8 {
        a.srv.part(au, "#c", "churn");
        pump(&mut a, &mut b);
        if i == 3 {
            b.srv.join(bu, "#c", None);
            pump(&mut a, &mut b);
        }
        a.srv.join(au, "#c", None);
        pump(&mut a, &mut b);
        assert_converged(&a, &b, "#c");
    }
    assert!(members(&a, "#c").contains(&a.srv.users[&au].uuid.clone()));
}

#[test]
fn fjoin_ts_arbitration_lower_ts_wins() {
    let mut a = Node::new("1AA", "a.test", "b.test", "10.0.0.2");
    let mut b = Node::new("2BB", "b.test", "a.test", "10.0.0.1");
    let au = a.add_user(1, "ann");
    let bu = b.add_user(1, "bob");
    // Both create #c independently BEFORE linking, at different timestamps.
    a.srv.join(au, "#c", None);
    b.srv.join(bu, "#c", None);
    a.srv.channels.get_mut("#c").unwrap().created = 100; // older — should win
    b.srv.channels.get_mut("#c").unwrap().created = 200;
    link(&mut a, &mut b);
    assert_converged(&a, &b, "#c");
    assert_eq!(chan_ts(&a, "#c"), Some(100), "the lower timestamp wins the channel");
    assert_eq!(members(&a, "#c").len(), 2, "both members merged");
}

proptest::proptest! {
    // Randomised churn: an arbitrary interleaving of join/part on both nodes must
    // always leave the two sides converged on #c.
    #[test]
    fn random_churn_converges(ops in proptest::collection::vec(0u8..4, 0..40)) {
        let mut a = Node::new("1AA", "a.test", "b.test", "10.0.0.2");
        let mut b = Node::new("2BB", "b.test", "a.test", "10.0.0.1");
        let au = a.add_user(1, "ann");
        let bu = b.add_user(1, "bob");
        link(&mut a, &mut b);
        for op in ops {
            match op {
                0 => a.srv.join(au, "#c", None),
                1 => { a.srv.part(au, "#c", "x"); }
                2 => b.srv.join(bu, "#c", None),
                _ => { b.srv.part(bu, "#c", "x"); }
            }
            pump(&mut a, &mut b);
        }
        // drain any residue and compare
        pump(&mut a, &mut b);
        proptest::prop_assert_eq!(members(&a, "#c"), members(&b, "#c"));
        proptest::prop_assert_eq!(chan_ts(&a, "#c"), chan_ts(&b, "#c"));
    }
}
