//! multiline — server side of IRCv3 draft/multiline. A client wraps one long message
//! in a `BATCH +<ref> draft/multiline <target>`; the `@batch=<ref>`-tagged
//! PRIVMSG/NOTICE lines are buffered (see `Ircd::dispatch`) and, when `BATCH -<ref>`
//! closes, reassembled (honouring `draft/multiline-concat`) and delivered as normal
//! messages. Limits: multiline_maxbytes / multiline_maxlines. In-flight batches live
//! in `Server.ext`, cleaned up by the on_user_quit hook.

use crate::map::HashMap;

use crate::command::{CmdResult, Command};
use crate::coremods::core_message::deliver;
use crate::module::Module;
use crate::server::Server;
use crate::Uid;

/// Default limits (overridable via `multiline_maxbytes` / `multiline_maxlines`),
/// advertised in the `draft/multiline` cap and enforced while buffering.
pub const MAX_BYTES: usize = 4096;
pub const MAX_LINES: usize = 24;

/// The configured maximum total bytes of one multiline batch.
pub fn max_bytes(s: &Server) -> usize {
    s.conf_num("multiline_maxbytes", MAX_BYTES)
}
/// The configured maximum number of lines in one multiline batch.
pub fn max_lines(s: &Server) -> usize {
    s.conf_num("multiline_maxlines", MAX_LINES)
}

/// An in-progress inbound multiline batch — one long client message being
/// assembled from several `@batch=`-tagged PRIVMSG/NOTICE lines.
pub struct MlineBatch {
    pub bref: String,
    pub target: String,
    pub notice: bool,
    pub parts: Vec<(String, bool)>, // (text, concat-with-previous-part)
    pub bytes: usize,
    pub overflowed: bool, // a line exceeded the byte/line limit — reject the whole batch
}

/// uid -> its open batch. Stored in `Server.ext`.
#[derive(Default)]
pub struct Mline(pub HashMap<Uid, MlineBatch>);

/// Open an inbound batch for `uid` (a client assembling one long message from
/// several tagged PRIVMSG/NOTICE lines).
fn open(s: &mut Server, uid: Uid, bref: &str, target: &str) {
    s.ext.get_or_insert_with::<Mline>(Mline::default).0.insert(
        uid,
        MlineBatch {
            bref: bref.to_string(),
            target: target.to_string(),
            notice: false,
            parts: Vec::new(),
            bytes: 0,
            overflowed: false,
        },
    );
}

/// Buffer one PRIVMSG/NOTICE line into `uid`'s open batch when `bref` matches
/// (bounded by the advertised byte/line limits). Returns true if it was part of
/// the batch — i.e. it should not be delivered on its own. Called from dispatch.
pub fn accumulate(
    s: &mut Server,
    uid: Uid,
    bref: &str,
    notice: bool,
    text: &str,
    concat: bool,
) -> bool {
    let (max_lines, max_bytes) = (max_lines(s), max_bytes(s));
    match s.ext.get_mut::<Mline>().and_then(|m| m.0.get_mut(&uid)) {
        Some(mb) if mb.bref == bref => {
            if mb.parts.len() < max_lines && mb.bytes + text.len() <= max_bytes {
                mb.notice = notice;
                mb.bytes += text.len();
                mb.parts.push((text.to_string(), concat));
            } else {
                // over the byte/line budget — flag so close() rejects the whole batch
                // rather than silently delivering a truncated message.
                mb.overflowed = true;
            }
            true
        }
        _ => false,
    }
}

/// Close `uid`'s batch `bref` and return `(target, is_notice, lines)` with `concat`
/// parts joined into single logical lines. `None` if no match.
fn close(s: &mut Server, uid: Uid, bref: &str) -> Option<(String, bool, Vec<String>)> {
    let store = s.ext.get_mut::<Mline>()?;
    match store.0.get(&uid) {
        Some(mb) if mb.bref == bref => {}
        _ => return None,
    }
    let mb = store.0.remove(&uid)?;
    if mb.overflowed {
        s.fail(
            uid,
            "BATCH",
            "MULTILINE_INVALID",
            "Multiline batch exceeded the size/line limit and was dropped.",
        );
        return None;
    }
    let mut lines: Vec<String> = Vec::new();
    for (text, concat) in mb.parts {
        if concat && !lines.is_empty() {
            lines.last_mut().unwrap().push_str(&text);
        } else {
            lines.push(text);
        }
    }
    Some((mb.target, mb.notice, lines))
}

/// Cleanup hook: drop any half-open batch on disconnect.
pub struct Multiline;
impl Module for Multiline {
    fn name(&self) -> &'static str {
        "multiline"
    }
    fn on_user_quit(&mut self, s: &mut Server, uid: Uid, _reason: &str) {
        if let Some(m) = s.ext.get_mut::<Mline>() {
            m.0.remove(&uid);
        }
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(Batch)]
}

/// BATCH — the client side of draft/multiline. `BATCH +<ref> draft/multiline
/// <target>` opens a batch; the tagged lines are buffered; `BATCH -<ref>` assembles
/// them and delivers each logical line as a normal PRIVMSG/NOTICE.
struct Batch;
impl Command for Batch {
    fn name(&self) -> &'static str {
        "BATCH"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let tag = &params[0];
        if let Some(bref) = tag.strip_prefix('+') {
            if params.get(1).map(|t| t.as_str()) == Some("draft/multiline") {
                let target = params.get(2).cloned().unwrap_or_default();
                open(s, uid, bref, &target);
            }
        } else if let Some(bref) = tag.strip_prefix('-') {
            if let Some((target, notice, lines)) = close(s, uid, bref) {
                for line in lines {
                    deliver(s, uid, &[target.clone(), line], notice);
                }
            }
        }
        CmdResult::Ok
    }
}
