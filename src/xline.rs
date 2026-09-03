//! X-lines — server bans: KLINE/GLINE on `user@host`, ZLINE on an IP. Matched at
//! registration (a banned client is refused) and when the line is added (matching
//! clients are killed); expired lines are reaped on the tick. Kept in
//! `Server.xlines`.

use crate::channels::glob_match;
use crate::server::{now, Server};
use crate::Uid;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum XKind {
    Kline,   // user@host, this server
    Gline,   // user@host, "global" (locally the same until services span it)
    Zline,   // an IP address
    Eline,   // user@host / ip EXEMPT from K/G/Z-lines
    Shun,    // user@host allowed to connect but whose commands are dropped
    Qline,   // a reserved/forbidden nick glob
    Cban,    // a forbidden channel-name glob
    Svshold, // a services-reserved nick glob (like Qline, but services-owned)
    Rline,   // a regex over "nick!user@host realname"
}

impl XKind {
    pub fn tag(&self) -> &'static str {
        match self {
            XKind::Kline => "K",
            XKind::Gline => "G",
            XKind::Zline => "Z",
            XKind::Eline => "E",
            XKind::Shun => "SHUN",
            XKind::Qline => "Q",
            XKind::Cban => "CBAN",
            XKind::Svshold => "SVSHOLD",
            XKind::Rline => "R",
        }
    }

    /// Inverse of [`tag`], for reloading the on-disk x-line db.
    pub fn from_tag(t: &str) -> Option<XKind> {
        Some(match t {
            "K" => XKind::Kline,
            "G" => XKind::Gline,
            "Z" => XKind::Zline,
            "E" => XKind::Eline,
            "SHUN" => XKind::Shun,
            "Q" => XKind::Qline,
            "CBAN" => XKind::Cban,
            "SVSHOLD" => XKind::Svshold,
            "R" => XKind::Rline,
            _ => return None,
        })
    }
}

pub struct XLine {
    pub kind: XKind,
    pub mask: String, // user@host glob (K/G) or ip glob (Z)
    pub reason: String,
    pub setter: String,
    pub expires: u64, // 0 = permanent
    pub set_at: u64,  // unix time the line was set (0 = unknown — a pre-upgrade db entry)
}

/// Parse a duration: bare number = seconds; `s`/`m`/`h`/`d`/`w` suffixes; `0`/"" = permanent.
pub fn parse_duration(s: &str) -> Option<u64> {
    if s.is_empty() || s == "0" {
        return Some(0);
    }
    let last = s.chars().last()?;
    if last.is_ascii_digit() {
        return s.parse::<u64>().ok();
    }
    // strip the suffix by its char length, not one byte — a multi-byte final char
    // (e.g. "5€") would otherwise slice mid-codepoint and panic
    let n: u64 = s[..s.len() - last.len_utf8()].parse().ok()?;
    let mul = match last {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        'w' => 604800,
        _ => return None,
    };
    Some(n.saturating_mul(mul))
}

/// Render a duration (seconds) as a human phrase — `1 week`, `1 day 2 hours`,
/// `30 minutes` — largest non-zero units first. Used in the XLINE server notice.
pub fn human_duration(mut secs: u64) -> String {
    if secs == 0 {
        return "0 seconds".to_string();
    }
    let mut parts = Vec::new();
    for (size, label) in [
        (604800, "week"),
        (86400, "day"),
        (3600, "hour"),
        (60, "minute"),
        (1, "second"),
    ] {
        let n = secs / size;
        if n > 0 {
            parts.push(format!("{n} {label}{}", if n == 1 { "" } else { "s" }));
            secs -= n * size;
        }
    }
    parts.join(" ")
}

/// "set by X on <date>, duration <dur>" — the provenance shown in the XLINE
/// lifecycle notices, degrading gracefully when the set-time is unknown (a
/// pre-upgrade db entry, `set_at` = 0).
fn xline_origin(setter: &str, set_at: u64, expires: u64) -> String {
    if set_at == 0 {
        return format!("set by {setter}");
    }
    let when = crate::server::long_date(set_at);
    if expires > set_at {
        format!(
            "set by {setter} on {when}, duration {}",
            human_duration(expires - set_at)
        )
    } else {
        format!("set by {setter} on {when}")
    }
}

/// Parse one line of the on-disk x-line db: `tag mask expires [set_at] setter reason`.
/// The optional `set_at` (a decimal, added later) is detected by an all-digit 4th
/// field — a setter is never all-digits — so old-format lines load with `set_at` 0.
fn parse_db_line(line: &str) -> Option<XLine> {
    let mut it = line.split(' ');
    let (tag, mask, exp, fourth) = (it.next()?, it.next()?, it.next()?, it.next()?);
    let kind = XKind::from_tag(tag)?;
    let expires: u64 = exp.parse().unwrap_or(0);
    let (set_at, setter, reason) =
        if !fourth.is_empty() && fourth.bytes().all(|b| b.is_ascii_digit()) {
            (
                fourth.parse().unwrap_or(0),
                it.next()?.to_string(),
                it.collect::<Vec<_>>().join(" "),
            )
        } else {
            (0, fourth.to_string(), it.collect::<Vec<_>>().join(" "))
        };
    if setter.is_empty() {
        return None;
    }
    Some(XLine {
        kind,
        mask: mask.to_string(),
        reason,
        setter,
        expires,
        set_at,
    })
}

/// Schema for the normalized x-line store (used when `store_backend = pgsql`). No
/// primary key: the set is snapshot-replaced wholesale, and a stray duplicate must not
/// abort the transaction.
const XLINES_DDL: &str = "CREATE TABLE IF NOT EXISTS echoircd_xlines \
     (tag text NOT NULL, mask text NOT NULL, expires bigint NOT NULL DEFAULT 0, \
      set_at bigint NOT NULL DEFAULT 0, setter text NOT NULL, reason text NOT NULL)";

/// The " (expires in …)" tail appended to the reason a banned user is shown, or
/// empty for a permanent ban (`expires` is the absolute unix expiry, 0 = permanent).
/// Lets someone who hits a K/G/Z/R-line see when it lifts, not just why.
fn ban_expiry_suffix(expires: u64, now: u64) -> String {
    if expires > now {
        format!(
            " (expires in {} on {})",
            human_duration(expires - now),
            crate::server::long_date(expires)
        )
    } else {
        String::new()
    }
}

impl Server {
    /// Whether an active x-line of `kind` matches this `user@host` / `ip`.
    fn xmatch(&self, kind: XKind, uh: &str, ip: &str) -> bool {
        let n = now();
        self.xlines.iter().any(|x| {
            x.kind == kind
                && (x.expires == 0 || x.expires > n)
                && match kind {
                    XKind::Zline => glob_match(&x.mask, ip),
                    _ => glob_match(&x.mask, uh),
                }
        })
    }

    /// True if this `user@host` / `ip` is E-lined (exempt from all bans).
    pub fn is_exempt(&self, ident: &str, host: &str, ip: &str) -> bool {
        let uh = format!("{ident}@{host}");
        self.xmatch(XKind::Eline, &uh, ip)
    }

    /// True if this `user@host` is SHUN'd (connected but silenced) and not exempt.
    pub fn is_shunned(&self, ident: &str, host: &str, ip: &str) -> bool {
        if self.is_exempt(ident, host, ip) {
            return false;
        }
        let uh = format!("{ident}@{host}");
        self.xmatch(XKind::Shun, &uh, ip)
    }

    /// True if the connected user `uid` is currently SHUN'd.
    pub fn user_shunned(&self, uid: Uid) -> bool {
        self.users
            .get(&uid)
            .map(|u| self.is_shunned(&u.ident, &u.host, &u.addr.ip().to_string()))
            .unwrap_or(false)
    }

    /// The reason nick `nick` is Q-lined (reserved/forbidden), if any.
    pub fn matched_qline(&self, nick: &str) -> Option<String> {
        let n = now();
        self.xlines
            .iter()
            .find(|x| {
                x.kind == XKind::Qline
                    && (x.expires == 0 || x.expires > n)
                    && glob_match(&x.mask, nick)
            })
            .map(|x| x.reason.clone())
    }

    /// The reason nick `nick` is held by services (SVSHOLD), if any.
    pub fn matched_svshold(&self, nick: &str) -> Option<String> {
        let n = now();
        self.xlines
            .iter()
            .find(|x| {
                x.kind == XKind::Svshold
                    && (x.expires == 0 || x.expires > n)
                    && glob_match(&x.mask, nick)
            })
            .map(|x| x.reason.clone())
    }

    /// The reason nick `nick` may not be used — a Q-line or a services SVSHOLD.
    pub fn nick_reserved(&self, nick: &str) -> Option<String> {
        self.matched_qline(nick)
            .or_else(|| self.matched_svshold(nick))
    }

    /// The reason channel `chan` is CBAN'd (forbidden), if any. Case-insensitive.
    pub fn matched_cban(&self, chan: &str) -> Option<String> {
        let n = now();
        let c = chan.to_ascii_lowercase();
        self.xlines
            .iter()
            .find(|x| {
                x.kind == XKind::Cban
                    && (x.expires == 0 || x.expires > n)
                    && glob_match(&x.mask.to_ascii_lowercase(), &c)
            })
            .map(|x| x.reason.clone())
    }

    /// The reason a `user@host` / `ip` is banned by an active x-line, if any.
    /// An E-line (exemption) overrides every K/G/Z-line.
    pub fn matched_xline(&self, ident: &str, host: &str, ip: &str) -> Option<String> {
        if self.is_exempt(ident, host, ip) {
            return None;
        }
        let uh = format!("{ident}@{host}");
        for kind in [XKind::Kline, XKind::Gline, XKind::Zline] {
            if self.xmatch(kind, &uh, ip) {
                let n = now();
                let (reason, expires) = self
                    .xlines
                    .iter()
                    .find(|x| {
                        x.kind == kind
                            && (x.expires == 0 || x.expires > n)
                            && match kind {
                                XKind::Zline => glob_match(&x.mask, ip),
                                _ => glob_match(&x.mask, &uh),
                            }
                    })
                    .map(|x| (x.reason.clone(), x.expires))
                    .unwrap_or_default();
                return Some(format!(
                    "{}-lined: {reason}{}",
                    kind.tag(),
                    ban_expiry_suffix(expires, n)
                ));
            }
        }
        None
    }

    /// The reason an R-line's regex matches this user, if any. RLINE tests the
    /// pattern against both `nick!user@host realname` and the ip form. A stored
    /// pattern that no longer compiles is skipped.
    pub fn matched_rline(
        &self,
        nick: &str,
        ident: &str,
        host: &str,
        ip: &str,
        real: &str,
    ) -> Option<String> {
        let n = now();
        let hostform = format!("{nick}!{ident}@{host} {real}");
        let ipform = format!("{nick}!{ident}@{ip} {real}");
        self.xlines
            .iter()
            .find(|x| {
                x.kind == XKind::Rline
                    && (x.expires == 0 || x.expires > n)
                    && crate::regex::Regex::new(&x.mask)
                        .map(|re| re.is_match(&hostform) || re.is_match(&ipform))
                        .unwrap_or(false)
            })
            .map(|x| format!("R-lined: {}{}", x.reason, ban_expiry_suffix(x.expires, n)))
    }

    /// Kill every registered local user matched by R-line `pattern` (called after an
    /// RLINE is added, since the generic enforce sweep is glob- not regex-based).
    pub fn enforce_rline(&mut self, pattern: &str, reason: &str) {
        let Ok(re) = crate::regex::Regex::new(pattern) else {
            return;
        };
        let victims: Vec<Uid> = self
            .users
            .iter()
            .filter(|(_, u)| u.registered)
            .filter(|(_, u)| {
                let host = format!("{}!{}@{} {}", u.nick, u.ident, u.host, u.realname);
                let ip = format!("{}!{}@{} {}", u.nick, u.ident, u.addr.ip(), u.realname);
                re.is_match(&host) || re.is_match(&ip)
            })
            .map(|(&uid, _)| uid)
            .collect();
        for uid in victims {
            let m = self.trf("Closing link: (R-lined: {0})", &[reason]);
            self.send(uid, format!("ERROR :{m}"));
            self.remove_user(uid, &format!("R-lined: {reason}"));
        }
    }

    /// Add (or replace) an x-line, then kill every connected user it matches.
    pub fn add_xline(
        &mut self,
        kind: XKind,
        mask: &str,
        duration: u64,
        setter: &str,
        reason: &str,
    ) {
        self.add_xline_at(kind, mask, duration, setter, reason, now());
    }

    /// Like [`add_xline`](Self::add_xline) but with an explicit set-time. The S2S
    /// ADDLINE handler passes the wire `settime` so a ban set on a peer keeps its
    /// original set-time (and true age/expiry) instead of our local receive time.
    #[allow(clippy::too_many_arguments)]
    pub fn add_xline_at(
        &mut self,
        kind: XKind,
        mask: &str,
        duration: u64,
        setter: &str,
        reason: &str,
        set_at: u64,
    ) {
        self.xlines.retain(|x| !(x.kind == kind && x.mask == mask));
        let expires = if duration == 0 {
            0
        } else {
            set_at.saturating_add(duration)
        };
        self.xlines.push(XLine {
            kind,
            mask: mask.to_string(),
            reason: reason.to_string(),
            setter: setter.to_string(),
            expires,
            set_at,
        });
        let detail = if duration == 0 {
            format!("permanent {}-line on {mask}", kind.tag())
        } else {
            format!(
                "timed {}-line on {mask}, expires in {} (on {})",
                kind.tag(),
                human_duration(duration),
                crate::server::long_date(expires)
            )
        };
        let m = self.trf(
            "XLINE: {0} added a {1}: {2}",
            &[setter, detail.as_str(), reason],
        );
        self.snotice_c('x', &m);
        self.save_xlines();
        self.enforce_xlines();
    }

    /// Remove an x-line by kind + mask; announces it (snomask +x, like the add) —
    /// reporting how long a timed ban had left to run, so opers see what they cut
    /// short — and returns whether one was found. `remover` is who took it off.
    pub fn remove_xline(&mut self, kind: XKind, mask: &str, remover: &str) -> bool {
        let n = now();
        // capture the target before dropping it, to report the time left plus who
        // originally set it and why
        let target = self
            .xlines
            .iter()
            .find(|x| x.kind == kind && x.mask.eq_ignore_ascii_case(mask))
            .map(|x| (x.expires, x.setter.clone(), x.reason.clone()));
        let before = self.xlines.len();
        // case-insensitive: nick/host/channel masks match case-insensitively when
        // enforced, so removal must too (e.g. remove `CBAN #foo` for a `#Foo` ban).
        self.xlines
            .retain(|x| !(x.kind == kind && x.mask.eq_ignore_ascii_case(mask)));
        let removed = self.xlines.len() < before;
        if removed {
            let tag = kind.tag();
            let (expires, setter, reason) = target.unwrap_or((0, String::new(), String::new()));
            let detail = match expires {
                e if e > n => {
                    format!(
                        "timed {tag}-line on {mask} ({} remaining)",
                        human_duration(e - n)
                    )
                }
                e if e != 0 => format!("timed {tag}-line on {mask} (already expired)"),
                _ => format!("permanent {tag}-line on {mask}"),
            };
            let m = self.trf(
                "XLINE: {0} removed a {1} (set by {2}: {3})",
                &[remover, detail.as_str(), setter.as_str(), reason.as_str()],
            );
            self.snotice_c('x', &m);
            self.save_xlines();
        }
        removed
    }

    /// Kill every connected local user that now matches an active x-line.
    pub fn enforce_xlines(&mut self) {
        let candidates: Vec<(Uid, String, String, String)> = self
            .users
            .iter()
            .filter(|(_, u)| u.registered)
            .map(|(&uid, u)| {
                (
                    uid,
                    u.ident.clone(),
                    u.host.clone(),
                    u.addr.ip().to_string(),
                )
            })
            .collect();
        let victims: Vec<(Uid, String)> = candidates
            .into_iter()
            .filter_map(|(uid, ident, host, ip)| {
                self.matched_xline(&ident, &host, &ip).map(|r| (uid, r))
            })
            .collect();
        for (uid, reason) in victims {
            let m = self.trf("Closing link: ({0})", &[reason.as_str()]);
            self.send(uid, format!("ERROR :{m}"));
            self.remove_user(uid, &reason);
        }
    }

    /// Drop expired x-lines (called on the background tick), announcing each one
    /// (snomask +x) so the XLINE notices cover a ban's whole life: add → expire.
    pub fn purge_xlines(&mut self) {
        let n = now();
        // capture the full record so the "expired" notice can say who set it, when,
        // for how long, and why — not just the bare mask.
        let expired: Vec<(XKind, String, String, String, u64, u64)> = self
            .xlines
            .iter()
            .filter(|x| x.expires != 0 && x.expires <= n)
            .map(|x| {
                (
                    x.kind,
                    x.mask.clone(),
                    x.setter.clone(),
                    x.reason.clone(),
                    x.expires,
                    x.set_at,
                )
            })
            .collect();
        if expired.is_empty() {
            return;
        }
        self.xlines.retain(|x| x.expires == 0 || x.expires > n);
        for (kind, mask, setter, reason, expires, set_at) in &expired {
            let origin = xline_origin(setter, *set_at, *expires);
            let m = self.trf(
                "XLINE: {0}-line on {1} expired ({2}): {3}",
                &[kind.tag(), mask.as_str(), origin.as_str(), reason.as_str()],
            );
            self.snotice_c('x', &m);
        }
        self.save_xlines(); // an expiry changed the set — persist it
    }

    /// Path of the on-disk x-line db: the `xline_database` conf key, or `<conf>.xlines`.
    fn xline_db_path(&self) -> String {
        match self.conf("xline_database") {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => format!("{}.xlines", self.conf_path),
        }
    }

    /// Persist all current x-lines so they survive a restart. With the database backend
    /// each line is a row in `echoircd_xlines` (queryable, atomically snapshot-replaced);
    /// with the file backend it stays one `tag mask expires set_at setter reason` blob.
    pub fn save_xlines(&self) {
        if crate::database::stores_in_db(self) {
            let rows: Vec<Vec<Option<Vec<u8>>>> = self
                .xlines
                .iter()
                .map(|x| {
                    vec![
                        Some(x.kind.tag().to_string().into_bytes()),
                        Some(x.mask.clone().into_bytes()),
                        Some((x.expires as i64).to_string().into_bytes()),
                        Some((x.set_at as i64).to_string().into_bytes()),
                        Some(x.setter.clone().into_bytes()),
                        Some(x.reason.clone().into_bytes()),
                    ]
                })
                .collect();
            crate::database::store_rows_replace(
                self,
                "echoircd_xlines",
                "INSERT INTO echoircd_xlines (tag, mask, expires, set_at, setter, reason) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
                rows,
            );
            return;
        }
        let mut out = String::new();
        for x in &self.xlines {
            out.push_str(&format!(
                "{} {} {} {} {} {}\n",
                x.kind.tag(),
                x.mask,
                x.expires,
                x.set_at,
                x.setter,
                x.reason
            ));
        }
        crate::database::persist_save(self, "xlines", &self.xline_db_path(), out);
    }

    /// Reload persisted x-lines at startup, skipping any already expired. Prefers the
    /// normalized table; if it's empty (first boot after enabling pgsql) it migrates the
    /// legacy blob / flat file in and seeds the table; on any DB error it falls back to
    /// the legacy text so bans are never lost.
    pub fn load_xlines(&mut self) {
        let n = now();
        if crate::database::stores_in_db(self) {
            if let Some(rows) = crate::database::store_rows_load(
                self,
                XLINES_DDL,
                "SELECT tag, mask, expires, set_at, setter, reason FROM echoircd_xlines",
            ) {
                if rows.is_empty() {
                    self.load_xlines_text(); // migrate the legacy blob/file …
                    self.save_xlines(); // … and seed the table
                } else {
                    for r in &rows {
                        let g = |i: usize| r.get(i).and_then(|v| v.as_deref());
                        let (Some(tag), Some(mask)) = (g(0), g(1)) else {
                            continue;
                        };
                        let Some(kind) = XKind::from_tag(tag) else {
                            continue;
                        };
                        let expires = g(2).and_then(|v| v.parse().ok()).unwrap_or(0);
                        if expires != 0 && expires <= n {
                            continue; // already expired — don't reinstate it
                        }
                        self.xlines.push(XLine {
                            kind,
                            mask: mask.to_string(),
                            reason: g(5).unwrap_or("").to_string(),
                            setter: g(4).unwrap_or("").to_string(),
                            expires,
                            set_at: g(3).and_then(|v| v.parse().ok()).unwrap_or(0),
                        });
                    }
                }
                return;
            }
            // the database was unreachable — fall through to the legacy text
        }
        self.load_xlines_text();
    }

    /// Parse x-lines from the legacy text form (the central blob when pgsql, else the
    /// flat file) into memory, skipping already-expired lines.
    fn load_xlines_text(&mut self) {
        let n = now();
        let Some(text) = crate::database::persist_load(self, "xlines", &self.xline_db_path())
        else {
            return;
        };
        for line in text.lines() {
            if let Some(x) = parse_db_line(line) {
                if x.expires != 0 && x.expires <= n {
                    continue;
                }
                self.xlines.push(x);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Fuzz the duration parser: no arbitrary string may panic it.
        #[test]
        fn parse_duration_never_panics(s in ".*") {
            let _ = parse_duration(&s);
        }
    }

    #[test]
    fn human_duration_reads_naturally() {
        assert_eq!(human_duration(604800), "1 week");
        assert_eq!(human_duration(86400), "1 day");
        assert_eq!(human_duration(2 * 604800), "2 weeks");
        assert_eq!(human_duration(90061), "1 day 1 hour 1 minute 1 second");
        assert_eq!(human_duration(3600), "1 hour");
        assert_eq!(human_duration(0), "0 seconds");
    }

    #[test]
    fn parse_db_line_reads_new_and_old_formats() {
        // new format: tag mask expires set_at setter reason(may contain spaces)
        let x = parse_db_line("Z 1.2.3.4 1700003600 1700000000 fold10 open proxy").unwrap();
        assert_eq!(x.kind.tag(), "Z");
        assert_eq!(x.mask, "1.2.3.4");
        assert_eq!((x.expires, x.set_at), (1700003600, 1700000000));
        assert_eq!(
            (x.setter.as_str(), x.reason.as_str()),
            ("fold10", "open proxy")
        );
        // old format (no set_at) still loads — set_at defaults to 0 (unknown)
        let o = parse_db_line("G *@bad.example 0 op spam bot").unwrap();
        assert_eq!((o.set_at, o.expires), (0, 0));
        assert_eq!((o.setter.as_str(), o.reason.as_str()), ("op", "spam bot"));
        // old-format TIMED line (real live shape): a non-zero expires in field 3 must
        // not be mistaken for set_at, and a "svc@server" setter is never all-digits
        let t =
            parse_db_line("Z 1.2.3.4 1788441609 dnsbl@irc.echoircd.org listed in a dnsbl").unwrap();
        assert_eq!((t.expires, t.set_at), (1788441609, 0));
        assert_eq!(t.setter.as_str(), "dnsbl@irc.echoircd.org");
        assert_eq!(t.reason.as_str(), "listed in a dnsbl");
        // junk is skipped
        assert!(parse_db_line("").is_none());
        assert!(parse_db_line("Z").is_none());
        assert!(parse_db_line("BOGUS mask 0 op reason").is_none()); // unknown tag
    }

    #[test]
    fn xline_origin_shows_setter_when_and_duration() {
        let s = xline_origin("fold10", 1000, 1000 + 3600);
        assert!(
            s.starts_with("set by fold10 on ") && s.contains("duration 1 hour"),
            "{s}"
        );
        // pre-upgrade entry (set_at unknown) degrades to just the setter
        assert_eq!(xline_origin("op", 0, 999), "set by op");
    }
}
