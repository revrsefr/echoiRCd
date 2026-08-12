//! X-lines — server bans: KLINE/GLINE on `user@host`, ZLINE on an IP. Matched at
//! registration (a banned client is refused) and when the line is added (matching
//! clients are killed); expired lines are reaped on the tick. Kept in
//! `Server.xlines`.

use crate::channels::glob_match;
use crate::server::{now, Server};
use crate::Uid;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum XKind {
    Kline, // user@host, this server
    Gline, // user@host, "global" (locally the same until services span it)
    Zline, // an IP address
    Eline, // user@host / ip EXEMPT from K/G/Z-lines
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
    let n: u64 = s[..s.len() - 1].parse().ok()?;
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
        self.matched_qline(nick).or_else(|| self.matched_svshold(nick))
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
                let reason = self
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
                    .map(|x| x.reason.clone())
                    .unwrap_or_default();
                return Some(format!("{}-lined: {reason}", kind.tag()));
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
            .map(|x| format!("R-lined: {}", x.reason))
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
            self.send(uid, format!("ERROR :Closing link: (R-lined: {reason})"));
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
        let n = now();
        self.xlines.retain(|x| !(x.kind == kind && x.mask == mask));
        self.xlines.push(XLine {
            kind,
            mask: mask.to_string(),
            reason: reason.to_string(),
            setter: setter.to_string(),
            expires: if duration == 0 { 0 } else { n + duration },
        });
        self.snotice(&format!(
            "{setter} added a {}-line on {mask}: {reason}",
            kind.tag()
        ));
        self.save_xlines();
        self.enforce_xlines();
    }

    /// Remove an x-line by kind + mask; returns whether one was found.
    pub fn remove_xline(&mut self, kind: XKind, mask: &str) -> bool {
        let before = self.xlines.len();
        self.xlines.retain(|x| !(x.kind == kind && x.mask == mask));
        let removed = self.xlines.len() < before;
        if removed {
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
            self.send(uid, format!("ERROR :Closing link: ({reason})"));
            self.remove_user(uid, &reason);
        }
    }

    /// Drop expired x-lines (called on the background tick).
    pub fn purge_xlines(&mut self) {
        let n = now();
        let before = self.xlines.len();
        self.xlines.retain(|x| x.expires == 0 || x.expires > n);
        if self.xlines.len() != before {
            self.save_xlines(); // an expiry changed the set — persist it
        }
    }

    /// Path of the on-disk x-line db (beside the config file).
    fn xline_db_path(&self) -> String {
        format!("{}.xlines", self.conf_path)
    }

    /// Persist all current x-lines so they survive a restart.
    pub fn save_xlines(&self) {
        let mut out = String::new();
        for x in &self.xlines {
            out.push_str(&format!(
                "{} {} {} {} {}\n",
                x.kind.tag(),
                x.mask,
                x.expires,
                x.setter,
                x.reason
            ));
        }
        self.disk_write(self.xline_db_path(), out); // off-core: a slow disk mustn't stall the event loop
    }

    /// Reload persisted x-lines at startup, skipping any already expired.
    pub fn load_xlines(&mut self) {
        let n = now();
        let Ok(text) = std::fs::read_to_string(self.xline_db_path()) else {
            return;
        };
        for line in text.lines() {
            let mut it = line.splitn(5, ' ');
            let (Some(tag), Some(mask), Some(exp), Some(setter), Some(reason)) =
                (it.next(), it.next(), it.next(), it.next(), it.next())
            else {
                continue;
            };
            let Some(kind) = XKind::from_tag(tag) else {
                continue;
            };
            let expires: u64 = exp.parse().unwrap_or(0);
            if expires != 0 && expires <= n {
                continue;
            }
            self.xlines.push(XLine {
                kind,
                mask: mask.to_string(),
                reason: reason.to_string(),
                setter: setter.to_string(),
                expires,
            });
        }
    }
}
