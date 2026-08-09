//! antirandom — detect spam drones whose nick/ident/realname is random-looking,
//! by scoring character patterns and acting when a threshold is crossed. This is
//! reverse's own detection model (the run rules + the unlikely-trigram penalty
//! table are the spec — they define what counts as random); everything around
//! them is original native Rust.
//!
//! Score, summed over nick (+ ident + realname when `checkfull`):
//!  - a run reaching 5 digits / 4 vowels / 4 consonants adds that length; each
//!    further char in the run adds 1
//!  - each adjacent letter pair found in the "unlikely trigram" table adds 1
//!
//! At/above `antirandom_threshold` the action fires: kill | gline | kline |
//! zline | block. Opers and logged-in accounts are always exempt. Off unless
//! `antirandom = yes` — read entirely from the config, nothing on `Server`.

use crate::module::{ModResult, Module};
use crate::server::Server;
use crate::xline::XKind;
use crate::Uid;

/// Adjacent letter pairs that rarely occur in real words but pepper random
/// strings — each occurrence adds 1 to the score. reverse's high-signal subset.
const TRIPLES: &[&[u8; 2]] = &[
    b"aj", b"aq", b"av", b"aw", b"ax", b"az", b"bd", b"bg", b"bk", b"bq", b"bx", b"bz", b"cb",
    b"cf", b"cg", b"cj", b"cp", b"cv", b"cw", b"cx", b"dx", b"fb", b"fc", b"fg", b"fh", b"fj",
    b"fk", b"fp", b"fq", b"fv", b"fw", b"fx", b"fz", b"gb", b"gf", b"gj", b"gp", b"gv", b"gx",
    b"hb", b"hf", b"hj", b"hk", b"hv", b"hx", b"hz", b"jc", b"jd", b"jf", b"jg", b"jh", b"jk",
    b"jl", b"jm", b"jn", b"jp", b"jq", b"jr", b"js", b"jt", b"jv", b"jw", b"jx", b"jy", b"jz",
    b"kb", b"kd", b"kf", b"kg", b"kh", b"kj", b"kp", b"kq", b"kv", b"kx", b"kz", b"lj", b"lq",
    b"lx", b"mj", b"mq", b"mx", b"mz", b"pb", b"pf", b"pg", b"pj", b"pk", b"pq", b"pv", b"px",
    b"pz", b"qb", b"qc", b"qd", b"qe", b"qf", b"qg", b"qh", b"qi", b"qj", b"qk", b"ql", b"qm",
    b"qn", b"qo", b"qp", b"qr", b"qs", b"qt", b"qu", b"qv", b"qw", b"qx", b"qy", b"qz", b"sx",
    b"sz", b"tj", b"tq", b"tx", b"vb", b"vc", b"vd", b"vf", b"vg", b"vh", b"vj", b"vk", b"vl",
    b"vm", b"vn", b"vp", b"vq", b"vr", b"vs", b"vt", b"vw", b"vx", b"vz", b"wb", b"wc", b"wd",
    b"wf", b"wg", b"wj", b"wk", b"wp", b"wq", b"wv", b"wx", b"wz", b"xb", b"xc", b"xd", b"xf",
    b"xg", b"xh", b"xj", b"xk", b"xl", b"xm", b"xn", b"xp", b"xq", b"xr", b"xs", b"xt", b"xv",
    b"xw", b"xz", b"yb", b"yc", b"yd", b"yf", b"yg", b"yh", b"yj", b"yk", b"yp", b"yq", b"yv",
    b"yw", b"yx", b"yz", b"zb", b"zc", b"zd", b"zf", b"zg", b"zh", b"zj", b"zk", b"zl", b"zm",
    b"zn", b"zp", b"zq", b"zr", b"zs", b"zt", b"zv", b"zw", b"zx",
];

fn is_vowel(c: u8) -> bool {
    matches!(c, b'a' | b'e' | b'i' | b'o' | b'u')
}
fn is_consonant(c: u8) -> bool {
    c.is_ascii_lowercase() && !is_vowel(c)
}

/// Score one string for "randomness". Higher = more likely a bot.
fn score_string(input: &str) -> u32 {
    if input.is_empty() {
        return 0;
    }
    let s: Vec<u8> = input.bytes().map(|b| b.to_ascii_lowercase()).collect();
    let mut score = 0u32;
    let (mut digits, mut vowels, mut consonants) = (0u32, 0u32, 0u32);
    for i in 0..s.len() {
        let c = s[i];
        if c.is_ascii_digit() {
            digits += 1;
            vowels = 0;
            consonants = 0;
        } else if is_vowel(c) {
            vowels += 1;
            digits = 0;
            consonants = 0;
        } else if is_consonant(c) {
            consonants += 1;
            digits = 0;
            vowels = 0;
        } else {
            digits = 0;
            vowels = 0;
            consonants = 0;
        }
        match digits {
            5 => score += 5,
            d if d > 5 => score += 1,
            _ => {}
        }
        match vowels {
            4 => score += 4,
            v if v > 4 => score += 1,
            _ => {}
        }
        match consonants {
            4 => score += 4,
            c if c > 4 => score += 1,
            _ => {}
        }
        // trigram penalty: the adjacent pair ending at i
        if i >= 1 {
            let pair = [s[i - 1], c];
            if TRIPLES.iter().any(|t| t[0] == pair[0] && t[1] == pair[1]) {
                score += 1;
            }
        }
    }
    score
}

fn dur(s: &Server) -> u64 {
    s.conf("antirandom_duration")
        .and_then(crate::xline::parse_duration)
        .filter(|&d| d > 0)
        .unwrap_or(3600)
}

pub struct AntiRandom;

impl Module for AntiRandom {
    fn name(&self) -> &'static str {
        "antirandom"
    }

    fn on_user_register(&mut self, srv: &mut Server, uid: Uid) -> ModResult {
        if !srv.conf_bool("antirandom", false) {
            return ModResult::Passthru;
        }
        // opers and logged-in accounts are exempt
        if srv.is_oper(uid) || srv.is_logged_in(uid) {
            return ModResult::Passthru;
        }
        let threshold = srv.conf_num("antirandom_threshold", 10u32).max(1);
        let checkfull = srv.conf_bool("antirandom_checkfull", true);

        let (nick, ident, realname, host, ip, mask) = {
            let Some(u) = srv.users.get(&uid) else {
                return ModResult::Passthru;
            };
            (
                u.nick.clone(),
                u.ident.clone(),
                u.realname.clone(),
                u.host.clone(),
                u.addr.ip().to_string(),
                u.prefix(),
            )
        };

        let mut score = score_string(&nick);
        if checkfull {
            score += score_string(&ident);
            score += score_string(&realname);
        }
        if score < threshold {
            return ModResult::Passthru;
        }

        let action = srv
            .conf("antirandom_action")
            .unwrap_or("kill")
            .to_ascii_lowercase();
        let reason = srv
            .conf("antirandom_reason")
            .unwrap_or("Random nick/ident/realname (likely spam bot)")
            .to_string();

        if srv.conf_bool("antirandom_showfailed", false) {
            srv.snotice(&format!(
                "ANTIRANDOM: {mask} (score {score} >= {threshold}) — action: {action}"
            ));
        }

        let setter = format!("antirandom@{}", srv.name);
        let d = dur(srv);
        match action.as_str() {
            "block" => {
                srv.send(
                    uid,
                    format!(
                        ":{} NOTICE {nick} :*** Your nick/ident/realname looks random \
                         (often a sign of a bot). Reconnect with a more natural nick, \
                         or register your account.",
                        srv.name
                    ),
                );
            }
            "gline" => srv.add_xline(XKind::Gline, &format!("*@{host}"), d, &setter, &reason),
            "kline" => srv.add_xline(XKind::Kline, &format!("*@{host}"), d, &setter, &reason),
            "zline" => srv.add_xline(XKind::Zline, &ip, d, &setter, &reason),
            _ => {} // "kill" (default): the core disconnects on Deny
        }
        ModResult::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_names_score_low() {
        assert!(score_string("reverse") < 10);
        assert!(score_string("michael") < 10);
        assert!(score_string("nick") < 10);
    }

    #[test]
    fn random_strings_score_high() {
        assert!(score_string("xkjqzvwx") >= 5);
        assert!(score_string("qzxjkvbg") >= 5);
        assert!(score_string("aeiouaeiou") >= 4); // long vowel run
        assert!(score_string("bcdfghjklm") >= 4); // long consonant run
    }

    #[test]
    fn digit_runs_score() {
        assert!(score_string("a123456789") >= 5);
    }
}
