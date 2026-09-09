//! sqlquery — a read-only SQL console over IRC for network administrators.
//!
//! `/SQL <SELECT …>` runs a query against the primary database and returns the rows as
//! notices to the oper who asked. It is:
//!   * **netadmin-only** — gated on the `servers/sql` privilege, which netadmin holds
//!     via `privs *` (and legacy type-less opers hold implicitly); no other opertype has
//!     it unless it's granted on purpose;
//!   * **non-blocking** — the query runs off-core through the [`crate::database`] pool,
//!     so a slow query can't freeze the server; the result comes back as a notice;
//!   * **read-only by default** — only `SELECT` is accepted (no `;`, no CTE, no DML),
//!     so a fat-fingered `DROP`/`DELETE` from a chat window can't wipe a table. Set
//!     `sqlquery_write yes` to lift that (dangerous).
//!
//! Config: `sqlquery` (master switch, default yes), `sqlquery_write` (default no),
//! `sqlquery_maxrows` (default 20), `sqlquery_maxwidth` (per-cell chars, default 96).

use crate::command::{CmdResult, Command};
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(SqlQuery)]
}

struct SqlQuery;

const USAGE: &[&str] = &[
    "SQL — console SQL en lecture seule (administrateurs réseau).",
    "  SQL <requête SELECT>   exécute la requête et affiche les lignes",
    "  SQL TABLES             liste les tables echoircd_*",
    "  SQL HELP               affiche cette aide",
    "Ex. : SQL SELECT addr, score FROM echoircd_reputation ORDER BY score DESC LIMIT 10",
];

impl Command for SqlQuery {
    fn name(&self) -> &'static str {
        "SQL"
    }
    fn min_params(&self) -> usize {
        1
    }

    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        // Netadmin-only: netadmin holds `servers/sql` through `privs *`.
        if !crate::modules::opertypes::has_priv(s, uid, "servers/sql") {
            reply(
                s,
                uid,
                "SQL : commande réservée aux administrateurs réseau.",
            );
            return CmdResult::Ok;
        }
        if !s.conf_bool("sqlquery", true) {
            reply(s, uid, "SQL : console désactivée (sqlquery no).");
            return CmdResult::Ok;
        }
        if !crate::database::is_enabled(s) {
            reply(
                s,
                uid,
                "SQL : aucune base de données configurée (pgsql_host).",
            );
            return CmdResult::Ok;
        }

        let sql = match params[0].to_ascii_uppercase().as_str() {
            "HELP" | "?" => {
                for line in USAGE {
                    reply(s, uid, line);
                }
                return CmdResult::Ok;
            }
            "TABLES" => {
                "SELECT tablename FROM pg_tables WHERE tablename LIKE 'echoircd%' ORDER BY 1"
                    .to_string()
            }
            _ => params.join(" "),
        };

        // Read-only guard (unless writes are explicitly enabled): one statement, SELECT.
        let query = sql.trim().trim_end_matches(';').trim();
        if query.contains(';') {
            reply(
                s,
                uid,
                "SQL : une seule instruction à la fois (pas de « ; »).",
            );
            return CmdResult::Ok;
        }
        if !s.conf_bool("sqlquery_write", false) && !starts_select(query) {
            reply(
                s,
                uid,
                "SQL : lecture seule — seules les requêtes SELECT sont autorisées \
                 (sqlquery_write pour lever la limite).",
            );
            return CmdResult::Ok;
        }

        let maxrows = s.conf_num("sqlquery_maxrows", 20usize).clamp(1, 500);
        let maxwidth = s.conf_num("sqlquery_maxwidth", 96usize).clamp(8, 400);
        let query = query.to_string();

        // Off-core: the result comes back on the core thread as a notice to this oper.
        crate::database::query(s, &query, vec![], move |s, result| match result {
            Err(e) => reply(s, uid, &format!("SQL : erreur — {}", one_line(&e, 400))),
            Ok(rows) => {
                reply(
                    s,
                    uid,
                    &format!(
                        "SQL : {} ligne(s), {} colonne(s).",
                        rows.len(),
                        rows.columns.len()
                    ),
                );
                if !rows.columns.is_empty() {
                    let head = rows.columns.join(" │ ");
                    reply(s, uid, &format!("SQL │ {}", clip(&head, 400)));
                }
                for (i, row) in rows.rows.iter().enumerate() {
                    if i >= maxrows {
                        reply(
                            s,
                            uid,
                            &format!(
                                "SQL : … {} ligne(s) de plus non affichée(s) (sqlquery_maxrows={}).",
                                rows.rows.len() - maxrows,
                                maxrows
                            ),
                        );
                        break;
                    }
                    let cells: Vec<String> = row.iter().map(|c| cell(c, maxwidth)).collect();
                    reply(s, uid, &format!("SQL │ {}", clip(&cells.join(" │ "), 400)));
                }
            }
        });
        CmdResult::Ok
    }
}

/// Send one NOTICE to the (possibly-since-departed) oper; a no-op if they've quit.
fn reply(s: &mut Server, uid: Uid, msg: &str) {
    if let Some(nick) = s.users.get(&uid).map(|u| u.nick.clone()) {
        s.send(uid, format!(":{} NOTICE {} :{}", s.name, nick, msg));
    }
}

/// True when the statement's first keyword is `SELECT` — so it can only read. `WITH`
/// is intentionally excluded (a CTE can hide a writable `DELETE … RETURNING`).
fn starts_select(q: &str) -> bool {
    let word: String = q
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    word.eq_ignore_ascii_case("select")
}

/// One SQL cell → a single-line, length-capped display string; NULL shows as `∅`.
fn cell(v: &Option<String>, max: usize) -> String {
    match v {
        None => "∅".to_string(),
        Some(s) => one_line(s, max),
    }
}

/// Collapse control characters to spaces (so a value can't break the IRC line) and cap.
fn one_line(s: &str, max: usize) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    clip(cleaned.trim(), max)
}

/// Truncate to `max` characters (UTF-8 safe), adding an ellipsis when cut.
fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_select_passes_the_read_only_gate() {
        assert!(starts_select("SELECT * FROM x"));
        assert!(starts_select("  select 1"));
        assert!(!starts_select(
            "WITH q AS (DELETE FROM x RETURNING *) SELECT * FROM q"
        ));
        assert!(!starts_select("DELETE FROM x"));
        assert!(!starts_select("update x set y=1"));
    }

    #[test]
    fn clip_is_utf8_safe() {
        assert_eq!(clip("hello", 10), "hello");
        assert_eq!(clip("hello", 3), "he…");
        assert_eq!(clip("café", 10), "café");
    }

    #[test]
    fn cell_shows_null_and_flattens_newlines() {
        assert_eq!(cell(&None, 10), "∅");
        assert_eq!(cell(&Some("a\nb".into()), 10), "a b");
    }
}
