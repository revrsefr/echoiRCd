//! Graceful binary upgrade: re-exec the daemon in place while keeping its listening
//! sockets open, so swapping to a new build leaves no rebind gap and no
//! "connection refused" window during the swap. Triggered by `SIGUSR2`.
//!
//! The low-level descriptor work lives in the `fdinherit` crate; this module only
//! orchestrates, so it holds no `unsafe`.

use std::net::TcpListener;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Env var carrying the `role:fd,role:fd,…` handover spec to the new process.
const ENV_FDS: &str = "ECHOIRCD_UPGRADE_FDS";

/// Re-exec the current executable, handing the given `(role, fd)` listeners to the new
/// image (each made to survive `exec`). Returns **only on failure** — on success the
/// process is replaced and control never returns, so the caller can log the error and
/// keep running the old image.
pub fn reexec(listeners: &[(&str, RawFd)]) -> std::io::Error {
    let mut spec = String::new();
    for (role, fd) in listeners {
        if let Err(e) = fdinherit::set_inheritable(*fd) {
            return e;
        }
        if !spec.is_empty() {
            spec.push(',');
        }
        spec.push_str(&format!("{role}:{fd}"));
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return e,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    Command::new(exe).args(args).env(ENV_FDS, spec).exec()
}

/// Whether this process was started by [`reexec`] — if so it adopts the inherited
/// listeners instead of binding fresh ones.
pub fn is_upgrade() -> bool {
    std::env::var_os(ENV_FDS).is_some()
}

/// The `(role, listener)` pairs handed over by the previous process (empty on a fresh
/// start); each spec fd is adopted into a [`TcpListener`].
pub fn inherited() -> Vec<(String, TcpListener)> {
    let Ok(spec) = std::env::var(ENV_FDS) else {
        return Vec::new();
    };
    spec.split(',')
        .filter_map(|item| {
            let (role, fd) = item.split_once(':')?;
            let fd: RawFd = fd.parse().ok()?;
            Some((role.to_string(), fdinherit::adopt_tcp_listener(fd)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn handover_spec_parses_and_skips_junk() {
        let spec = "client:7,tls:9,,bogus,server:11";
        let parsed: Vec<(&str, i32)> = spec
            .split(',')
            .filter_map(|i| {
                let (r, f) = i.split_once(':')?;
                Some((r, f.parse().ok()?))
            })
            .collect();
        assert_eq!(parsed, vec![("client", 7), ("tls", 9), ("server", 11)]);
    }
}
