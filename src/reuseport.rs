//! Bind a TCP listener with `SO_REUSEPORT` so several accept loops (or a new binary
//! during a reload) can listen on the same port at once — the kernel load-balances
//! incoming connections across them. The basis for multi-core accept scaling and a
//! zero-gap executable upgrade.
//!
//! Uses `socket2`'s safe API; no `unsafe` in this crate.

use std::io;
use std::net::{SocketAddr, TcpListener};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Bind `addr` for TCP with `SO_REUSEADDR` + `SO_REUSEPORT` and return a ready-to-accept
/// listener. Several listeners may hold the same address concurrently.
pub fn bind_reuseport(addr: SocketAddr, backlog: i32) -> io::Result<TcpListener> {
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.bind(&SockAddr::from(addr))?;
    sock.listen(backlog)?;
    Ok(sock.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_listeners_share_one_port() {
        // Bind an ephemeral port, then bind a SECOND listener to that same port —
        // SO_REUSEPORT makes this succeed where a plain bind would hit EADDRINUSE.
        let l1 = bind_reuseport("127.0.0.1:0".parse().unwrap(), 128).unwrap();
        let addr = l1.local_addr().unwrap();
        let l2 = bind_reuseport(addr, 128).expect("second bind on the same port");
        assert_eq!(
            l1.local_addr().unwrap().port(),
            l2.local_addr().unwrap().port()
        );
    }
}
