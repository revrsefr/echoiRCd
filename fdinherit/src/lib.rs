//! File-descriptor inheritance for a zero-downtime executable upgrade.
//!
//! A graceful upgrade re-execs the daemon and hands its already-open listening and
//! client sockets to the new image, so connections are never dropped and server links
//! never split. That needs two operations the safe std API doesn't offer:
//!   * clear `FD_CLOEXEC` so a descriptor survives `exec()` (the new binary inherits it);
//!   * rebuild a `TcpListener` / `TcpStream` from an inherited raw descriptor.
//!
//! Both are isolated here — the daemon stays `#![forbid(unsafe_code)]`, exactly the way
//! the `sslgroup` crate isolates its one FFI call.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::fd::{FromRawFd, RawFd};

/// Clear `FD_CLOEXEC` on `fd` so it stays open across `exec()`. Errors on a bad fd.
pub fn set_inheritable(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl with F_GETFD/F_SETFD only reads/writes the descriptor flags of an
    // existing fd — it dereferences no memory and transfers no ownership. A bad fd is
    // reported as an error rather than causing UB.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above — writes the (validated) descriptor's flags with CLOEXEC cleared.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Take ownership of an inherited **listening** socket. The caller must pass an `fd`
/// that is a live, open, listening TCP socket whose ownership it is transferring here.
pub fn adopt_tcp_listener(fd: RawFd) -> TcpListener {
    // SAFETY: per the contract above — `fd` is a live listening socket; the returned
    // `TcpListener` becomes its sole owner (and closes it on drop).
    unsafe { TcpListener::from_raw_fd(fd) }
}

/// Take ownership of an inherited **connected** socket (a client or link connection),
/// same contract as [`adopt_tcp_listener`].
pub fn adopt_tcp_stream(fd: RawFd) -> TcpStream {
    // SAFETY: `fd` is a live connected socket whose ownership is transferred here.
    unsafe { TcpStream::from_raw_fd(fd) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;

    #[test]
    fn a_listener_survives_being_adopted_from_its_raw_fd() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let want = l.local_addr().unwrap();
        // into_raw_fd releases std's ownership so there's no double close after adoption
        let fd = l.into_raw_fd();
        set_inheritable(fd).unwrap();
        let adopted = adopt_tcp_listener(fd);
        assert_eq!(adopted.local_addr().unwrap(), want);
    }

    #[test]
    fn set_inheritable_rejects_a_bad_fd() {
        assert!(set_inheritable(-1).is_err());
    }
}
