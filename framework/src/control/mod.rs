//! Control plane of NetBricks, mainly the scheduler.
#[cfg(target_os = "linux")]
pub use self::epoll::*;

#[cfg(target_os = "linux")]
#[path = "linux/epoll.rs"]
mod epoll;
// #[cfg(feature = "sctp")]
// pub mod sctp;
pub mod tcp;

use std::os::unix::io::RawFd;

/// Available.
pub type Available = u64;

/// None.
pub const NONE: u64 = 0x0;
/// Read.
pub const READ: u64 = 0x1;
/// Write.
pub const WRITE: u64 = 0x2;
/// HUP.
pub const HUP: u64 = 0x4;

/// IO scheduler.
#[derive(Debug)]
pub struct IOScheduler {
    fd: RawFd,
    scheduler: PollHandle,
    token: Token,
}

impl IOScheduler {
    /// Initialize IO scheduler.
    pub fn new(scheduler: PollHandle, fd: RawFd, token: Token) -> IOScheduler {
        scheduler.new_io_fd(fd, token);
        IOScheduler { fd, scheduler, token }
    }

    /// Read IO scheduler.
    pub fn schedule_read(&self) {
        self.scheduler.schedule_read_rawfd(self.fd, self.token);
    }

    /// Write IO scheduler.
    pub fn schedule_write(&self) {
        self.scheduler.schedule_write_rawfd(self.fd, self.token);
    }
}
