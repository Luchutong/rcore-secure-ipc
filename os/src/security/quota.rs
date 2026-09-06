//! IPC quota extension point.

use super::IpcOperation;
use super::{IpcError, IpcRequest, IpcResult};
use crate::task::{current_task, pid2task};

/// Maximum number of open file descriptors per process.
pub const MAX_OPEN_FILES: usize = 32;

/// Maximum number of pipe endpoint file descriptors per process.
///
/// One pipe created by `pipe()` normally consumes two pipe FDs:
/// one readable endpoint and one writable endpoint.
pub const MAX_OPEN_PIPE_FDS: usize = 16;

/// Per-process IPC resource accounting state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaState {
    /// Number of currently open file descriptors.
    ///
    /// This includes ordinary files, stdio descriptors, and pipe endpoints.
    pub open_files: usize,

    /// Number of currently open pipe endpoint file descriptors.
    ///
    /// This counts endpoints rather than pipe objects. Therefore one newly
    /// created pipe normally contributes two.
    pub open_pipes: usize,

    /// Bitmap recording which descriptor numbers refer to pipe endpoints.
    ///
    /// `MAX_OPEN_FILES` is currently 32, so a u64 is sufficient.
    pipe_fd_mask: u64,
}

impl Default for QuotaState {
    fn default() -> Self {
        Self::initial()
    }
}

impl QuotaState {
    /// Initial quota state.
    ///
    /// The initial process starts with stdin, stdout, and stderr.
    pub const fn initial() -> Self {
        Self {
            open_files: 3,
            open_pipes: 0,
            pipe_fd_mask: 0,
        }
    }

    /// Fork inherits the parent's descriptor table, so the child starts with
    /// the same per-process usage counters and pipe-FD metadata.
    pub const fn fork_from(parent: &Self) -> Self {
        *parent
    }

    /// Reserve ordinary file descriptors.
    ///
    /// On failure the state is left unchanged.
    pub fn reserve_files(&mut self, amount: usize) -> IpcResult<()> {
        let next = self
            .open_files
            .checked_add(amount)
            .ok_or(IpcError::TooManyFiles)?;

        if next > MAX_OPEN_FILES {
            return Err(IpcError::TooManyFiles);
        }

        self.open_files = next;
        Ok(())
    }

    /// Roll back previously reserved ordinary file descriptors.
    pub fn release_files(&mut self, amount: usize) {
        debug_assert!(self.open_files >= amount);
        self.open_files = self.open_files.saturating_sub(amount);
    }

    /// Atomically reserve pipe endpoint descriptors.
    ///
    /// Every pipe endpoint is also an open file descriptor, so this checks
    /// both the total FD limit and the pipe-specific limit before changing
    /// either counter.
    ///
    /// If either check fails, neither counter is modified.
    pub fn reserve_pipe_fds(&mut self, amount: usize) -> IpcResult<()> {
        let next_files = self
            .open_files
            .checked_add(amount)
            .ok_or(IpcError::TooManyFiles)?;

        if next_files > MAX_OPEN_FILES {
            return Err(IpcError::TooManyFiles);
        }

        let next_pipes = self
            .open_pipes
            .checked_add(amount)
            .ok_or(IpcError::ResourceExhausted)?;

        if next_pipes > MAX_OPEN_PIPE_FDS {
            return Err(IpcError::ResourceExhausted);
        }

        self.open_files = next_files;
        self.open_pipes = next_pipes;

        Ok(())
    }

    /// Roll back pipe descriptors before descriptor numbers are committed.
    pub fn release_pipe_fds(&mut self, amount: usize) {
        debug_assert!(self.open_files >= amount);
        debug_assert!(self.open_pipes >= amount);

        self.open_files = self.open_files.saturating_sub(amount);
        self.open_pipes = self.open_pipes.saturating_sub(amount);
    }

    /// Record that an already-reserved descriptor number is a pipe endpoint.
    ///
    /// This does not change counters; `reserve_pipe_fds` must have succeeded
    /// before this method is called.
    pub fn register_pipe_fd(&mut self, fd: usize) {
        debug_assert!(fd < MAX_OPEN_FILES);
        debug_assert!(fd < u64::BITS as usize);

        if fd < u64::BITS as usize {
            self.pipe_fd_mask |= 1u64 << fd;
        }
    }

    /// Return whether a descriptor number is currently recorded as a pipe.
    pub fn is_pipe_fd(&self, fd: usize) -> bool {
        if fd >= u64::BITS as usize {
            return false;
        }

        self.pipe_fd_mask & (1u64 << fd) != 0
    }

    /// Release one committed descriptor.
    ///
    /// If the descriptor is a pipe endpoint, both the total FD counter and
    /// the pipe-specific counter are decremented.
    pub fn release_fd(&mut self, fd: usize) {
        let was_pipe = self.is_pipe_fd(fd);

        if fd < u64::BITS as usize {
            self.pipe_fd_mask &= !(1u64 << fd);
        }

        debug_assert!(self.open_files > 0);
        self.open_files = self.open_files.saturating_sub(1);

        if was_pipe {
            debug_assert!(self.open_pipes > 0);
            self.open_pipes = self.open_pipes.saturating_sub(1);
        }
    }
}

/// Opaque reservation carried by the security facade.
///
/// A pipe creation reserves its two endpoint descriptors before the pipe is
/// allocated.  Keeping the owner PID and reserved amount here lets
/// `security::complete` roll that reservation back without changing the
/// public facade API.
pub(crate) struct QuotaReservation {
    owner_pid: Option<usize>,
    pipe_fds: usize,
}

impl QuotaReservation {
    const fn none() -> Self {
        Self {
            owner_pid: None,
            pipe_fds: 0,
        }
    }
}

/// Reserve resources requested through the stable security facade.
///
/// The current task is resolved internally so the public
/// `security::preflight(IpcRequest)` contract does not need to expose task or
/// quota implementation details. Only pipe creation consumes quota through
/// the IPC facade; ordinary `open`, `dup`, and `close` use the lifecycle
/// helpers on `QuotaState` from C-owned filesystem syscall code.
pub(crate) fn reserve(request: &IpcRequest) -> IpcResult<QuotaReservation> {
    if request.operation != IpcOperation::PipeCreate {
        return Ok(QuotaReservation::none());
    }

    let task = current_task().ok_or(IpcError::ProcessNotFound)?;
    let owner_pid = task.getpid();

    // Kernel call sites construct IpcRequest from the current task. Reject a
    // mismatched subject rather than charging another process accidentally.
    if request.subject.pid != owner_pid {
        return Err(IpcError::InvalidArgument);
    }

    let mut inner = task.inner_exclusive_access();
    inner.security.quota.reserve_pipe_fds(2)?;

    Ok(QuotaReservation {
        owner_pid: Some(owner_pid),
        pipe_fds: 2,
    })
}

/// Complete or roll back a quota reservation.
///
/// Successful reservations were already charged during `reserve`. A failed
/// operation releases the exact reservation from the originating process.
pub(crate) fn finish(reservation: QuotaReservation, success: bool) {
    if success || reservation.pipe_fds == 0 {
        return;
    }

    let Some(owner_pid) = reservation.owner_pid else {
        return;
    };
    let Some(task) = pid2task(owner_pid) else {
        // A permit is completed in the same syscall that created it, so the
        // task should still be registered. Avoid touching unrelated state if
        // that invariant is ever broken.
        debug_assert!(false, "quota reservation owner disappeared");
        return;
    };

    task.inner_exclusive_access()
        .security
        .quota
        .release_pipe_fds(reservation.pipe_fds);
}
