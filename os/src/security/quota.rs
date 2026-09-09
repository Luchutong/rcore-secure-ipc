//! IPC quota extension point.

use super::{IpcError, IpcOperation, IpcRequest, IpcResult};

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

    /// Reserve quota for duplicating an existing descriptor.
    ///
    /// Returns whether the source descriptor is a pipe endpoint so the
    /// caller can register the newly allocated descriptor accordingly.
    pub fn reserve_dup_fd(&mut self, source_fd: usize) -> IpcResult<bool> {
        let is_pipe = self.is_pipe_fd(source_fd);

        if is_pipe {
            self.reserve_pipe_fds(1)?;
        } else {
            self.reserve_files(1)?;
        }

        Ok(is_pipe)
    }

    /// Remove pipe metadata without changing quota counters.
    ///
    /// This is used when an operation has installed pipe descriptors but
    /// later fails. The quota reservation itself is rolled back by
    /// `complete`.
    pub fn unregister_pipe_fd(&mut self, fd: usize) {
        if fd < u64::BITS as usize {
            self.pipe_fd_mask &= !(1u64 << fd);
        }
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

/// Kind of resource represented by a pending reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuotaReservationKind {
    /// This IPC operation does not reserve quota.
    None,

    /// Pipe endpoint descriptors were reserved.
    PipeFds,
}

/// Opaque reservation carried by the security facade.
///
/// A successful `preflight` may already have charged quota. `finish` keeps
/// that charge on success and rolls it back on failure.
pub(crate) struct QuotaReservation {
    kind: QuotaReservationKind,
    amount: usize,
}

/// Reserve resources requested through the security facade.
///
/// Reservation happens before the actual operation. On failure this function
/// leaves the quota state unchanged.
pub(crate) fn reserve(state: &mut QuotaState, request: &IpcRequest) -> IpcResult<QuotaReservation> {
    match request.operation {
        IpcOperation::PipeCreate => {
            state.reserve_pipe_fds(request.amount)?;
            Ok(QuotaReservation {
                kind: QuotaReservationKind::PipeFds,
                amount: request.amount,
            })
        }
        _ => Ok(QuotaReservation {
            kind: QuotaReservationKind::None,
            amount: 0,
        }),
    }
}

/// Commit or roll back a quota reservation.
///
/// Successful operations keep the quota charged. Failed operations release
/// exactly the resources reserved during `preflight`.
pub(crate) fn finish(state: &mut QuotaState, reservation: QuotaReservation, success: bool) {
    if success {
        return;
    }

    match reservation.kind {
        QuotaReservationKind::None => {}
        QuotaReservationKind::PipeFds => {
            state.release_pipe_fds(reservation.amount);
        }
    }
}
