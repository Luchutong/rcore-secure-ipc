//! IPC quota extension point.

use super::{IpcError, IpcRequest, IpcResult};

/// Maximum number of open file descriptors per process.
pub const MAX_OPEN_FILES: usize = 32;

/// Maximum number of pipe endpoint file descriptors per process.
pub const MAX_OPEN_PIPE_FDS: usize = 16;

/// Per-process quota counters reserved in the task control block.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaState {
    /// Number of currently open file descriptors.
    pub open_files: usize,

    /// Number of currently open pipe endpoint descriptors.
    ///
    /// A single pipe normally contributes two descriptors:
    /// one read endpoint and one write endpoint.
    pub open_pipes: usize,
}

impl QuotaState {
    /// Initial quota state.
    ///
    /// The initial process owns stdin, stdout and stderr,
    /// therefore three file descriptors are already in use.
    pub const fn initial() -> Self {
        Self {
            open_files: 3,
            open_pipes: 0,
        }
    }

    /// Derive counters for a child process.
    ///
    /// fork inherits the parent's file descriptor table,
    /// so the child starts with the same usage counters.
    pub const fn fork_from(parent: &Self) -> Self {
        *parent
    }

    /// Reserve normal file-descriptor slots.
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

    /// Release normal file-descriptor slots.
    pub fn release_files(&mut self, amount: usize) {
        debug_assert!(self.open_files >= amount);

        self.open_files -= amount;
    }

    /// Reserve pipe endpoint descriptors.
    pub fn reserve_pipe_fds(&mut self, amount: usize) -> IpcResult<()> {
        let next = self
            .open_pipes
            .checked_add(amount)
            .ok_or(IpcError::ResourceExhausted)?;

        if next > MAX_OPEN_PIPE_FDS {
            return Err(IpcError::ResourceExhausted);
        }

        self.open_pipes = next;

        Ok(())
    }

    /// Release pipe endpoint descriptors.
    pub fn release_pipe_fds(&mut self, amount: usize) {
        debug_assert!(self.open_pipes >= amount);

        self.open_pipes -= amount;
    }
}

/// Opaque reservation returned to the security facade.
///
/// The real per-process accounting will be connected through the
/// security facade during integration.
pub(crate) struct QuotaReservation;

/// Reserve resources for a request.
///
/// This remains a facade stub until the per-process `QuotaState`
/// is wired into `security::preflight`.
pub(crate) fn reserve(_request: &IpcRequest) -> IpcResult<QuotaReservation> {
    Ok(QuotaReservation)
}

/// Commit or roll back a reservation.
///
/// The actual accounting hook will be completed when the facade
/// passes the corresponding per-process quota state.
pub(crate) fn finish(_reservation: QuotaReservation, _success: bool) {}
