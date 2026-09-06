//! IPC quota extension point.

use super::{IpcError, IpcRequest, IpcResult};

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
        }
    }

    /// Fork inherits the parent's descriptor table, so the child starts with
    /// the same per-process usage counters.
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

    /// Release ordinary file descriptors.
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

        // Commit only after every check succeeds.
        self.open_files = next_files;
        self.open_pipes = next_pipes;

        Ok(())
    }

    /// Release pipe endpoint descriptors.
    ///
    /// A pipe endpoint consumes both one total FD slot and one pipe FD slot,
    /// so both counters are released together.
    pub fn release_pipe_fds(&mut self, amount: usize) {
        debug_assert!(self.open_files >= amount);
        debug_assert!(self.open_pipes >= amount);

        self.open_files = self.open_files.saturating_sub(amount);
        self.open_pipes = self.open_pipes.saturating_sub(amount);
    }
}

/// Opaque reservation carried by the security facade.
///
/// The facade is not yet wired to the per-process `QuotaState`; the concrete
/// accounting helpers above remain ready for that integration step.
pub(crate) struct QuotaReservation;

/// Reserve resources requested through the stable security facade.
///
/// This remains a facade stub until the integration layer provides access to
/// the requesting process's `QuotaState`.
pub(crate) fn reserve(_request: &IpcRequest) -> IpcResult<QuotaReservation> {
    Ok(QuotaReservation)
}

/// Complete or roll back a quota reservation.
///
/// This remains a facade stub until per-process quota state is wired through
/// the security facade.
pub(crate) fn finish(_reservation: QuotaReservation, _success: bool) {}
