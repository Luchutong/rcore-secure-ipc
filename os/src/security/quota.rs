//! IPC quota extension point.

use super::{IpcRequest, IpcResult};

/// Per-process quota counters reserved in the task control block.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaState {
    pub open_files: usize,
    pub open_pipes: usize,
}

impl QuotaState {
    /// Empty quota state for the first process.
    pub const fn initial() -> Self {
        Self {
            open_files: 0,
            open_pipes: 0,
        }
    }

    /// Derive counters for a child process.
    pub const fn fork_from(parent: &Self) -> Self {
        *parent
    }
}

/// Opaque reservation returned to the security facade.
pub(crate) struct QuotaReservation;

/// Reserve resources for a request.
pub(crate) fn reserve(_request: &IpcRequest) -> IpcResult<QuotaReservation> {
    Ok(QuotaReservation)
}

/// Commit or roll back a reservation.
pub(crate) fn finish(_reservation: QuotaReservation, _success: bool) {}
