//! Stable facade for independently developed IPC security modules.

mod api;
pub(crate) mod audit;
pub(crate) mod credentials;
pub(crate) mod policy;
pub(crate) mod quota;

pub use api::{
    CapabilitySet, IpcError, IpcObject, IpcOperation, IpcRequest, IpcResult, IpcSubject,
    ResourceId, Uid,
};

use credentials::Credentials;
use quota::{QuotaReservation, QuotaState};

/// Security-related state embedded once in each process.
pub struct ProcessSecurityState {
    pub credentials: Credentials,
    pub quota: QuotaState,
}

impl ProcessSecurityState {
    /// Construct state for the initial process.
    pub const fn initial() -> Self {
        Self {
            credentials: Credentials::initial(),
            quota: QuotaState::initial(),
        }
    }

    /// Construct child state through module-owned inheritance hooks.
    pub const fn fork_from(parent: &Self) -> Self {
        Self {
            credentials: Credentials::fork_from(&parent.credentials),
            quota: QuotaState::fork_from(&parent.quota),
        }
    }
}

/// Opaque proof that policy and quota checks ran for a request.
pub struct IpcPermit {
    request: IpcRequest,
    reservation: QuotaReservation,
}

/// Run authorization and quota checks through stable module boundaries.
pub fn preflight(state: &mut ProcessSecurityState, request: IpcRequest) -> IpcResult<IpcPermit> {
    policy::authorize(&request)?;
    let reservation = quota::reserve(&mut state.quota, &request)?;
    Ok(IpcPermit {
        request,
        reservation,
    })
}

/// Finish a request, update quota state, and emit its audit outcome.
pub fn complete(
    state: &mut ProcessSecurityState,
    permit: IpcPermit,
    outcome: IpcResult<usize>,
) -> IpcResult<usize> {
    quota::finish(&mut state.quota, permit.reservation, outcome.is_ok());
    audit::record(&permit.request, &outcome);
    outcome
}
/// Reserve one ordinary file-descriptor slot.
///
/// This crate-private hook keeps syscall code outside the quota module.
pub(crate) fn reserve_file_fd(state: &mut ProcessSecurityState) -> IpcResult<()> {
    state.quota.reserve_files(1)
}

/// Reserve quota for duplicating an existing descriptor.
///
/// Returns whether the source descriptor is a pipe endpoint.
pub(crate) fn reserve_dup_fd(
    state: &mut ProcessSecurityState,
    source_fd: usize,
) -> IpcResult<bool> {
    state.quota.reserve_dup_fd(source_fd)
}

/// Register an already-reserved descriptor as a pipe endpoint.
pub(crate) fn register_pipe_fd(state: &mut ProcessSecurityState, fd: usize) {
    state.quota.register_pipe_fd(fd);
}

/// Remove pipe metadata without releasing the pending quota reservation.
pub(crate) fn unregister_pipe_fd(state: &mut ProcessSecurityState, fd: usize) {
    state.quota.unregister_pipe_fd(fd);
}

/// Release one committed descriptor and its associated quota.
pub(crate) fn release_fd(state: &mut ProcessSecurityState, fd: usize) {
    state.quota.release_fd(fd);
}
