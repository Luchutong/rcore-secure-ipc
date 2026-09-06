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
