//! Authorization policy for IPC operations.

use super::{IpcError, IpcOperation, IpcRequest, IpcResult};

/// Authorize an IPC request.
///
/// # Signal send (kill) rules
///
/// | Condition                          | Decision |
/// |------------------------------------|----------|
/// | sender PID == target PID (self)    | Allow    |
/// | sender UID == target owner UID     | Allow    |
/// | sender UID == 0 (root)             | Allow    |
/// | sender has `KILL` capability       | Allow    |
/// | otherwise                          | EPERM    |
pub fn authorize(request: &IpcRequest) -> IpcResult<()> {
    match request.operation {
        IpcOperation::SignalSend => authorize_signal(request),
        // Other operations are open until their feature branches plug in.
        _ => Ok(()),
    }
}

/// Check whether `subject` may send a signal to `object`.
fn authorize_signal(request: &IpcRequest) -> IpcResult<()> {
    let subj = &request.subject;
    let obj = &request.object;

    // Self-signal is always allowed.
    if subj.pid as u64 == obj.id {
        return Ok(());
    }

    // Same UID is allowed.
    if subj.uid == obj.owner_uid {
        return Ok(());
    }

    // Root (UID 0) is allowed.
    if subj.uid == 0 {
        return Ok(());
    }

    // Explicit KILL capability allows cross-UID signalling.
    if subj.capabilities.contains(super::CapabilitySet::KILL) {
        return Ok(());
    }

    Err(IpcError::PermissionDenied)
}
