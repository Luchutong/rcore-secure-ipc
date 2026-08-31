//! Authorization policy extension point.

use super::{IpcRequest, IpcResult};

/// Authorize an IPC request.
///
/// The integration scaffold preserves the original rCore behavior. The
/// credentials feature branch replaces this compatibility policy.
pub fn authorize(_request: &IpcRequest) -> IpcResult<()> {
    Ok(())
}
