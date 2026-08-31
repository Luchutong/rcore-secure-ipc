//! IPC audit extension point.

use super::{IpcRequest, IpcResult};

/// Record the outcome of an IPC request.
///
/// This compatibility implementation is intentionally a no-op so the audit
/// feature can be developed without changing callers.
pub(crate) fn record(_request: &IpcRequest, _outcome: &IpcResult<usize>) {}
