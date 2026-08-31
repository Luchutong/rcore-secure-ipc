//! Stable data types shared by the IPC security modules.

/// User identity used by the teaching kernel security model.
pub type Uid = u32;

/// Stable identifier for an IPC object.
pub type ResourceId = u64;

/// Minimal capability set carried by a process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilitySet(u32);

impl CapabilitySet {
    /// No capabilities.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Capability to signal processes owned by another user.
    pub const KILL: Self = Self(1 << 0);

    /// Capability to administer IPC resources.
    pub const IPC_ADMIN: Self = Self(1 << 1);

    /// Capability to read the security audit stream.
    pub const AUDIT_READ: Self = Self(1 << 2);

    /// Return whether every bit in `required` is present.
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

/// IPC operations that can be authorized and audited.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcOperation {
    SignalSend,
    PipeCreate,
    PipeRead,
    PipeWrite,
    AuditRead,
}

/// Security attributes of the calling process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcSubject {
    pub pid: usize,
    pub uid: Uid,
    pub capabilities: CapabilitySet,
}

/// Security attributes of the target process or IPC object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcObject {
    pub id: ResourceId,
    pub owner_uid: Uid,
}

/// Common request passed through policy, quota, and audit modules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcRequest {
    pub subject: IpcSubject,
    pub object: IpcObject,
    pub operation: IpcOperation,
    pub amount: usize,
}

/// Errors exposed by the IPC security boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcError {
    PermissionDenied,
    InvalidAddress,
    InvalidArgument,
    ProcessNotFound,
    TooManyFiles,
    ResourceExhausted,
    TryAgain,
}

/// Common result type for IPC security operations.
pub type IpcResult<T> = Result<T, IpcError>;
