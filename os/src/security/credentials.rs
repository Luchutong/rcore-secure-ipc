//! Per-process credentials: UID and capability set.

use super::{CapabilitySet, Uid};

/// Root UID — the initproc and all processes forked from it before any
/// `setuid` call share this identity.
pub const ROOT_UID: Uid = 0;

/// Credentials embedded in the process security state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Credentials {
    pub uid: Uid,
    pub capabilities: CapabilitySet,
}

impl Credentials {
    /// Initial credentials for the initproc (UID 0, all capabilities).
    pub const fn root() -> Self {
        Self {
            uid: ROOT_UID,
            capabilities: CapabilitySet::all(),
        }
    }

    /// Baseline identity used before the credential feature is implemented.
    /// Kept for compatibility with the scaffold's `ProcessSecurityState::initial`.
    pub const fn initial() -> Self {
        Self::root()
    }

    /// Derive child credentials: child inherits parent UID and capabilities.
    pub const fn fork_from(parent: &Self) -> Self {
        *parent
    }

    /// Whether this credential set has root privilege (UID 0).
    pub const fn is_root(&self) -> bool {
        self.uid == ROOT_UID
    }
}
