//! Per-process credentials.

use super::{CapabilitySet, Uid};

/// Credentials embedded in the process security state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Credentials {
    pub uid: Uid,
    pub capabilities: CapabilitySet,
}

impl Credentials {
    /// Baseline identity used before the credential feature is implemented.
    pub const fn initial() -> Self {
        Self {
            uid: 0,
            capabilities: CapabilitySet::empty(),
        }
    }

    /// Derive child credentials without exposing task internals.
    pub const fn fork_from(parent: &Self) -> Self {
        *parent
    }
}
