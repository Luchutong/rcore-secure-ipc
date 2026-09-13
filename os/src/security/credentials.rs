//! Per-process credentials: UID and capability set.

use super::{CapabilitySet, Uid};
use crate::sync::UPSafeCell;
use alloc::vec::Vec;
use lazy_static::lazy_static;

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

// ---------------------------------------------------------------------------
//  UID allocator
// ---------------------------------------------------------------------------

/// Monotonic UID allocator. UID 0 is reserved for root; the first non-root
/// UID handed out is 1.
struct UidAllocator {
    next: Uid,
    freed: Vec<Uid>,
}

impl UidAllocator {
    const fn new() -> Self {
        Self {
            next: 1, // 0 is root
            freed: Vec::new(),
        }
    }

    fn alloc(&mut self) -> Uid {
        if let Some(uid) = self.freed.pop() {
            uid
        } else {
            let uid = self.next;
            self.next += 1;
            uid
        }
    }

    fn dealloc(&mut self, uid: Uid) {
        if uid != ROOT_UID {
            self.freed.push(uid);
        }
    }
}

lazy_static! {
    static ref UID_ALLOCATOR: UPSafeCell<UidAllocator> =
        unsafe { UPSafeCell::new(UidAllocator::new()) };
}

/// Allocate a fresh non-root UID.
pub fn alloc_uid() -> Uid {
    UID_ALLOCATOR.exclusive_access().alloc()
}

/// Return a UID to the pool (no-op for root).
pub fn dealloc_uid(uid: Uid) {
    UID_ALLOCATOR.exclusive_access().dealloc(uid);
}
