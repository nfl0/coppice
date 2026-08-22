//! Wallet-local Coppice primitives for librustzcash integrations.
//!
//! This crate deliberately contains no wallet database, synchronization, RPC,
//! transaction-construction, or UI integration. Its inputs are locally derived
//! wallet facts and its lock backend is an explicit seam for a later concrete
//! wallet implementation.

mod guard;
mod inventory;
mod locking;
mod pending;
mod selection;
mod source;

pub use guard::{
    CoppiceProtectionMode, HostCanonicalTipSource, SpendGuardError, WalletCanonicalTip,
    with_coppice_spend_guard,
};
pub use inventory::{
    InventoryError, IronwoodOutputId, IronwoodViewingCapability, OwnedBond, OwnedIronwoodNote,
    OwnedIronwoodNoteSource, active_canonical_bond_tags, active_canonical_bond_tags_from_state,
    classify_owned_bonds,
};
pub use locking::{
    CoppiceLockBackend, DesiredLockSetError, OutputLockBackendError, OutputLockStoreBridge,
    ReconciliationError, ReconciliationReport, desired_lock_tags, lock_owner_for_bond,
    reconcile_locks,
};
pub use pending::{
    PendingRegistration, PendingRegistrationCollection, PendingRegistrationCollectionError,
    PendingRegistrationTransitionError, PendingRegistrationValidationError,
    pending_attempt_expired, pending_commit_expired,
};
pub use selection::{FreshnessEligibility, SelectedBondNote, select_bond_note};
pub use source::{
    InputSourceIronwoodNoteSource, IronwoodNoteConversionError, IronwoodNoteSourceError,
};

/// The exact pinned librustzcash lock-owner type used by this adapter.
pub use zcash_client_backend::wallet::LockOwner;
