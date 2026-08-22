//! Wallet-local Coppice primitives for librustzcash integrations.
//!
//! This crate deliberately contains no wallet database, synchronization, RPC,
//! transaction-construction, or UI integration. Its inputs are locally derived
//! wallet facts and its lock backend is an explicit seam for a later concrete
//! wallet implementation.

mod bond_prover;
mod guard;
mod inventory;
mod locking;
mod pending;
mod register;
mod selection;
mod source;
mod witness;

pub use guard::{
    CoppiceProtectionMode, ExactCanonicalTipError, HostCanonicalTipSource, SpendGuardError,
    WalletCanonicalTip, require_exact_canonical_tip, with_coppice_spend_guard,
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
pub use register::{
    BeginRegistrationError, CarrierPreparationError, CommitTransitionError, CompletionMismatch,
    LifecycleError, PrepareRevealError, PreparedCarrier, PreparedCommit, PreparedReveal,
    RegistrationBondMaterialSource, RegistrationOwner, RegistrationStage,
    abandon_expired_registration, abandon_registration, begin_registration, complete_registration,
    prepare_reveal, record_commit_broadcast, record_commit_mined,
    registration_matches_active_record, registration_stage,
};
pub use selection::{FreshnessEligibility, SelectedBondNote, select_bond_note};
pub use source::{
    InputSourceIronwoodNoteSource, IronwoodNoteConversionError, IronwoodNoteSourceError,
};
pub use witness::{
    AnchorContext, BondFreshnessContext, FreshnessContextError, IronwoodWitness,
    IronwoodWitnessSource, ResolveWitnessError, WalletCommitmentTreesIronwoodWitnessSource,
    WalletIronwoodWitnessError, anchor_for_registration, choose_current_anchor,
    freshness_for_canonical_commit, freshness_for_next_block_commit,
    resolve_canonical_ironwood_witness, select_fresh_bond_note,
};

pub use bond_prover::{WalletBondPrivateMaterial, WalletBondProverError, prove_selected_bond};
/// The exact pinned librustzcash lock-owner type used by this adapter.
pub use zcash_client_backend::wallet::LockOwner;
