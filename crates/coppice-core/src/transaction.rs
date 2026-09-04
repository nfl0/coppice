//! Host-owned transaction boundaries for large stateful applications.
//!
//! Core intentionally does not choose a storage engine. A host implements
//! [`TransactionHost`] for its database and passes the borrowed transaction to
//! every participating layer. The higher-ranked closure prevents that borrowed
//! transaction from escaping its commit/rollback scope.

use crate::application::{
    ApplicationAcquisitionRequirement, ApplicationBlockContext,
    ApplicationCompactTransactionSummary, ApplicationDescriptor, ApplicationTip,
};

/// A storage engine capable of running one closure in an atomic transaction.
///
/// Implementations must commit if and only if `operation` returns `Ok`. An
/// error or unwind must roll back all writes. Hosts should poison and restart
/// their runtime after an unwind rather than attempting to continue with
/// possibly inconsistent non-durable state.
pub trait TransactionHost {
    type Error;
    type Transaction<'tx>
    where
        Self: 'tx;

    fn with_transaction<R, F>(&mut self, operation: F) -> Result<R, Self::Error>
    where
        F: for<'tx> FnOnce(&mut Self::Transaction<'tx>) -> Result<R, Self::Error>;
}

/// Optional application lifecycle for state too large to clone per block.
///
/// The application value contains immutable configuration and behavior. All
/// mutable state is read and written through the host's borrowed `Tx`, allowing
/// wallet scan state, Core persistence, application records, derived indexes,
/// and rollback journals to share one outer transaction.
///
/// Applications opt into this trait explicitly. The existing
/// [`crate::application::CoppiceApplication`] interface remains the simpler
/// clone-staged choice for small state machines.
pub trait TransactionalCoppiceApplication<Tx: ?Sized> {
    type BlockOutput;
    type StateError;
    type ApplyError;
    type RewindError;

    fn descriptor(&self) -> ApplicationDescriptor;
    fn tip(&self, transaction: &Tx) -> Result<ApplicationTip, Self::StateError>;
    fn state_root(&self, transaction: &Tx) -> Result<[u8; 32], Self::StateError>;
    fn apply_block(
        &self,
        transaction: &mut Tx,
        block: &ApplicationBlockContext,
    ) -> Result<Self::BlockOutput, Self::ApplyError>;
    fn rewind_to(&self, transaction: &mut Tx, height: u32) -> Result<(), Self::RewindError>;
    fn rewind_retention_blocks(&self) -> u32;
    fn oldest_rewind_height(&self, transaction: &Tx) -> Result<u32, Self::StateError>;
    fn retained_tip_at(
        &self,
        transaction: &Tx,
        height: u32,
    ) -> Result<Option<ApplicationTip>, Self::StateError>;

    fn full_transaction_acquisition(
        &self,
        _summary: &ApplicationCompactTransactionSummary<'_>,
    ) -> ApplicationAcquisitionRequirement {
        ApplicationAcquisitionRequirement::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryHost {
        durable: u32,
    }

    struct MemoryTransaction {
        staged: u32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Error {
        Injected,
    }

    impl TransactionHost for MemoryHost {
        type Error = Error;
        type Transaction<'tx> = MemoryTransaction;

        fn with_transaction<R, F>(&mut self, operation: F) -> Result<R, Self::Error>
        where
            F: for<'tx> FnOnce(&mut Self::Transaction<'tx>) -> Result<R, Self::Error>,
        {
            let mut transaction = MemoryTransaction {
                staged: self.durable,
            };
            let output = operation(&mut transaction)?;
            self.durable = transaction.staged;
            Ok(output)
        }
    }

    #[test]
    fn transaction_host_commits_only_successful_closures() {
        let mut host = MemoryHost::default();
        host.with_transaction(|transaction| {
            transaction.staged = 7;
            Ok(())
        })
        .unwrap();
        assert_eq!(host.durable, 7);

        assert_eq!(
            host.with_transaction(|transaction| {
                transaction.staged = 9;
                Err::<(), _>(Error::Injected)
            }),
            Err(Error::Injected)
        );
        assert_eq!(host.durable, 7);
    }
}
