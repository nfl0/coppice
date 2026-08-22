//! Dedicated Coppice carrier transactions through the normal librustzcash
//! proposal and transaction-construction path.

use std::fmt::Debug;

use coppice::{
    carrier::{V1CarrierError, inspect_v1_bulletin_for},
    config::{DeploymentParameters, Rendezvous},
    constants::MAX_TRANSACTION_LEN,
    envelope,
    reducer_v1::V1Reducer,
};
use sapling::prover::{OutputProver, SpendProver};
use zcash_client_backend::{
    data_api::{
        InputSource, WalletCommitmentTrees, WalletRead, WalletWrite,
        wallet::{
            ConfirmationsPolicy, CreateErrT, LockRequest, ProposeTransferErrT, SpendingKeys,
            create_proposed_transactions,
            input_selection::{InputSelector, SpendPolicy},
            propose_transfer,
        },
    },
    fees::ChangeStrategy,
    proposal::Proposal,
    wallet::OvkPolicy,
};
use zcash_keys::address::UnifiedAddress;
use zcash_primitives::transaction::{Transaction, TxId, fees::FeeRule};
use zcash_protocol::{
    PoolType,
    consensus::{self, BlockHeight, NetworkUpgrade},
    memo::{Error as MemoBytesError, MemoBytes},
    value::Zatoshis,
};
use zip321::{Payment, PaymentError, TransactionRequest, Zip321Error};

use crate::{
    CoppiceLockBackend, CoppiceProtectionMode, HostCanonicalTipSource, IronwoodViewingCapability,
    PendingRegistrationCollection, PreparedCarrier, SpendGuardError, with_coppice_spend_guard,
};

#[derive(Debug)]
pub enum CarrierTransactionRequestError {
    InvalidDeployment,
    InvalidRendezvous,
    InvalidFrameMemo(MemoBytesError),
    InvalidPayment(PaymentError),
    InvalidRequest(Zip321Error),
}

/// Purely maps one prepared frame to one zero-valued rendezvous payment.
pub fn carrier_transaction_request(
    deployment: &DeploymentParameters,
    prepared: &PreparedCarrier,
) -> Result<TransactionRequest, CarrierTransactionRequestError> {
    deployment
        .validate()
        .map_err(|_| CarrierTransactionRequestError::InvalidDeployment)?;
    let orchard = coppice::carrier::bulletin_address(deployment.rendezvous)
        .map_err(|_| CarrierTransactionRequestError::InvalidRendezvous)?;
    let ua = UnifiedAddress::from_receivers(Some(orchard), None, None)
        .ok_or(CarrierTransactionRequestError::InvalidRendezvous)?;
    if ua.orchard().map(orchard::Address::to_raw_address_bytes)
        != Some(deployment.rendezvous.orchard_receiver)
    {
        return Err(CarrierTransactionRequestError::InvalidRendezvous);
    }
    let recipient = ua.to_zcash_address(deployment.address_network);
    let payments = prepared
        .frames()
        .iter()
        .map(|frame| {
            let memo = MemoBytes::from_bytes(frame)
                .map_err(CarrierTransactionRequestError::InvalidFrameMemo)?;
            Payment::new(
                recipient.clone(),
                Some(Zatoshis::ZERO),
                Some(memo),
                None,
                None,
                vec![],
            )
            .map_err(CarrierTransactionRequestError::InvalidPayment)
        })
        .collect::<Result<Vec<_>, _>>()?;
    TransactionRequest::new(payments).map_err(CarrierTransactionRequestError::InvalidRequest)
}

/// A proposal tied to the unpublished carrier material it must construct.
/// This intentionally has no `Debug`.
pub struct PreparedCarrierProposal<'a, FeeRuleT, NoteRef> {
    proposal: Proposal<FeeRuleT, NoteRef>,
    prepared: &'a PreparedCarrier,
    rendezvous: Rendezvous,
    deployment_id: [u8; 32],
}

impl<FeeRuleT, NoteRef> PreparedCarrierProposal<'_, FeeRuleT, NoteRef> {
    pub fn proposal(&self) -> &Proposal<FeeRuleT, NoteRef> {
        &self.proposal
    }

    pub fn frame_count(&self) -> usize {
        self.prepared.frames().len()
    }
}

#[derive(Debug)]
pub enum CarrierProposalError<HostError, LockError: Debug, ProposalError> {
    Request(CarrierTransactionRequestError),
    NetworkMismatch,
    LockedInputsPermitted,
    SpendGuard(SpendGuardError<HostError, LockError>),
    Proposal(ProposalError),
    TargetHeightOverflow,
    UnexpectedTargetHeight { expected: u32, actual: u32 },
    IronwoodNotActive { target_height: u32 },
    CarrierPaymentNotIronwood { payment_index: usize },
    MultiStepCarrierProposalUnsupported { steps: usize },
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn propose_carrier_transaction<
    'a,
    Host,
    LockBackend,
    DbT,
    ParamsT,
    InputsT,
    ChangeT,
    CommitmentTreeErrT,
>(
    mode: CoppiceProtectionMode,
    host_tip_source: &Host,
    reducer: &V1Reducer,
    pending: &PendingRegistrationCollection,
    capability: IronwoodViewingCapability,
    lock_backend: &mut LockBackend,
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_from_account: <DbT as InputSource>::AccountId,
    input_selector: &InputsT,
    change_strategy: &ChangeT,
    confirmations_policy: ConfirmationsPolicy,
    spend_policy: &SpendPolicy,
    lock_inputs: Option<LockRequest>,
    prepared: &'a PreparedCarrier,
) -> Result<
    PreparedCarrierProposal<'a, ChangeT::FeeRule, DbT::NoteRef>,
    CarrierProposalError<
        Host::Error,
        LockBackend::Error,
        ProposeTransferErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT>,
    >,
>
where
    Host: HostCanonicalTipSource,
    LockBackend: CoppiceLockBackend,
    DbT: WalletWrite + InputSource<Error = <DbT as WalletRead>::Error>,
    DbT::NoteRef: Copy + Eq + Ord,
    ParamsT: consensus::Parameters + Clone,
    InputsT: InputSelector<InputSource = DbT>,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
{
    if params.network_type() != reducer.deployment().address_network {
        return Err(CarrierProposalError::NetworkMismatch);
    }
    if spend_policy.locked_input_policy().admits_locked() {
        return Err(CarrierProposalError::LockedInputsPermitted);
    }
    let request = carrier_transaction_request(reducer.deployment(), prepared)
        .map_err(CarrierProposalError::Request)?;
    let expected_height = reducer
        .tip()
        .height
        .checked_add(1)
        .ok_or(CarrierProposalError::TargetHeightOverflow)?;
    let (proposal_result, _) = with_coppice_spend_guard(
        mode,
        host_tip_source,
        reducer,
        pending,
        capability,
        lock_backend,
        || {
            propose_transfer(
                wallet_db,
                params,
                spend_from_account,
                input_selector,
                change_strategy,
                request,
                confirmations_policy,
                spend_policy,
                lock_inputs,
                None,
            )
        },
    )
    .map_err(CarrierProposalError::SpendGuard)?;
    let proposal = proposal_result.map_err(CarrierProposalError::Proposal)?;
    let target_height: u32 = BlockHeight::from(proposal.min_target_height()).into();
    if target_height != expected_height {
        return Err(CarrierProposalError::UnexpectedTargetHeight {
            expected: expected_height,
            actual: target_height,
        });
    }
    if !params.is_nu_active(NetworkUpgrade::Nu6_3, BlockHeight::from_u32(target_height)) {
        return Err(CarrierProposalError::IronwoodNotActive { target_height });
    }
    if proposal.steps().len() != 1 {
        return Err(CarrierProposalError::MultiStepCarrierProposalUnsupported {
            steps: proposal.steps().len(),
        });
    }
    let step = proposal.steps().first();
    for index in 0..prepared.frames().len() {
        if step.payment_pools().get(&index) != Some(&PoolType::IRONWOOD) {
            return Err(CarrierProposalError::CarrierPaymentNotIronwood {
                payment_index: index,
            });
        }
    }
    Ok(PreparedCarrierProposal {
        proposal,
        prepared,
        rendezvous: reducer.deployment().rendezvous,
        deployment_id: reducer.deployment_id(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConstructedCarrierTransaction {
    pub txid: TxId,
    pub frame_count: usize,
    pub serialized_size: usize,
}

#[derive(Debug)]
pub enum CarrierConstructionError<DbError, ConstructionError> {
    InvalidExpectedPayload,
    Construction(ConstructionError),
    UnexpectedTransactionCount { count: usize },
    ConstructedTransactionUnavailable(DbError),
    MissingConstructedTransaction,
    MissingIronwoodBundle,
    BulletinDecode(V1CarrierError),
    BulletinFrameCountMismatch { expected: usize, actual: usize },
    BulletinFrameMismatch { index: usize },
    PayloadMismatch,
    Serialization,
    TransactionTooLarge { size: usize },
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn create_carrier_transaction<DbT, ParamsT, InputsErrT, FeeRuleT, ChangeErrT, N>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_prover: &impl SpendProver,
    output_prover: &impl OutputProver,
    spending_keys: &SpendingKeys,
    ovk_policy: OvkPolicy,
    prepared: PreparedCarrierProposal<'_, FeeRuleT, N>,
    expiry_height: Option<BlockHeight>,
) -> Result<
    ConstructedCarrierTransaction,
    CarrierConstructionError<
        <DbT as WalletRead>::Error,
        CreateErrT<DbT, InputsErrT, FeeRuleT, ChangeErrT, N>,
    >,
>
where
    DbT: WalletWrite + WalletCommitmentTrees,
    ParamsT: consensus::Parameters + Clone,
    FeeRuleT: FeeRule,
{
    let expected_operation = envelope::decode_operation(prepared.prepared.payload())
        .map_err(|_| CarrierConstructionError::InvalidExpectedPayload)?;
    let txids = create_proposed_transactions(
        wallet_db,
        params,
        spend_prover,
        output_prover,
        spending_keys,
        ovk_policy,
        &prepared.proposal,
        expiry_height,
    )
    .map_err(CarrierConstructionError::Construction)?;
    if txids.len() != 1 {
        return Err(CarrierConstructionError::UnexpectedTransactionCount { count: txids.len() });
    }
    let txid = *txids.first();
    let tx: Transaction = wallet_db
        .get_transaction(txid)
        .map_err(CarrierConstructionError::ConstructedTransactionUnavailable)?
        .ok_or(CarrierConstructionError::MissingConstructedTransaction)?;
    if tx.ironwood_bundle().is_none() {
        return Err(CarrierConstructionError::MissingIronwoodBundle);
    }
    let inspection = inspect_v1_bulletin_for(&tx, prepared.rendezvous, prepared.deployment_id)
        .map_err(CarrierConstructionError::BulletinDecode)?;
    if inspection.frames().len() != prepared.prepared.frames().len() {
        return Err(CarrierConstructionError::BulletinFrameCountMismatch {
            expected: prepared.prepared.frames().len(),
            actual: inspection.frames().len(),
        });
    }
    for (index, expected) in prepared.prepared.frames().iter().enumerate() {
        if !inspection.frames().contains(expected) {
            return Err(CarrierConstructionError::BulletinFrameMismatch { index });
        }
    }
    if inspection.operation() != &expected_operation
        || envelope::encode_operation(inspection.operation())
            .ok()
            .as_deref()
            != Some(prepared.prepared.payload())
        || inspection.payload() != prepared.prepared.payload()
    {
        return Err(CarrierConstructionError::PayloadMismatch);
    }
    let mut encoded = Vec::new();
    tx.write(&mut encoded)
        .map_err(|_| CarrierConstructionError::Serialization)?;
    let serialized_size = encoded.len();
    if serialized_size > MAX_TRANSACTION_LEN {
        return Err(CarrierConstructionError::TransactionTooLarge {
            size: serialized_size,
        });
    }
    Ok(ConstructedCarrierTransaction {
        txid,
        frame_count: prepared.prepared.frames().len(),
        serialized_size,
    })
}

#[cfg(test)]
mod tests {
    use coppice::{
        config::DeploymentParameters,
        constants::{MAX_ADDRESS_LEN, MAX_BOND_PROOF_LEN, REGTEST_V0_ACTIVATION_HEIGHT},
        envelope::Operation,
    };
    use zcash_protocol::consensus::NetworkType;

    use super::*;

    fn deployment() -> DeploymentParameters {
        let input: serde_json::Value =
            serde_json::from_str(include_str!("../../../test-vectors/deployment.json")).unwrap();
        let input = &input["input"];
        DeploymentParameters {
            network_id: hex::decode(input["network_id_hex"].as_str().unwrap()).unwrap(),
            address_network: NetworkType::Regtest,
            activation_height: REGTEST_V0_ACTIVATION_HEIGHT,
            minimum_bond_value: input["minimum_bond_value"].as_u64().unwrap(),
            commit_ttl_blocks: input["commit_ttl_blocks"].as_u64().unwrap() as u32,
            reuse_delay_blocks: input["reuse_delay_blocks"].as_u64().unwrap() as u32,
            bond_note_max_age_blocks: input["bond_note_max_age_blocks"].as_u64().unwrap() as u32,
            rendezvous: coppice::config::Rendezvous {
                orchard_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                orchard_receiver: hex::decode(input["rendezvous_receiver_hex"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            },
        }
    }

    fn prepared(deployment: &DeploymentParameters, operation: Operation) -> PreparedCarrier {
        PreparedCarrier::from_operation(deployment.deployment_id().unwrap(), &operation).unwrap()
    }

    fn assert_request(operation: Operation, expected_frames: usize) {
        let deployment = deployment();
        let prepared = prepared(&deployment, operation);
        assert_eq!(prepared.frames().len(), expected_frames);
        let request = carrier_transaction_request(&deployment, &prepared).unwrap();
        assert_eq!(request.payments().len(), expected_frames);

        let orchard = coppice::carrier::bulletin_address(deployment.rendezvous).unwrap();
        let ua = UnifiedAddress::from_receivers(Some(orchard), None, None).unwrap();
        assert_eq!(
            ua.orchard().unwrap().to_raw_address_bytes(),
            deployment.rendezvous.orchard_receiver
        );
        let expected_recipient = ua.to_zcash_address(deployment.address_network);
        for (index, payment) in request.payments() {
            assert_eq!(payment.recipient_address(), &expected_recipient);
            assert_eq!(payment.amount(), Some(Zatoshis::ZERO));
            let memo = payment.memo().unwrap();
            assert_eq!(memo.as_array(), &prepared.frames()[*index]);
            assert_eq!(memo.as_array()[0], 0xff);
        }
    }

    #[test]
    fn commit_maps_one_frame_to_one_exact_zero_valued_payment() {
        assert_request(
            Operation::Commit {
                commitment: [7; 32],
            },
            1,
        );
    }

    #[test]
    fn reveal_maps_twelve_frames_without_memo_mutation() {
        assert_request(
            Operation::Reveal {
                name: "carrier".to_owned(),
                owner_pk: [1; 32],
                bond_tag: [2; 32],
                bond_anchor_height: 100,
                bond_anchor: [3; 32],
                bond_proof: vec![4; 4_960],
                address: vec![5; MAX_ADDRESS_LEN],
                secret: [6; 32],
            },
            12,
        );
    }

    #[test]
    fn syntactic_max_reveal_maps_eighteen_distinct_payments() {
        assert_request(
            Operation::Reveal {
                name: "n".repeat(coppice::constants::MAX_NAME_LEN),
                owner_pk: [1; 32],
                bond_tag: [2; 32],
                bond_anchor_height: u32::MAX,
                bond_anchor: [3; 32],
                bond_proof: vec![4; MAX_BOND_PROOF_LEN],
                address: vec![5; MAX_ADDRESS_LEN],
                secret: [6; 32],
            },
            18,
        );
    }
}
