#![cfg_attr(target_arch = "wasm32", no_std)]
// The frozen Casper ABI deliberately uses flattened typed arguments instead of
// opaque structs, and the initialization event has eight frozen fields.
#![allow(clippy::too_many_arguments)]

extern crate alloc;

mod encoding;

pub use encoding::{
    derive_action_id, derive_deployment_domain, derive_envelope_hash, derive_transfer_id,
    CommonHeader, NativeTransferV1, OfficialX402SettlementV1, ValidationError, CAIP2_NETWORK,
    CASPER_CHAIN_NAME, OFFICIAL_X402_SUPPORTED,
};

use alloc::string::String;
use encoding::{
    is_zero32, valid_proposal_id, ACTION_VERSION, NATIVE_TRANSFER_KIND, OFFICIAL_X402_KIND,
    SCHEMA_VERSION,
};
use odra::{
    casper_types::{U256, U512},
    prelude::*,
};

// Casper Testnet does not accept Wasm bulk-memory instructions. These explicit
// operations keep the pinned Odra build compatible with the chain runtime.
#[cfg(all(target_arch = "wasm32", not(test)))]
mod casper_memops {
    use core::ffi::c_void;

    #[no_mangle]
    pub unsafe extern "C" fn memcpy(
        dest: *mut c_void,
        src: *const c_void,
        n: usize,
    ) -> *mut c_void {
        let dest = dest.cast::<u8>();
        let src = src.cast::<u8>();
        let mut i = 0;
        while i < n {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
        dest.cast()
    }

    #[no_mangle]
    pub unsafe extern "C" fn memmove(
        dest: *mut c_void,
        src: *const c_void,
        n: usize,
    ) -> *mut c_void {
        if dest as usize <= src as usize || dest as usize >= src as usize + n {
            memcpy(dest, src, n)
        } else {
            let dest_bytes = dest.cast::<u8>();
            let src_bytes = src.cast::<u8>();
            let mut i = n;
            while i > 0 {
                i -= 1;
                *dest_bytes.add(i) = *src_bytes.add(i);
            }
            dest
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn memset(dest: *mut c_void, value: i32, n: usize) -> *mut c_void {
        let dest_bytes = dest.cast::<u8>();
        let mut i = 0;
        while i < n {
            *dest_bytes.add(i) = value as u8;
            i += 1;
        }
        dest
    }

    #[no_mangle]
    pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, n: usize) -> i32 {
        let left = left.cast::<u8>();
        let right = right.cast::<u8>();
        let mut i = 0;
        while i < n {
            let a = *left.add(i);
            let b = *right.add(i);
            if a != b {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        0
    }

    #[no_mangle]
    pub unsafe extern "C" fn bcmp(left: *const c_void, right: *const c_void, n: usize) -> i32 {
        memcmp(left, right, n)
    }
}

#[odra::odra_error]
pub enum GovernanceReceiptV3Error {
    InvalidSignerSet = 1,
    InvalidThreshold = 2,
    InvalidRoleAddress = 3,
    UnauthorizedProposer = 4,
    UnauthorizedSigner = 5,
    UnauthorizedFinalizer = 6,
    ProposalAlreadyExists = 7,
    QuorumNotMet = 8,
    ProposalMissing = 9,
    EnvelopeHashMismatch = 10,
    AlreadyApproved = 11,
    AlreadyFinalized = 12,
    ActionAlreadyAuthorized = 13,
    InvalidProposalId = 14,
    InvalidEnvelopeField = 15,
    InvalidActionField = 16,
}

/// Semantic identity accepted by the off-chain deployment boundary.
///
/// The frozen constructor wire type is `ByteArray(32)`, so the contract cannot
/// infer whether those bytes were originally supplied as an account, contract,
/// or contract-package identity. Release tooling must pass role identities
/// through [`validated_deployment_init_args`] before building install arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(not(target_arch = "wasm32"))]
pub enum DeploymentIdentity {
    Account([u8; 32]),
    Contract([u8; 32]),
    ContractPackage([u8; 32]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(not(target_arch = "wasm32"))]
pub struct DeploymentRoleInputs {
    pub proposer: DeploymentIdentity,
    pub finalizer: DeploymentIdentity,
    pub signer_a: DeploymentIdentity,
    pub signer_b: DeploymentIdentity,
    pub signer_c: DeploymentIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(not(target_arch = "wasm32"))]
pub enum DeploymentValidationError {
    InvalidSignerSet,
    InvalidThreshold,
    InvalidRoleAddress,
    InvalidEnvelopeField,
}

/// Builds the only release-approved constructor arguments after preserving the
/// account-only identity provenance that is intentionally absent on the wire.
#[cfg(not(target_arch = "wasm32"))]
pub fn validated_deployment_init_args(
    installer: DeploymentIdentity,
    roles: DeploymentRoleInputs,
    threshold: u8,
    casper_chain_name: String,
    installation_nonce: [u8; 32],
) -> Result<GovernanceReceiptV3InitArgs, DeploymentValidationError> {
    fn account(identity: DeploymentIdentity) -> Result<[u8; 32], DeploymentValidationError> {
        match identity {
            DeploymentIdentity::Account(value) if !is_zero32(&value) => Ok(value),
            DeploymentIdentity::Account(_)
            | DeploymentIdentity::Contract(_)
            | DeploymentIdentity::ContractPackage(_) => {
                Err(DeploymentValidationError::InvalidRoleAddress)
            }
        }
    }

    let installer = account(installer)?;
    let proposer = account(roles.proposer)?;
    let finalizer = account(roles.finalizer)?;
    let signer_a = account(roles.signer_a)?;
    let signer_b = account(roles.signer_b)?;
    let signer_c = account(roles.signer_c)?;
    let signers = [signer_a, signer_b, signer_c];
    if [proposer, finalizer, signer_a, signer_b, signer_c].contains(&installer)
        || proposer == finalizer
        || signers
            .iter()
            .any(|signer| *signer == proposer || *signer == finalizer)
    {
        return Err(DeploymentValidationError::InvalidRoleAddress);
    }
    if signer_a == signer_b || signer_a == signer_c || signer_b == signer_c {
        return Err(DeploymentValidationError::InvalidSignerSet);
    }
    if !matches!(threshold, 2 | 3) {
        return Err(DeploymentValidationError::InvalidThreshold);
    }
    derive_deployment_domain(&casper_chain_name, installation_nonce)
        .map_err(|_| DeploymentValidationError::InvalidEnvelopeField)?;
    Ok(GovernanceReceiptV3InitArgs {
        proposer,
        finalizer,
        signer_a,
        signer_b,
        signer_c,
        threshold,
        casper_chain_name,
        installation_nonce,
    })
}

#[allow(clippy::too_many_arguments)]
#[odra::event]
pub struct V3Initialized {
    pub schema_version: u32,
    pub deployment_domain: [u8; 32],
    pub proposer: [u8; 32],
    pub finalizer: [u8; 32],
    pub signer_a: [u8; 32],
    pub signer_b: [u8; 32],
    pub signer_c: [u8; 32],
    pub threshold: u8,
}

#[odra::event]
pub struct EnvelopeProposed {
    pub proposal_id: String,
    pub envelope_hash: [u8; 32],
    pub proposer: [u8; 32],
}

#[odra::event]
pub struct EnvelopeApproved {
    pub proposal_id: String,
    pub envelope_hash: [u8; 32],
    pub signer: [u8; 32],
    pub approval_count: u8,
}

#[odra::event]
pub struct EnvelopeFinalized {
    pub proposal_id: String,
    pub envelope_hash: [u8; 32],
    pub action_id: [u8; 32],
    pub finalizer: [u8; 32],
    pub approval_count: u8,
    pub schema_version: u32,
    pub action_kind: u8,
}

#[odra::module(
    events = [V3Initialized, EnvelopeProposed, EnvelopeApproved, EnvelopeFinalized],
    errors = GovernanceReceiptV3Error
)]
pub struct GovernanceReceiptV3 {
    owner: Var<[u8; 32]>,
    schema_version_value: Var<u32>,
    deployment_domain_value: Var<[u8; 32]>,
    chain_name: Var<String>,
    proposer_account: Var<[u8; 32]>,
    finalizer_account: Var<[u8; 32]>,
    signer_a_account: Var<[u8; 32]>,
    signer_b_account: Var<[u8; 32]>,
    signer_c_account: Var<[u8; 32]>,
    quorum_threshold: Var<u8>,
    signers: Mapping<[u8; 32], bool>,
    proposed_envelopes: Mapping<String, [u8; 32]>,
    approval_counts: Mapping<String, u8>,
    approvals: Mapping<(String, [u8; 32], [u8; 32]), bool>,
    finalized_proposals: Mapping<String, bool>,
    finalized_envelopes: Mapping<String, [u8; 32]>,
    authorized_actions: Mapping<[u8; 32], bool>,
}

#[odra::module]
impl GovernanceReceiptV3 {
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        &mut self,
        proposer: [u8; 32],
        finalizer: [u8; 32],
        signer_a: [u8; 32],
        signer_b: [u8; 32],
        signer_c: [u8; 32],
        threshold: u8,
        casper_chain_name: String,
        installation_nonce: [u8; 32],
    ) {
        let owner = self.caller_account_or_revert(GovernanceReceiptV3Error::InvalidRoleAddress);
        let roles = [proposer, finalizer, signer_a, signer_b, signer_c];
        if roles.iter().any(is_zero32) || roles.contains(&owner) {
            self.env()
                .revert(GovernanceReceiptV3Error::InvalidRoleAddress);
        }
        let governance_signers = [signer_a, signer_b, signer_c];
        if proposer == finalizer
            || governance_signers
                .iter()
                .any(|signer| *signer == proposer || *signer == finalizer)
        {
            self.env()
                .revert(GovernanceReceiptV3Error::InvalidRoleAddress);
        }
        for left in 0..governance_signers.len() {
            for right in left + 1..governance_signers.len() {
                if governance_signers[left] == governance_signers[right] {
                    self.env()
                        .revert(GovernanceReceiptV3Error::InvalidSignerSet);
                }
            }
        }
        if !matches!(threshold, 2 | 3) {
            self.env()
                .revert(GovernanceReceiptV3Error::InvalidThreshold);
        }
        let deployment_domain = derive_deployment_domain(&casper_chain_name, installation_nonce)
            .unwrap_or_else(|error| self.revert_validation(error));

        self.owner.set(owner);
        self.schema_version_value.set(SCHEMA_VERSION);
        self.deployment_domain_value.set(deployment_domain);
        self.chain_name.set(casper_chain_name);
        self.proposer_account.set(proposer);
        self.finalizer_account.set(finalizer);
        self.signer_a_account.set(signer_a);
        self.signer_b_account.set(signer_b);
        self.signer_c_account.set(signer_c);
        self.quorum_threshold.set(threshold);
        self.signers.set(&signer_a, true);
        self.signers.set(&signer_b, true);
        self.signers.set(&signer_c, true);
        self.env().emit_event(V3Initialized {
            schema_version: SCHEMA_VERSION,
            deployment_domain,
            proposer,
            finalizer,
            signer_a,
            signer_b,
            signer_c,
            threshold,
        });
    }

    pub fn propose_envelope(&mut self, proposal_id: String, envelope_hash: [u8; 32]) {
        let caller = self.caller_account_or_revert(GovernanceReceiptV3Error::UnauthorizedProposer);
        if caller != self.proposer() {
            self.env()
                .revert(GovernanceReceiptV3Error::UnauthorizedProposer);
        }
        if !valid_proposal_id(&proposal_id) {
            self.env()
                .revert(GovernanceReceiptV3Error::InvalidProposalId);
        }
        if self.proposed_envelopes.get(&proposal_id).is_some() {
            self.env()
                .revert(GovernanceReceiptV3Error::ProposalAlreadyExists);
        }
        self.proposed_envelopes.set(&proposal_id, envelope_hash);
        self.approval_counts.set(&proposal_id, 0);
        self.env().emit_event(EnvelopeProposed {
            proposal_id,
            envelope_hash,
            proposer: caller,
        });
    }

    pub fn approve_envelope(&mut self, proposal_id: String, envelope_hash: [u8; 32]) {
        let signer = self.caller_account_or_revert(GovernanceReceiptV3Error::UnauthorizedSigner);
        if !self.signers.get(&signer).unwrap_or(false) {
            self.env()
                .revert(GovernanceReceiptV3Error::UnauthorizedSigner);
        }
        if !valid_proposal_id(&proposal_id) {
            self.env()
                .revert(GovernanceReceiptV3Error::InvalidProposalId);
        }
        let committed = self
            .proposed_envelopes
            .get(&proposal_id)
            .unwrap_or_else(|| self.env().revert(GovernanceReceiptV3Error::ProposalMissing));
        if self.finalized(proposal_id.clone()) {
            self.env()
                .revert(GovernanceReceiptV3Error::AlreadyFinalized);
        }
        if committed != envelope_hash {
            self.env()
                .revert(GovernanceReceiptV3Error::EnvelopeHashMismatch);
        }
        let key = (proposal_id.clone(), envelope_hash, signer);
        if self.approvals.get(&key).unwrap_or(false) {
            self.env().revert(GovernanceReceiptV3Error::AlreadyApproved);
        }
        let count = self.approval_count(proposal_id.clone()) + 1;
        self.approvals.set(&key, true);
        self.approval_counts.set(&proposal_id, count);
        self.env().emit_event(EnvelopeApproved {
            proposal_id,
            envelope_hash,
            signer,
            approval_count: count,
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finalize_native_transfer(
        &mut self,
        proposal_id: String,
        proposal_nonce: [u8; 32],
        decision_code: u8,
        requested_allocation_bps: u32,
        approved_allocation_bps: u32,
        action_kind: u8,
        action_version: u32,
        action_id: [u8; 32],
        proposal_hash: [u8; 32],
        policy_hash: [u8; 32],
        plan_hash: [u8; 32],
        final_card_hash: [u8; 32],
        dissent_hash: [u8; 32],
        agent_action_hash: [u8; 32],
        preauth_evidence_root: [u8; 32],
        authorized_metadata_root: [u8; 32],
        asset_kind: u8,
        source_account: [u8; 32],
        recipient_account: [u8; 32],
        amount_motes: U512,
        treasury_snapshot_balance_motes: U512,
        snapshot_block_hash: [u8; 32],
        snapshot_block_height: u64,
        transfer_id: u64,
        action_nonce: [u8; 32],
        execution_target: String,
        execution_version: u32,
    ) -> [u8; 32] {
        self.require_finalization_preconditions(&proposal_id);
        let header = self.common_header(
            proposal_id.clone(),
            proposal_nonce,
            decision_code,
            requested_allocation_bps,
            approved_allocation_bps,
            action_kind,
            action_version,
            action_id,
            proposal_hash,
            policy_hash,
            plan_hash,
            final_card_hash,
            dissent_hash,
            agent_action_hash,
            preauth_evidence_root,
            authorized_metadata_root,
        );
        self.validate_header_basic(&header, NATIVE_TRANSFER_KIND);
        let body = NativeTransferV1 {
            asset_kind,
            source_account,
            recipient_account,
            amount_motes,
            treasury_snapshot_balance_motes,
            snapshot_block_hash,
            snapshot_block_height,
            transfer_id,
            action_nonce,
            execution_target,
            execution_version,
        };
        body.validate_basic()
            .unwrap_or_else(|error| self.revert_validation(error));
        let core = body
            .action_core_bytes()
            .unwrap_or_else(|error| self.revert_validation(error));
        if derive_action_id(action_kind, action_nonce, &core) != action_id {
            self.env()
                .revert(GovernanceReceiptV3Error::InvalidActionField);
        }
        let expected_transfer_id = derive_transfer_id(&proposal_id, proposal_nonce, action_id)
            .unwrap_or_else(|error| self.revert_validation(error));
        if transfer_id != expected_transfer_id {
            self.env()
                .revert(GovernanceReceiptV3Error::InvalidActionField);
        }
        let body_bytes = body
            .canonical_bytes()
            .unwrap_or_else(|error| self.revert_validation(error));
        let envelope_hash = derive_envelope_hash(&header, &body_bytes)
            .unwrap_or_else(|error| self.revert_validation(error));
        self.require_committed_hash(&proposal_id, envelope_hash);
        header
            .validate_semantics()
            .unwrap_or_else(|error| self.revert_validation(error));
        body.validate_semantics(approved_allocation_bps)
            .unwrap_or_else(|error| self.revert_validation(error));
        self.finish_finalization(proposal_id, envelope_hash, action_id, action_kind)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finalize_official_x402(
        &mut self,
        proposal_id: String,
        proposal_nonce: [u8; 32],
        decision_code: u8,
        requested_allocation_bps: u32,
        approved_allocation_bps: u32,
        action_kind: u8,
        action_version: u32,
        action_id: [u8; 32],
        proposal_hash: [u8; 32],
        policy_hash: [u8; 32],
        plan_hash: [u8; 32],
        final_card_hash: [u8; 32],
        dissent_hash: [u8; 32],
        agent_action_hash: [u8; 32],
        preauth_evidence_root: [u8; 32],
        authorized_metadata_root: [u8; 32],
        x402_version: u32,
        scheme: String,
        caip2_network: String,
        wcspr_package: [u8; 32],
        wcspr_contract: [u8; 32],
        token_name: String,
        token_symbol: String,
        eip712_domain_version: String,
        token_decimals: u8,
        payer: [u8; 32],
        payee: [u8; 32],
        value: U256,
        resource_url_hash: [u8; 32],
        report_hash: [u8; 32],
        payment_requirements_hash: [u8; 32],
        signed_payment_payload_hash: [u8; 32],
        eip712_auth_nonce: [u8; 32],
        valid_after: u64,
        valid_before: u64,
        action_nonce: [u8; 32],
        settlement_target: String,
        settlement_version: u32,
    ) -> [u8; 32] {
        self.require_finalization_preconditions(&proposal_id);
        let header = self.common_header(
            proposal_id.clone(),
            proposal_nonce,
            decision_code,
            requested_allocation_bps,
            approved_allocation_bps,
            action_kind,
            action_version,
            action_id,
            proposal_hash,
            policy_hash,
            plan_hash,
            final_card_hash,
            dissent_hash,
            agent_action_hash,
            preauth_evidence_root,
            authorized_metadata_root,
        );
        self.validate_header_basic(&header, OFFICIAL_X402_KIND);
        let body = OfficialX402SettlementV1 {
            x402_version,
            scheme,
            caip2_network,
            wcspr_package,
            wcspr_contract,
            token_name,
            token_symbol,
            eip712_domain_version,
            token_decimals,
            payer,
            payee,
            value,
            resource_url_hash,
            report_hash,
            payment_requirements_hash,
            signed_payment_payload_hash,
            eip712_auth_nonce,
            valid_after,
            valid_before,
            action_nonce,
            settlement_target,
            settlement_version,
        };
        body.validate_basic()
            .unwrap_or_else(|error| self.revert_validation(error));
        let core = body
            .action_core_bytes()
            .unwrap_or_else(|error| self.revert_validation(error));
        if derive_action_id(action_kind, action_nonce, &core) != action_id {
            self.env()
                .revert(GovernanceReceiptV3Error::InvalidActionField);
        }
        let body_bytes = body
            .canonical_bytes()
            .unwrap_or_else(|error| self.revert_validation(error));
        let envelope_hash = derive_envelope_hash(&header, &body_bytes)
            .unwrap_or_else(|error| self.revert_validation(error));
        self.require_committed_hash(&proposal_id, envelope_hash);
        header
            .validate_semantics()
            .unwrap_or_else(|error| self.revert_validation(error));
        body.validate_semantics()
            .unwrap_or_else(|error| self.revert_validation(error));
        self.finish_finalization(proposal_id, envelope_hash, action_id, action_kind)
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version_value.get_or_default()
    }

    pub fn deployment_domain(&self) -> [u8; 32] {
        self.deployment_domain_value.get_or_default()
    }

    pub fn casper_chain_name(&self) -> String {
        self.chain_name.get_or_default()
    }

    pub fn proposer(&self) -> [u8; 32] {
        self.proposer_account.get_or_default()
    }

    pub fn finalizer(&self) -> [u8; 32] {
        self.finalizer_account.get_or_default()
    }

    pub fn signer_a(&self) -> [u8; 32] {
        self.signer_a_account.get_or_default()
    }

    pub fn signer_b(&self) -> [u8; 32] {
        self.signer_b_account.get_or_default()
    }

    pub fn signer_c(&self) -> [u8; 32] {
        self.signer_c_account.get_or_default()
    }

    pub fn threshold(&self) -> u8 {
        self.quorum_threshold.get_or_default()
    }

    pub fn proposed_envelope(&self, proposal_id: String) -> Option<[u8; 32]> {
        self.proposed_envelopes.get(&proposal_id)
    }

    pub fn approval_count(&self, proposal_id: String) -> u8 {
        self.approval_counts.get(&proposal_id).unwrap_or(0)
    }

    pub fn has_approved(&self, proposal_id: String, signer: [u8; 32]) -> bool {
        let Some(envelope_hash) = self.proposed_envelopes.get(&proposal_id) else {
            return false;
        };
        self.approvals
            .get(&(proposal_id, envelope_hash, signer))
            .unwrap_or(false)
    }

    pub fn quorum_met(&self, proposal_id: String) -> bool {
        self.proposed_envelopes.get(&proposal_id).is_some()
            && self.approval_count(proposal_id) >= self.threshold()
    }

    pub fn finalized(&self, proposal_id: String) -> bool {
        self.finalized_proposals.get(&proposal_id).unwrap_or(false)
    }

    pub fn finalized_envelope(&self, proposal_id: String) -> Option<[u8; 32]> {
        self.finalized_envelopes.get(&proposal_id)
    }

    pub fn action_authorized(&self, action_id: [u8; 32]) -> bool {
        self.authorized_actions.get(&action_id).unwrap_or(false)
    }

    fn caller_account_or_revert(&self, error: GovernanceReceiptV3Error) -> [u8; 32] {
        self.env()
            .caller()
            .as_account_hash()
            .map(|account| account.value())
            .unwrap_or_else(|| self.env().revert(error))
    }

    fn require_finalization_preconditions(&self, proposal_id: &String) {
        let caller = self.caller_account_or_revert(GovernanceReceiptV3Error::UnauthorizedFinalizer);
        if caller != self.finalizer() {
            self.env()
                .revert(GovernanceReceiptV3Error::UnauthorizedFinalizer);
        }
        if !valid_proposal_id(proposal_id) {
            self.env()
                .revert(GovernanceReceiptV3Error::InvalidProposalId);
        }
        if self.proposed_envelopes.get(proposal_id).is_none() {
            self.env().revert(GovernanceReceiptV3Error::ProposalMissing);
        }
        if self.finalized(proposal_id.clone()) {
            self.env()
                .revert(GovernanceReceiptV3Error::AlreadyFinalized);
        }
        if !self.quorum_met(proposal_id.clone()) {
            self.env().revert(GovernanceReceiptV3Error::QuorumNotMet);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn common_header(
        &self,
        proposal_id: String,
        proposal_nonce: [u8; 32],
        decision_code: u8,
        requested_allocation_bps: u32,
        approved_allocation_bps: u32,
        action_kind: u8,
        action_version: u32,
        action_id: [u8; 32],
        proposal_hash: [u8; 32],
        policy_hash: [u8; 32],
        plan_hash: [u8; 32],
        final_card_hash: [u8; 32],
        dissent_hash: [u8; 32],
        agent_action_hash: [u8; 32],
        preauth_evidence_root: [u8; 32],
        authorized_metadata_root: [u8; 32],
    ) -> CommonHeader {
        CommonHeader {
            schema_version: SCHEMA_VERSION,
            deployment_domain: self.deployment_domain(),
            casper_chain_name: self.casper_chain_name(),
            proposal_id,
            proposal_nonce,
            decision_code,
            requested_allocation_bps,
            approved_allocation_bps,
            action_kind,
            action_version,
            action_id,
            proposal_hash,
            policy_hash,
            plan_hash,
            final_card_hash,
            dissent_hash,
            agent_action_hash,
            preauth_evidence_root,
            authorized_metadata_root,
        }
    }

    fn validate_header_basic(&self, header: &CommonHeader, expected_kind: u8) {
        header
            .validate_basic()
            .unwrap_or_else(|error| self.revert_validation(error));
        if header.action_kind != expected_kind || header.action_version != ACTION_VERSION {
            self.env()
                .revert(GovernanceReceiptV3Error::InvalidActionField);
        }
    }

    fn require_committed_hash(&self, proposal_id: &String, computed: [u8; 32]) {
        let committed = self
            .proposed_envelopes
            .get(proposal_id)
            .unwrap_or_else(|| self.env().revert(GovernanceReceiptV3Error::ProposalMissing));
        if computed != committed {
            self.env()
                .revert(GovernanceReceiptV3Error::EnvelopeHashMismatch);
        }
    }

    fn finish_finalization(
        &mut self,
        proposal_id: String,
        envelope_hash: [u8; 32],
        action_id: [u8; 32],
        action_kind: u8,
    ) -> [u8; 32] {
        if self.action_authorized(action_id) {
            self.env()
                .revert(GovernanceReceiptV3Error::ActionAlreadyAuthorized);
        }
        let finalizer = self.finalizer();
        let approval_count = self.approval_count(proposal_id.clone());
        self.finalized_proposals.set(&proposal_id, true);
        self.finalized_envelopes.set(&proposal_id, envelope_hash);
        self.authorized_actions.set(&action_id, true);
        self.env().emit_event(EnvelopeFinalized {
            proposal_id,
            envelope_hash,
            action_id,
            finalizer,
            approval_count,
            schema_version: SCHEMA_VERSION,
            action_kind,
        });
        envelope_hash
    }

    fn revert_validation(&self, error: ValidationError) -> ! {
        match error {
            ValidationError::InvalidProposalId => self
                .env()
                .revert(GovernanceReceiptV3Error::InvalidProposalId),
            ValidationError::InvalidEnvelopeField => self
                .env()
                .revert(GovernanceReceiptV3Error::InvalidEnvelopeField),
            ValidationError::InvalidActionField => self
                .env()
                .revert(GovernanceReceiptV3Error::InvalidActionField),
        }
    }
}
