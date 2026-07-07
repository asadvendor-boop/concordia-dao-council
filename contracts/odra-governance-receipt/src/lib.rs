//! Odra-oriented Concordia governance migration package.
//!
//! The canonical live qualification proof uses the deployed Odra
//! `GovernanceReceipt` contract. This crate also implements the production
//! migration topology split into separate governance domains:
//! - council credential registry
//! - tamper-evident card index
//! - treasury policy limits
//! - typed governance receipt anchoring
//!
//! The canonical reviewer proof exercises the `GovernanceReceipt` entry point.
//! A supplemental topology-genesis proof independently installs and calls the
//! registry, card-index, and treasury-policy modules on Casper Testnet; those
//! calls prove module execution without replacing the canonical receipt.

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use alloc::format;
use odra::prelude::*;

// Casper Testnet currently rejects Wasm that relies on the bulk-memory proposal.
// These explicit memory operations keep the Odra Wasm compatible with Casper's
// runtime while still allowing the same source to run under native tests.
#[cfg(all(target_arch = "wasm32", not(test)))]
mod casper_memops {
    use core::ffi::c_void;

    #[no_mangle]
    pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        let dest_bytes = dest.cast::<u8>();
        let src_bytes = src.cast::<u8>();
        let mut i = 0;
        while i < n {
            *dest_bytes.add(i) = *src_bytes.add(i);
            i += 1;
        }
        dest
    }

    #[no_mangle]
    pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
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
        let left_bytes = left.cast::<u8>();
        let right_bytes = right.cast::<u8>();
        let mut i = 0;
        while i < n {
            let a = *left_bytes.add(i);
            let b = *right_bytes.add(i);
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

fn hex32(bytes: &[u8; 32]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    for byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}

#[odra::module]
pub struct CouncilRegistry {
    agents: Mapping<String, String>,
}

#[odra::module]
impl CouncilRegistry {
    pub fn register_agent(&mut self, agent_id: String, public_key_hex: String) {
        self.agents.set(&agent_id, public_key_hex);
    }

    pub fn get_agent_key(&self, agent_id: String) -> Option<String> {
        self.agents.get(&agent_id)
    }
}

#[odra::module]
pub struct CardIndexLedger {
    card_roots: Mapping<String, String>,
}

#[odra::module]
impl CardIndexLedger {
    pub fn seal_card_root(&mut self, proposal_id: String, sequence: u32, card_root_hex: String) {
        let key = format!("{}:{}", proposal_id, sequence);
        self.card_roots.set(&key, card_root_hex);
    }

    pub fn get_card_root(&self, proposal_id: String, sequence: u32) -> Option<String> {
        let key = format!("{}:{}", proposal_id, sequence);
        self.card_roots.get(&key)
    }
}

#[odra::module]
pub struct TreasuryPolicy {
    max_single_allocation_bps: Var<u32>,
    max_high_risk_allocation_bps: Var<u32>,
}

#[odra::module]
impl TreasuryPolicy {
    pub fn init(&mut self, max_single_allocation_bps: u32, max_high_risk_allocation_bps: u32) {
        self.max_single_allocation_bps.set(max_single_allocation_bps);
        self.max_high_risk_allocation_bps.set(max_high_risk_allocation_bps);
    }

    pub fn validate_allocation(&self, requested_bps: u32, high_risk: bool) -> bool {
        let cap = if high_risk {
            self.max_high_risk_allocation_bps.get_or_default()
        } else {
            self.max_single_allocation_bps.get_or_default()
        };
        requested_bps <= cap
    }

    pub fn current_caps(&self) -> String {
        format!(
            "{{\"max_single_allocation_bps\":{},\"max_high_risk_allocation_bps\":{}}}",
            self.max_single_allocation_bps.get_or_default(),
            self.max_high_risk_allocation_bps.get_or_default()
        )
    }
}

#[odra::module]
pub struct GovernanceReceipt {
    owner: Var<Address>,
    quorum_configured: Var<bool>,
    quorum_threshold: Var<u32>,
    signer_count: Var<u32>,
    signers: Mapping<Address, bool>,
    proposed_envelopes: Mapping<String, String>,
    approval_counts: Mapping<String, u32>,
    approvals: Mapping<(String, Address), bool>,
    receipts: Mapping<String, String>,
}

#[odra::odra_error]
pub enum GovernanceReceiptError {
    QuorumAlreadyConfigured = 1,
    InvalidQuorum = 2,
    QuorumNotConfigured = 3,
    UnauthorizedSigner = 4,
    EnvelopeAlreadyProposed = 5,
    EnvelopeMissing = 6,
    AlreadyApproved = 7,
    QuorumNotMet = 8,
}

#[odra::module]
impl GovernanceReceipt {
    /// Configure the caller-bound signer set for receipt execution.
    ///
    /// This is intentionally simple and demo-friendly: a DAO owner configures
    /// three signers and a threshold, then every final receipt must reference a
    /// proposed envelope approved by at least `threshold` distinct signers.
    pub fn configure_quorum(
        &mut self,
        signer_a: Address,
        signer_b: Address,
        signer_c: Address,
        threshold: u32,
    ) {
        if self.quorum_configured.get_or_default() {
            self.env()
                .revert(GovernanceReceiptError::QuorumAlreadyConfigured);
        }
        if threshold == 0 || threshold > 3 {
            self.env().revert(GovernanceReceiptError::InvalidQuorum);
        }
        self.owner.set(self.env().caller());
        self.signers.set(&signer_a, true);
        self.signers.set(&signer_b, true);
        self.signers.set(&signer_c, true);
        self.signer_count.set(3);
        self.quorum_threshold.set(threshold);
        self.quorum_configured.set(true);
    }

    /// Propose the exact approved envelope root before signer approvals.
    pub fn propose_envelope(&mut self, proposal_id: String, envelope_hash: [u8; 32]) {
        self.require_signer();
        if self.proposed_envelopes.get(&proposal_id).is_some() {
            self.env()
                .revert(GovernanceReceiptError::EnvelopeAlreadyProposed);
        }
        self.proposed_envelopes.set(&proposal_id, hex32(&envelope_hash));
        self.approval_counts.set(&proposal_id, 0);
    }

    /// Approve an existing envelope as the current Casper caller.
    pub fn approve_envelope(&mut self, proposal_id: String) {
        self.require_signer();
        if self.proposed_envelopes.get(&proposal_id).is_none() {
            self.env().revert(GovernanceReceiptError::EnvelopeMissing);
        }
        let caller = self.env().caller();
        let marker = (proposal_id.clone(), caller);
        if self.approvals.get(&marker).unwrap_or(false) {
            self.env().revert(GovernanceReceiptError::AlreadyApproved);
        }
        self.approvals.set(&marker, true);
        let next = self.approval_counts.get(&proposal_id).unwrap_or(0) + 1;
        self.approval_counts.set(&proposal_id, next);
    }

    pub fn quorum_status(&self, proposal_id: String) -> String {
        let approvals = self.approval_counts.get(&proposal_id).unwrap_or(0);
        let threshold = self.quorum_threshold.get_or_default();
        format!(
            "{{\"proposal_id\":\"{}\",\"configured\":{},\"approvals\":{},\"threshold\":{},\"quorum_met\":{}}}",
            proposal_id,
            self.quorum_configured.get_or_default(),
            approvals,
            threshold,
            self.quorum_met(&proposal_id)
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn store_governance_receipt(
        &mut self,
        proposal_id: String,
        proposal_type: String,
        proposal_hash: [u8; 32],
        final_card_hash: [u8; 32],
        plan_hash: [u8; 32],
        decision: String,
        risk_level: String,
        risk_score: u32,
        treasury_action: String,
        policy_hash: [u8; 32],
        policy_version: String,
        dissent_hash: [u8; 32],
        approved_allocation_bps: u32,
        casper_network: String,
        agent_council_version: String,
        evidence_uri: String,
        agent_action_hash: [u8; 32],
    ) {
        self.require_quorum(&proposal_id);
        let receipt = format!(
            "{{\"proposal_id\":\"{}\",\"proposal_type\":\"{}\",\"proposal_hash\":\"{}\",\"final_card_hash\":\"{}\",\"plan_hash\":\"{}\",\"decision\":\"{}\",\"risk_level\":\"{}\",\"risk_score\":{},\"treasury_action\":\"{}\",\"policy_hash\":\"{}\",\"policy_version\":\"{}\",\"dissent_hash\":\"{}\",\"approved_allocation_bps\":{},\"casper_network\":\"{}\",\"agent_council_version\":\"{}\",\"evidence_uri\":\"{}\",\"agent_action_hash\":\"{}\"}}",
            proposal_id,
            proposal_type,
            hex32(&proposal_hash),
            hex32(&final_card_hash),
            hex32(&plan_hash),
            decision,
            risk_level,
            risk_score,
            treasury_action,
            hex32(&policy_hash),
            policy_version,
            hex32(&dissent_hash),
            approved_allocation_bps,
            casper_network,
            agent_council_version,
            evidence_uri,
            hex32(&agent_action_hash),
        );
        self.receipts.set(&proposal_id, receipt);
    }

    pub fn get_receipt(&self, proposal_id: String) -> Option<String> {
        self.receipts.get(&proposal_id)
    }

    fn require_signer(&self) {
        if !self.quorum_configured.get_or_default() {
            self.env().revert(GovernanceReceiptError::QuorumNotConfigured);
        }
        let caller = self.env().caller();
        if !self.signers.get(&caller).unwrap_or(false) {
            self.env().revert(GovernanceReceiptError::UnauthorizedSigner);
        }
    }

    fn quorum_met(&self, proposal_id: &String) -> bool {
        let approvals = self.approval_counts.get(proposal_id).unwrap_or(0);
        let threshold = self.quorum_threshold.get_or_default();
        threshold > 0 && approvals >= threshold
    }

    fn require_quorum(&self, proposal_id: &String) {
        if !self.quorum_configured.get_or_default() {
            self.env().revert(GovernanceReceiptError::QuorumNotConfigured);
        }
        if self.proposed_envelopes.get(proposal_id).is_none() {
            self.env().revert(GovernanceReceiptError::EnvelopeMissing);
        }
        if !self.quorum_met(proposal_id) {
            self.env().revert(GovernanceReceiptError::QuorumNotMet);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odra::host::{Deployer, NoArgs};

    fn h(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[allow(clippy::too_many_arguments)]
    fn store_sample(contract: &mut GovernanceReceiptHostRef, proposal_id: &str) {
        contract.store_governance_receipt(
            proposal_id.to_string(),
            "DEFI_TREASURY_REALLOCATION".to_string(),
            h(1),
            h(2),
            h(3),
            "APPROVED_WITH_LIMITS".to_string(),
            "MEDIUM".to_string(),
            61,
            "cap_to_800_bps".to_string(),
            h(4),
            "2026.06.cas-v1".to_string(),
            h(5),
            800,
            "casper-test".to_string(),
            "concordia-dao-council-2026.06".to_string(),
            "ipfs://bafkrei...".to_string(),
            h(6),
        );
    }

    #[test]
    fn quorum_blocks_until_two_distinct_signers_approve() {
        let env = odra_test::env();
        let signer_a = env.get_account(0);
        let signer_b = env.get_account(1);
        let signer_c = env.get_account(2);
        let mut receipt = GovernanceReceipt::deploy(&env, NoArgs);

        receipt.configure_quorum(signer_a, signer_b, signer_c, 2);
        receipt.propose_envelope("DAO-PROP-6CB25C".to_string(), h(9));

        let before_quorum = receipt.try_store_governance_receipt(
            "DAO-PROP-6CB25C".to_string(),
            "DEFI_TREASURY_REALLOCATION".to_string(),
            h(1),
            h(2),
            h(3),
            "APPROVED_WITH_LIMITS".to_string(),
            "MEDIUM".to_string(),
            61,
            "cap_to_800_bps".to_string(),
            h(4),
            "2026.06.cas-v1".to_string(),
            h(5),
            800,
            "casper-test".to_string(),
            "concordia-dao-council-2026.06".to_string(),
            "ipfs://bafkrei...".to_string(),
            h(6),
        );
        assert_eq!(
            before_quorum.unwrap_err(),
            GovernanceReceiptError::QuorumNotMet.into()
        );

        receipt.approve_envelope("DAO-PROP-6CB25C".to_string());
        assert!(receipt.quorum_status("DAO-PROP-6CB25C".to_string()).contains("\"quorum_met\":false"));

        env.set_caller(signer_b);
        receipt.approve_envelope("DAO-PROP-6CB25C".to_string());
        assert!(receipt.quorum_status("DAO-PROP-6CB25C".to_string()).contains("\"quorum_met\":true"));

        store_sample(&mut receipt, "DAO-PROP-6CB25C");
        assert!(receipt
            .get_receipt("DAO-PROP-6CB25C".to_string())
            .unwrap()
            .contains("\"approved_allocation_bps\":800"));
    }

    #[test]
    fn quorum_rejects_non_signers_and_duplicate_approvals() {
        let env = odra_test::env();
        let signer_a = env.get_account(0);
        let signer_b = env.get_account(1);
        let signer_c = env.get_account(2);
        let stranger = env.get_account(3);
        let mut receipt = GovernanceReceipt::deploy(&env, NoArgs);

        receipt.configure_quorum(signer_a, signer_b, signer_c, 2);
        receipt.propose_envelope("DAO-PROP-6CB25C".to_string(), h(9));
        receipt.approve_envelope("DAO-PROP-6CB25C".to_string());

        let duplicate = receipt.try_approve_envelope("DAO-PROP-6CB25C".to_string());
        assert_eq!(
            duplicate.unwrap_err(),
            GovernanceReceiptError::AlreadyApproved.into()
        );

        env.set_caller(stranger);
        let blocked = receipt.try_approve_envelope("DAO-PROP-6CB25C".to_string());
        assert_eq!(
            blocked.unwrap_err(),
            GovernanceReceiptError::UnauthorizedSigner.into()
        );
    }
}
