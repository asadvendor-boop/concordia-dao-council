// Testnet-profile suite: every fixture embeds the frozen `casper-test`
// identity, so this file only exists on the Testnet network profile.
#![cfg(network_profile_testnet)]

use concordia_odra_governance_receipt_v3::{
    derive_action_id, derive_deployment_domain, derive_envelope_hash, derive_transfer_id,
    CommonHeader, GovernanceReceiptV3, GovernanceReceiptV3Error, GovernanceReceiptV3InitArgs,
    NativeTransferV1, OfficialX402SettlementV1, V3Initialized,
};
use odra::{
    casper_types::{U256, U512},
    host::{Deployer, HostEnv},
    prelude::{Address, OdraResult},
};

fn b(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn h(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    out
}

fn raw(address: Address) -> [u8; 32] {
    address.as_account_hash().unwrap().value()
}

struct Roles {
    owner: Address,
    proposer: Address,
    finalizer: Address,
    signer_a: Address,
    signer_b: Address,
    signer_c: Address,
    stranger: Address,
}

fn roles(env: &HostEnv) -> Roles {
    Roles {
        owner: env.get_account(0),
        proposer: env.get_account(1),
        finalizer: env.get_account(2),
        signer_a: env.get_account(3),
        signer_b: env.get_account(4),
        signer_c: env.get_account(5),
        stranger: env.get_account(6),
    }
}

fn deploy(
    env: &HostEnv,
    roles: &Roles,
) -> concordia_odra_governance_receipt_v3::GovernanceReceiptV3HostRef {
    env.set_caller(roles.owner);
    GovernanceReceiptV3::deploy(env, init_args(roles))
}

fn init_args(roles: &Roles) -> GovernanceReceiptV3InitArgs {
    GovernanceReceiptV3InitArgs {
        proposer: raw(roles.proposer),
        finalizer: raw(roles.finalizer),
        signer_a: raw(roles.signer_a),
        signer_b: raw(roles.signer_b),
        signer_c: raw(roles.signer_c),
        threshold: 2,
        casper_chain_name: "casper-test".to_string(),
        installation_nonce: b(0xa5),
    }
}

#[derive(Clone)]
struct NativeCall {
    header: CommonHeader,
    body: NativeTransferV1,
}

impl NativeCall {
    fn new(proposal_id: &str, source: [u8; 32], recipient: [u8; 32]) -> Self {
        let proposal_nonce = if proposal_id.ends_with("002") {
            b(0x11)
        } else {
            b(0x10)
        };
        let action_nonce = b(0x44);
        let mut body = NativeTransferV1 {
            asset_kind: 0,
            source_account: source,
            recipient_account: recipient,
            amount_motes: U512::from(50_000_000_000u64),
            treasury_snapshot_balance_motes: U512::from(625_000_000_000u64),
            snapshot_block_hash: b(0x43),
            snapshot_block_height: 8_590_556,
            transfer_id: 0,
            action_nonce,
            execution_target: "native-transfer".to_string(),
            execution_version: 1,
        };
        let action_id = derive_action_id(1, action_nonce, &body.action_core_bytes().unwrap());
        body.transfer_id = derive_transfer_id(proposal_id, proposal_nonce, action_id).unwrap();
        let header = CommonHeader {
            schema_version: 3,
            deployment_domain: derive_deployment_domain("casper-test", b(0xa5)).unwrap(),
            casper_chain_name: "casper-test".to_string(),
            proposal_id: proposal_id.to_string(),
            proposal_nonce,
            decision_code: 2,
            requested_allocation_bps: 3000,
            approved_allocation_bps: 800,
            action_kind: 1,
            action_version: 1,
            action_id,
            proposal_hash: b(0x31),
            policy_hash: b(0x32),
            plan_hash: b(0x33),
            final_card_hash: b(0x34),
            dissent_hash: b(0x35),
            agent_action_hash: b(0x36),
            preauth_evidence_root: b(0x37),
            authorized_metadata_root: b(0x38),
        };
        Self { header, body }
    }

    fn envelope_hash(&self) -> [u8; 32] {
        derive_envelope_hash(&self.header, &self.body.canonical_bytes().unwrap()).unwrap()
    }

    fn finalize(
        &self,
        contract: &mut concordia_odra_governance_receipt_v3::GovernanceReceiptV3HostRef,
    ) -> [u8; 32] {
        let h = &self.header;
        let b = &self.body;
        contract.finalize_native_transfer(
            h.proposal_id.clone(),
            h.proposal_nonce,
            h.decision_code,
            h.requested_allocation_bps,
            h.approved_allocation_bps,
            h.action_kind,
            h.action_version,
            h.action_id,
            h.proposal_hash,
            h.policy_hash,
            h.plan_hash,
            h.final_card_hash,
            h.dissent_hash,
            h.agent_action_hash,
            h.preauth_evidence_root,
            h.authorized_metadata_root,
            b.asset_kind,
            b.source_account,
            b.recipient_account,
            b.amount_motes,
            b.treasury_snapshot_balance_motes,
            b.snapshot_block_hash,
            b.snapshot_block_height,
            b.transfer_id,
            b.action_nonce,
            b.execution_target.clone(),
            b.execution_version,
        )
    }

    fn try_finalize(
        &self,
        contract: &mut concordia_odra_governance_receipt_v3::GovernanceReceiptV3HostRef,
    ) -> OdraResult<[u8; 32]> {
        let h = &self.header;
        let b = &self.body;
        contract.try_finalize_native_transfer(
            h.proposal_id.clone(),
            h.proposal_nonce,
            h.decision_code,
            h.requested_allocation_bps,
            h.approved_allocation_bps,
            h.action_kind,
            h.action_version,
            h.action_id,
            h.proposal_hash,
            h.policy_hash,
            h.plan_hash,
            h.final_card_hash,
            h.dissent_hash,
            h.agent_action_hash,
            h.preauth_evidence_root,
            h.authorized_metadata_root,
            b.asset_kind,
            b.source_account,
            b.recipient_account,
            b.amount_motes,
            b.treasury_snapshot_balance_motes,
            b.snapshot_block_hash,
            b.snapshot_block_height,
            b.transfer_id,
            b.action_nonce,
            b.execution_target.clone(),
            b.execution_version,
        )
    }
}

#[derive(Clone)]
struct X402Call {
    header: CommonHeader,
    body: OfficialX402SettlementV1,
}

impl X402Call {
    fn new() -> Self {
        let action_nonce = b(0x57);
        let body = OfficialX402SettlementV1 {
            x402_version: 2,
            scheme: "exact".to_string(),
            caip2_network: "casper:casper-test".to_string(),
            wcspr_package: h("3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e"),
            wcspr_contract: h("032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a"),
            token_name: "Wrapped CSPR".to_string(),
            token_symbol: "WCSPR".to_string(),
            eip712_domain_version: "1".to_string(),
            token_decimals: 9,
            payer: h("5e4de9c4290a76042658e8e0d127d3e0d4ba7b99a11ad17da88d0bed2e15ec5c"),
            payee: b(0x52),
            value: U256::from(25_000_000_000u64),
            resource_url_hash: h(
                "20fc9888adc9639d9f0df5515e8f00cfc6692abec50dd1e7786602fbb8861798",
            ),
            report_hash: h("f9f447a0d14fe8494c1d2a2cc6bfa72c395e118b6f91728d0022f853a3492aa3"),
            payment_requirements_hash: h(
                "422f2b989183feec6407630c5296b36ed83c5d743b4d21d179dbc39495f5369c",
            ),
            signed_payment_payload_hash: h(
                "5e8d4237514cf04a2e2652822ef7d77d5841c658d2a271b4cdb581b4017480d8",
            ),
            eip712_auth_nonce: b(0x56),
            valid_after: 1_784_750_400,
            valid_before: 1_784_754_000,
            action_nonce,
            settlement_target: "cspr-cloud-facilitator".to_string(),
            settlement_version: 1,
        };
        let action_id = derive_action_id(2, action_nonce, &body.action_core_bytes().unwrap());
        Self {
            header: CommonHeader {
                schema_version: 3,
                deployment_domain: derive_deployment_domain("casper-test", b(0xa5)).unwrap(),
                casper_chain_name: "casper-test".to_string(),
                proposal_id: "DAO-PROP-V3-X402".to_string(),
                proposal_nonce: b(0x60),
                decision_code: 1,
                requested_allocation_bps: 0,
                approved_allocation_bps: 0,
                action_kind: 2,
                action_version: 1,
                action_id,
                proposal_hash: b(0x31),
                policy_hash: b(0x32),
                plan_hash: b(0x33),
                final_card_hash: b(0x34),
                dissent_hash: b(0x35),
                agent_action_hash: b(0x36),
                preauth_evidence_root: b(0x37),
                authorized_metadata_root: b(0x38),
            },
            body,
        }
    }

    fn refresh_action_id(&mut self) {
        self.header.action_id = derive_action_id(
            self.header.action_kind,
            self.body.action_nonce,
            &self.body.action_core_bytes().unwrap(),
        );
    }

    fn envelope_hash(&self) -> [u8; 32] {
        derive_envelope_hash(&self.header, &self.body.canonical_bytes().unwrap()).unwrap()
    }

    fn try_finalize(
        &self,
        contract: &mut concordia_odra_governance_receipt_v3::GovernanceReceiptV3HostRef,
    ) -> OdraResult<[u8; 32]> {
        let h = &self.header;
        let b = &self.body;
        contract.try_finalize_official_x402(
            h.proposal_id.clone(),
            h.proposal_nonce,
            h.decision_code,
            h.requested_allocation_bps,
            h.approved_allocation_bps,
            h.action_kind,
            h.action_version,
            h.action_id,
            h.proposal_hash,
            h.policy_hash,
            h.plan_hash,
            h.final_card_hash,
            h.dissent_hash,
            h.agent_action_hash,
            h.preauth_evidence_root,
            h.authorized_metadata_root,
            b.x402_version,
            b.scheme.clone(),
            b.caip2_network.clone(),
            b.wcspr_package,
            b.wcspr_contract,
            b.token_name.clone(),
            b.token_symbol.clone(),
            b.eip712_domain_version.clone(),
            b.token_decimals,
            b.payer,
            b.payee,
            b.value,
            b.resource_url_hash,
            b.report_hash,
            b.payment_requirements_hash,
            b.signed_payment_payload_hash,
            b.eip712_auth_nonce,
            b.valid_after,
            b.valid_before,
            b.action_nonce,
            b.settlement_target.clone(),
            b.settlement_version,
        )
    }
}

fn propose_and_approve(
    env: &HostEnv,
    roles: &Roles,
    contract: &mut concordia_odra_governance_receipt_v3::GovernanceReceiptV3HostRef,
    call: &NativeCall,
) {
    let envelope_hash = call.envelope_hash();
    env.set_caller(roles.proposer);
    contract.propose_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.signer_a);
    contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.signer_b);
    contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
}

#[test]
fn constructor_injects_domain_and_freezes_distinct_roles() {
    let env = odra_test::env();
    let roles = roles(&env);
    let contract = deploy(&env, &roles);
    assert_eq!(contract.schema_version(), 3);
    assert_eq!(contract.casper_chain_name(), "casper-test");
    assert_eq!(
        contract.deployment_domain(),
        derive_deployment_domain("casper-test", b(0xa5)).unwrap()
    );
    assert_eq!(contract.proposer(), raw(roles.proposer));
    assert_eq!(contract.finalizer(), raw(roles.finalizer));
    assert_eq!(contract.signer_a(), raw(roles.signer_a));
    assert_eq!(contract.signer_b(), raw(roles.signer_b));
    assert_eq!(contract.signer_c(), raw(roles.signer_c));
    assert_eq!(contract.threshold(), 2);
    assert_eq!(env.events_count(&contract), 1);
    let initialized: V3Initialized = env.get_event(&contract, 0).unwrap();
    assert_eq!(initialized.schema_version, 3);
    assert_eq!(initialized.proposer, raw(roles.proposer));
    assert_eq!(initialized.finalizer, raw(roles.finalizer));
    assert_eq!(initialized.signer_a, raw(roles.signer_a));
    assert_eq!(initialized.signer_b, raw(roles.signer_b));
    assert_eq!(initialized.signer_c, raw(roles.signer_c));
    assert_eq!(initialized.threshold, 2);
}

#[test]
fn constructor_rejects_zero_duplicate_roles_and_invalid_threshold() {
    let env = odra_test::env();
    let roles = roles(&env);
    env.set_caller(roles.owner);
    for role_index in 0..5 {
        let mut zero = init_args(&roles);
        match role_index {
            0 => zero.proposer = [0u8; 32],
            1 => zero.finalizer = [0u8; 32],
            2 => zero.signer_a = [0u8; 32],
            3 => zero.signer_b = [0u8; 32],
            4 => zero.signer_c = [0u8; 32],
            _ => unreachable!(),
        }
        assert_eq!(
            GovernanceReceiptV3::try_deploy(&env, zero).err().unwrap(),
            GovernanceReceiptV3Error::InvalidRoleAddress.into()
        );
    }

    for pair in [(0, 1), (0, 2), (1, 2)] {
        let mut duplicate = init_args(&roles);
        let signers = [duplicate.signer_a, duplicate.signer_b, duplicate.signer_c];
        match pair.1 {
            1 => duplicate.signer_b = signers[pair.0],
            2 => duplicate.signer_c = signers[pair.0],
            _ => unreachable!(),
        }
        assert_eq!(
            GovernanceReceiptV3::try_deploy(&env, duplicate)
                .err()
                .unwrap(),
            GovernanceReceiptV3Error::InvalidSignerSet.into()
        );
    }

    for invalid_threshold in [0, 1, 4, u8::MAX] {
        let mut threshold = init_args(&roles);
        threshold.threshold = invalid_threshold;
        assert_eq!(
            GovernanceReceiptV3::try_deploy(&env, threshold)
                .err()
                .unwrap(),
            GovernanceReceiptV3Error::InvalidThreshold.into()
        );
    }

    for invalid_domain_input in 0..2 {
        let mut args = init_args(&roles);
        if invalid_domain_input == 0 {
            args.casper_chain_name = "casper".to_string();
        } else {
            args.installation_nonce = [0u8; 32];
        }
        assert_eq!(
            GovernanceReceiptV3::try_deploy(&env, args).err().unwrap(),
            GovernanceReceiptV3Error::InvalidEnvelopeField.into()
        );
    }
}

#[test]
fn constructor_rejects_every_cross_role_collision_as_invalid_role_address() {
    let env = odra_test::env();
    let roles = roles(&env);
    env.set_caller(roles.owner);

    for collision in 0..7 {
        let mut args = init_args(&roles);
        match collision {
            0 => args.finalizer = args.proposer,
            1 => args.signer_a = args.proposer,
            2 => args.signer_b = args.proposer,
            3 => args.signer_c = args.proposer,
            4 => args.signer_a = args.finalizer,
            5 => args.signer_b = args.finalizer,
            6 => args.signer_c = args.finalizer,
            _ => unreachable!(),
        }
        assert_eq!(
            GovernanceReceiptV3::try_deploy(&env, args).err().unwrap(),
            GovernanceReceiptV3Error::InvalidRoleAddress.into()
        );
    }
}

#[test]
fn both_frozen_thresholds_require_the_exact_configured_quorum() {
    for threshold in [2, 3] {
        let env = odra_test::env();
        let roles = roles(&env);
        env.set_caller(roles.owner);
        let mut args = init_args(&roles);
        args.threshold = threshold;
        let mut contract = GovernanceReceiptV3::deploy(&env, args);
        let call = NativeCall::new(
            &format!("DAO-PROP-V3-THRESHOLD-{threshold}"),
            raw(roles.proposer),
            raw(roles.stranger),
        );
        let envelope_hash = call.envelope_hash();
        env.set_caller(roles.proposer);
        contract.propose_envelope(call.header.proposal_id.clone(), envelope_hash);
        env.set_caller(roles.signer_a);
        contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
        assert_eq!(
            contract.quorum_met(call.header.proposal_id.clone()),
            threshold == 1
        );
        env.set_caller(roles.signer_b);
        contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
        assert_eq!(
            contract.quorum_met(call.header.proposal_id.clone()),
            threshold == 2
        );
        if threshold == 3 {
            env.set_caller(roles.signer_c);
            contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
            assert!(contract.quorum_met(call.header.proposal_id.clone()));
            assert_eq!(contract.approval_count(call.header.proposal_id), 3);
        }
    }
}

#[test]
fn constructor_rejects_owner_collision_with_every_governance_role() {
    let env = odra_test::env();
    let roles = roles(&env);
    env.set_caller(roles.owner);
    let owner = raw(roles.owner);

    for role_index in 0..5 {
        let mut args = init_args(&roles);
        match role_index {
            0 => args.proposer = owner,
            1 => args.finalizer = owner,
            2 => args.signer_a = owner,
            3 => args.signer_b = owner,
            4 => args.signer_c = owner,
            _ => unreachable!(),
        }
        assert_eq!(
            GovernanceReceiptV3::try_deploy(&env, args).err().unwrap(),
            GovernanceReceiptV3Error::InvalidRoleAddress.into()
        );
    }
}

#[test]
fn installer_owner_has_no_callable_governance_power() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);
    let call = NativeCall::new(
        "DAO-PROP-V3-OWNER",
        raw(roles.proposer),
        raw(roles.stranger),
    );
    let envelope_hash = call.envelope_hash();

    env.set_caller(roles.owner);
    assert_eq!(
        contract
            .try_propose_envelope(call.header.proposal_id.clone(), envelope_hash)
            .unwrap_err(),
        GovernanceReceiptV3Error::UnauthorizedProposer.into()
    );
    assert_eq!(
        contract.proposed_envelope(call.header.proposal_id.clone()),
        None
    );

    env.set_caller(roles.proposer);
    contract.propose_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.owner);
    assert_eq!(
        contract
            .try_approve_envelope(call.header.proposal_id.clone(), envelope_hash)
            .unwrap_err(),
        GovernanceReceiptV3Error::UnauthorizedSigner.into()
    );
    assert_eq!(contract.approval_count(call.header.proposal_id.clone()), 0);
    assert_eq!(
        call.try_finalize(&mut contract).unwrap_err(),
        GovernanceReceiptV3Error::UnauthorizedFinalizer.into()
    );
    assert!(!contract.finalized(call.header.proposal_id));
}

#[test]
fn proposer_and_approval_paths_fail_closed_without_mutation() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);
    let call = NativeCall::new("DAO-PROP-V3-001", raw(roles.proposer), raw(roles.stranger));
    let envelope_hash = call.envelope_hash();

    env.set_caller(roles.stranger);
    assert_eq!(
        contract
            .try_propose_envelope(call.header.proposal_id.clone(), envelope_hash)
            .unwrap_err(),
        GovernanceReceiptV3Error::UnauthorizedProposer.into()
    );
    assert_eq!(
        contract.proposed_envelope(call.header.proposal_id.clone()),
        None
    );

    env.set_caller(roles.proposer);
    contract.propose_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.signer_a);
    let events_before_wrong_hash = env.events_count(&contract);
    assert_eq!(
        contract
            .try_approve_envelope(call.header.proposal_id.clone(), b(0xee))
            .unwrap_err(),
        GovernanceReceiptV3Error::EnvelopeHashMismatch.into()
    );
    assert_eq!(contract.approval_count(call.header.proposal_id.clone()), 0);
    assert!(!contract.has_approved(call.header.proposal_id.clone(), raw(roles.signer_a)));
    assert_eq!(env.events_count(&contract), events_before_wrong_hash);

    contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
    assert_eq!(
        contract
            .try_approve_envelope(call.header.proposal_id.clone(), envelope_hash)
            .unwrap_err(),
        GovernanceReceiptV3Error::AlreadyApproved.into()
    );
    assert_eq!(contract.approval_count(call.header.proposal_id.clone()), 1);
}

#[test]
fn lifecycle_errors_and_third_signer_preserve_exact_state_and_events() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);
    let call = NativeCall::new(
        "DAO-PROP-V3-LIFECYCLE",
        raw(roles.proposer),
        raw(roles.stranger),
    );
    let envelope_hash = call.envelope_hash();

    env.set_caller(roles.signer_a);
    let initial_events = env.events_count(&contract);
    assert_eq!(
        contract
            .try_approve_envelope(call.header.proposal_id.clone(), envelope_hash)
            .unwrap_err(),
        GovernanceReceiptV3Error::ProposalMissing.into()
    );
    assert_eq!(env.events_count(&contract), initial_events);

    env.set_caller(roles.proposer);
    contract.propose_envelope(call.header.proposal_id.clone(), envelope_hash);
    let proposed_events = env.events_count(&contract);
    assert_eq!(
        contract
            .try_propose_envelope(call.header.proposal_id.clone(), envelope_hash)
            .unwrap_err(),
        GovernanceReceiptV3Error::ProposalAlreadyExists.into()
    );
    assert_eq!(env.events_count(&contract), proposed_events);

    for signer in [roles.signer_a, roles.signer_b, roles.signer_c] {
        env.set_caller(signer);
        contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
    }
    assert_eq!(contract.approval_count(call.header.proposal_id.clone()), 3);
    assert!(contract.quorum_met(call.header.proposal_id.clone()));
    assert!(!contract.finalized(call.header.proposal_id));
}

#[test]
fn injected_immutable_mutations_cannot_be_supplied_by_the_finalizer() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);

    for case in 0..3 {
        let mut call = NativeCall::new(
            &format!("DAO-PROP-V3-IMM-{case}"),
            raw(roles.proposer),
            raw(roles.stranger),
        );
        match case {
            0 => call.header.schema_version = 4,
            1 => call.header.deployment_domain = b(0xdd),
            2 => call.header.casper_chain_name = "casper".to_string(),
            _ => unreachable!(),
        }
        let alternate_commitment = if case == 1 {
            derive_envelope_hash(&call.header, &call.body.canonical_bytes().unwrap()).unwrap()
        } else {
            // schema_version and casper_chain_name are absent from the finalizer ABI.
            // Their alternative-domain commitments are represented as opaque proposal
            // commitments because the v3 encoder correctly refuses to encode them.
            b(0xc0 + case as u8)
        };
        env.set_caller(roles.proposer);
        contract.propose_envelope(call.header.proposal_id.clone(), alternate_commitment);
        env.set_caller(roles.signer_a);
        contract.approve_envelope(call.header.proposal_id.clone(), alternate_commitment);
        env.set_caller(roles.signer_b);
        contract.approve_envelope(call.header.proposal_id.clone(), alternate_commitment);
        env.set_caller(roles.finalizer);
        let events_before = env.events_count(&contract);
        assert_eq!(
            call.try_finalize(&mut contract).unwrap_err(),
            GovernanceReceiptV3Error::EnvelopeHashMismatch.into(),
            "IMM case {case}"
        );
        assert!(!contract.finalized(call.header.proposal_id.clone()));
        assert!(!contract.action_authorized(call.header.action_id));
        assert_eq!(env.events_count(&contract), events_before);
    }
}

#[test]
fn every_mutable_header_field_obeys_frozen_error_precedence_without_mutation() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);
    let call = NativeCall::new(
        "DAO-PROP-V3-MUT-H",
        raw(roles.proposer),
        raw(roles.stranger),
    );
    let envelope_hash = call.envelope_hash();
    propose_and_approve(&env, &roles, &mut contract, &call);

    let case_ids = [
        "MUT-H04", "MUT-H05", "MUT-H06", "MUT-H07", "MUT-H08", "MUT-H09", "MUT-H10", "MUT-H11",
        "MUT-H12", "MUT-H13", "MUT-H14", "MUT-H15", "MUT-H16", "MUT-H17", "MUT-H18", "MUT-H19",
    ];
    for (case, case_id) in case_ids.iter().enumerate() {
        let mut mutation = call.clone();
        match case {
            0 => mutation.header.proposal_id = "DAO-PROP-V3-MUT-H-MISSING".to_string(),
            1 => mutation.header.proposal_nonce = b(0x91),
            2 => mutation.header.decision_code = 1,
            3 => mutation.header.requested_allocation_bps = 2999,
            4 => mutation.header.approved_allocation_bps = 3000,
            5 => mutation.header.action_kind = 2,
            6 => mutation.header.action_version = 2,
            7 => mutation.header.action_id = b(0x92),
            8 => mutation.header.proposal_hash = b(0x93),
            9 => mutation.header.policy_hash = b(0x94),
            10 => mutation.header.plan_hash = b(0x95),
            11 => mutation.header.final_card_hash = b(0x96),
            12 => mutation.header.dissent_hash = b(0x97),
            13 => mutation.header.agent_action_hash = b(0x98),
            14 => mutation.header.preauth_evidence_root = b(0x99),
            15 => mutation.header.authorized_metadata_root = b(0x9a),
            _ => unreachable!(),
        }
        env.set_caller(roles.finalizer);
        let events_before = env.events_count(&contract);
        let error = mutation.try_finalize(&mut contract).unwrap_err();
        if case == 0 {
            assert_eq!(
                error,
                GovernanceReceiptV3Error::ProposalMissing.into(),
                "{case_id}"
            );
        } else if case == 1 || matches!(case, 5..=7) {
            assert_eq!(
                error,
                GovernanceReceiptV3Error::InvalidActionField.into(),
                "{case_id}"
            );
        } else {
            assert_eq!(
                error,
                GovernanceReceiptV3Error::EnvelopeHashMismatch.into(),
                "{case_id}"
            );
        }
        assert_eq!(
            contract.proposed_envelope(call.header.proposal_id.clone()),
            Some(envelope_hash),
            "{case_id}"
        );
        assert_eq!(
            contract.approval_count(call.header.proposal_id.clone()),
            2,
            "{case_id}"
        );
        assert!(
            !contract.finalized(call.header.proposal_id.clone()),
            "{case_id}"
        );
        assert!(
            !contract.action_authorized(call.header.action_id),
            "{case_id}"
        );
        assert_eq!(env.events_count(&contract), events_before, "{case_id}");
    }
    env.set_caller(roles.finalizer);
    assert_eq!(call.try_finalize(&mut contract).unwrap(), envelope_hash);
}

#[test]
fn every_native_action_field_mutation_is_rejected_before_state_or_event_mutation() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);
    let call = NativeCall::new(
        "DAO-PROP-V3-MUT-N",
        raw(roles.proposer),
        raw(roles.stranger),
    );
    let envelope_hash = call.envelope_hash();
    propose_and_approve(&env, &roles, &mut contract, &call);

    let case_ids = [
        "MUT-N01", "MUT-N02", "MUT-N03", "MUT-N04", "MUT-N05", "MUT-N06", "MUT-N07", "MUT-N08",
        "MUT-N09", "MUT-N10", "MUT-N11",
    ];
    for (case, case_id) in case_ids.iter().enumerate() {
        let mut mutation = call.clone();
        match case {
            0 => mutation.body.asset_kind = 1,
            1 => mutation.body.source_account = b(0x71),
            2 => mutation.body.recipient_account = b(0x72),
            3 => mutation.body.amount_motes += U512::from(1u8),
            4 => mutation.body.treasury_snapshot_balance_motes += U512::from(1u8),
            5 => mutation.body.snapshot_block_hash = b(0x73),
            6 => mutation.body.snapshot_block_height += 1,
            7 => mutation.body.transfer_id += 1,
            8 => mutation.body.action_nonce = b(0x74),
            9 => mutation.body.execution_target = "native-transfer-v2".to_string(),
            10 => mutation.body.execution_version = 2,
            _ => unreachable!(),
        }
        env.set_caller(roles.finalizer);
        let events_before = env.events_count(&contract);
        assert_eq!(
            mutation.try_finalize(&mut contract).unwrap_err(),
            GovernanceReceiptV3Error::InvalidActionField.into(),
            "{case_id}"
        );
        assert_eq!(
            contract.approval_count(call.header.proposal_id.clone()),
            2,
            "{case_id}"
        );
        assert!(
            !contract.finalized(call.header.proposal_id.clone()),
            "{case_id}"
        );
        assert!(
            !contract.action_authorized(call.header.action_id),
            "{case_id}"
        );
        assert_eq!(env.events_count(&contract), events_before, "{case_id}");
    }
    env.set_caller(roles.finalizer);
    assert_eq!(call.try_finalize(&mut contract).unwrap(), envelope_hash);
}

#[test]
fn every_x402_action_field_mutation_is_rejected_before_state_or_event_mutation() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);
    let call = X402Call::new();
    let envelope_hash = call.envelope_hash();
    env.set_caller(roles.proposer);
    contract.propose_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.signer_a);
    contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.signer_b);
    contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);

    let case_ids = [
        "MUT-X01", "MUT-X02", "MUT-X03", "MUT-X04", "MUT-X05", "MUT-X06", "MUT-X07", "MUT-X08",
        "MUT-X09", "MUT-X10", "MUT-X11", "MUT-X12", "MUT-X13", "MUT-X14", "MUT-X15", "MUT-X16",
        "MUT-X17", "MUT-X18", "MUT-X19", "MUT-X20", "MUT-X21", "MUT-X22",
    ];
    for (case, case_id) in case_ids.iter().enumerate() {
        let mut mutation = call.clone();
        match case {
            0 => mutation.body.x402_version = 3,
            1 => mutation.body.scheme = "deferred".to_string(),
            2 => mutation.body.caip2_network = "casper:other".to_string(),
            3 => mutation.body.wcspr_package = b(0x81),
            4 => mutation.body.wcspr_contract = b(0x82),
            5 => mutation.body.token_name = "Wrapped Casper".to_string(),
            6 => mutation.body.token_symbol = "wCSPR".to_string(),
            7 => mutation.body.eip712_domain_version = "2".to_string(),
            8 => mutation.body.token_decimals = 18,
            9 => mutation.body.payer = b(0x83),
            10 => mutation.body.payee = b(0x84),
            11 => mutation.body.value += U256::from(1u8),
            12 => mutation.body.resource_url_hash = b(0x85),
            13 => mutation.body.report_hash = b(0x86),
            14 => mutation.body.payment_requirements_hash = b(0x87),
            15 => mutation.body.signed_payment_payload_hash = b(0x88),
            16 => mutation.body.eip712_auth_nonce = b(0x89),
            17 => mutation.body.valid_after += 1,
            18 => mutation.body.valid_before += 1,
            19 => mutation.body.action_nonce = b(0x8a),
            20 => mutation.body.settlement_target = "other-facilitator".to_string(),
            21 => mutation.body.settlement_version = 2,
            _ => unreachable!(),
        }
        env.set_caller(roles.finalizer);
        let events_before = env.events_count(&contract);
        assert_eq!(
            mutation.try_finalize(&mut contract).unwrap_err(),
            GovernanceReceiptV3Error::InvalidActionField.into(),
            "{case_id}"
        );
        assert_eq!(
            contract.approval_count(call.header.proposal_id.clone()),
            2,
            "{case_id}"
        );
        assert!(
            !contract.finalized(call.header.proposal_id.clone()),
            "{case_id}"
        );
        assert!(
            !contract.action_authorized(call.header.action_id),
            "{case_id}"
        );
        assert_eq!(env.events_count(&contract), events_before, "{case_id}");
    }
    env.set_caller(roles.finalizer);
    assert_eq!(call.try_finalize(&mut contract).unwrap(), envelope_hash);
}

#[test]
fn semantic_financial_account_endpoints_reject_zero_after_exact_hash_match() {
    for case in 0..4 {
        let env = odra_test::env();
        let roles = roles(&env);
        let mut contract = deploy(&env, &roles);
        if case < 2 {
            let proposal_id = format!("DAO-PROP-V3-ZERO-N-{case}");
            let mut call = NativeCall::new(&proposal_id, raw(roles.proposer), raw(roles.stranger));
            if case == 0 {
                call.body.source_account = [0u8; 32];
            } else {
                call.body.recipient_account = [0u8; 32];
            }
            call.header.action_id = derive_action_id(
                call.header.action_kind,
                call.body.action_nonce,
                &call.body.action_core_bytes().unwrap(),
            );
            call.body.transfer_id = derive_transfer_id(
                &call.header.proposal_id,
                call.header.proposal_nonce,
                call.header.action_id,
            )
            .unwrap();
            propose_and_approve(&env, &roles, &mut contract, &call);
            env.set_caller(roles.finalizer);
            assert_eq!(
                call.try_finalize(&mut contract).unwrap_err(),
                GovernanceReceiptV3Error::InvalidActionField.into()
            );
            assert!(!contract.finalized(proposal_id));
        } else {
            let mut call = X402Call::new();
            call.header.proposal_id = format!("DAO-PROP-V3-ZERO-X-{case}");
            if case == 2 {
                call.body.payer = [0u8; 32];
            } else {
                call.body.payee = [0u8; 32];
            }
            call.refresh_action_id();
            let envelope_hash = call.envelope_hash();
            env.set_caller(roles.proposer);
            contract.propose_envelope(call.header.proposal_id.clone(), envelope_hash);
            env.set_caller(roles.signer_a);
            contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
            env.set_caller(roles.signer_b);
            contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
            env.set_caller(roles.finalizer);
            assert_eq!(
                call.try_finalize(&mut contract).unwrap_err(),
                GovernanceReceiptV3Error::InvalidActionField.into()
            );
            assert!(!contract.finalized(call.header.proposal_id));
        }
    }
}

#[test]
fn finalizer_authentication_and_lookup_precede_all_envelope_validation() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);
    let mut call = NativeCall::new("DAO-PROP-V3-001", raw(roles.proposer), raw(roles.stranger));
    call.header.action_kind = 0;
    env.set_caller(roles.stranger);
    assert_eq!(
        call.try_finalize(&mut contract).unwrap_err(),
        GovernanceReceiptV3Error::UnauthorizedFinalizer.into()
    );

    env.set_caller(roles.finalizer);
    assert_eq!(
        call.try_finalize(&mut contract).unwrap_err(),
        GovernanceReceiptV3Error::ProposalMissing.into()
    );
}

#[test]
fn quorum_wrong_envelope_correct_envelope_and_repeat_have_stable_errors() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);
    let call = NativeCall::new("DAO-PROP-V3-001", raw(roles.proposer), raw(roles.stranger));
    let envelope_hash = call.envelope_hash();
    env.set_caller(roles.proposer);
    contract.propose_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.finalizer);
    assert_eq!(
        call.try_finalize(&mut contract).unwrap_err(),
        GovernanceReceiptV3Error::QuorumNotMet.into()
    );

    env.set_caller(roles.signer_a);
    contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.signer_b);
    contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);

    let mut mutation = call.clone();
    mutation.header.approved_allocation_bps = 3000;
    env.set_caller(roles.finalizer);
    assert_eq!(
        mutation.try_finalize(&mut contract).unwrap_err(),
        GovernanceReceiptV3Error::EnvelopeHashMismatch.into()
    );
    assert!(!contract.finalized(call.header.proposal_id.clone()));

    assert_eq!(call.finalize(&mut contract), envelope_hash);
    assert!(contract.finalized(call.header.proposal_id.clone()));
    assert!(contract.action_authorized(call.header.action_id));
    assert_eq!(
        contract.finalized_envelope(call.header.proposal_id.clone()),
        Some(envelope_hash)
    );
    assert_eq!(
        call.try_finalize(&mut contract).unwrap_err(),
        GovernanceReceiptV3Error::AlreadyFinalized.into()
    );
}

#[test]
fn action_cannot_be_authorized_again_under_another_proposal() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);
    let first = NativeCall::new("DAO-PROP-V3-001", raw(roles.proposer), raw(roles.stranger));
    let second = NativeCall::new("DAO-PROP-V3-002", raw(roles.proposer), raw(roles.stranger));
    assert_eq!(first.header.action_id, second.header.action_id);

    propose_and_approve(&env, &roles, &mut contract, &first);
    env.set_caller(roles.finalizer);
    first.finalize(&mut contract);
    propose_and_approve(&env, &roles, &mut contract, &second);
    env.set_caller(roles.finalizer);
    assert_eq!(
        second.try_finalize(&mut contract).unwrap_err(),
        GovernanceReceiptV3Error::ActionAlreadyAuthorized.into()
    );
    assert!(!contract.finalized(second.header.proposal_id.clone()));
}

#[test]
fn official_x402_finalization_recomputes_ids_hash_and_policy_before_mutation() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);
    let call = X402Call::new();
    let envelope_hash = call.envelope_hash();
    assert_eq!(
        envelope_hash,
        h("3902fc5ae46d5f337b18ad4e7acfa7c05b6b8c0b52d3a3c72aaf5d5286ae450d")
    );

    env.set_caller(roles.proposer);
    contract.propose_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.signer_a);
    contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.signer_b);
    contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);

    let mut stale_id_mutation = call.clone();
    stale_id_mutation.body.payee = b(0x53);
    env.set_caller(roles.finalizer);
    assert_eq!(
        stale_id_mutation.try_finalize(&mut contract).unwrap_err(),
        GovernanceReceiptV3Error::InvalidActionField.into()
    );
    assert!(!contract.finalized(call.header.proposal_id.clone()));

    assert_eq!(call.try_finalize(&mut contract).unwrap(), envelope_hash);
    assert!(contract.finalized(call.header.proposal_id.clone()));
    assert!(contract.action_authorized(call.header.action_id));
}

#[test]
fn self_consistent_but_policy_invalid_x402_envelope_is_rejected_after_hash_match() {
    let env = odra_test::env();
    let roles = roles(&env);
    let mut contract = deploy(&env, &roles);
    let mut call = X402Call::new();
    call.header.proposal_id = "DAO-PROP-V3-X402-BAD".to_string();
    call.body.valid_before = call.body.valid_after;
    call.refresh_action_id();
    let envelope_hash = call.envelope_hash();

    env.set_caller(roles.proposer);
    contract.propose_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.signer_a);
    contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.signer_b);
    contract.approve_envelope(call.header.proposal_id.clone(), envelope_hash);
    env.set_caller(roles.finalizer);
    assert_eq!(
        call.try_finalize(&mut contract).unwrap_err(),
        GovernanceReceiptV3Error::InvalidActionField.into()
    );
    assert!(!contract.finalized(call.header.proposal_id));
    assert!(!contract.action_authorized(call.header.action_id));
}
