// Network-profile acceptance suite. One section per compile-time profile;
// the golden deployment-domain hex literals below are cross-pinned with the
// Python mirror (tests/mainnet_canary/test_mc_encoding_crosscheck.py), so
// both languages must derive the exact same bytes or their suite fails.

use concordia_odra_governance_receipt_v3::{CAIP2_NETWORK, CASPER_CHAIN_NAME, OFFICIAL_X402_SUPPORTED};

// blake2b-256(DOMAIN_SEPARATOR || len32("casper-test") || len32(package) || 0xa5*32)
const TESTNET_DOMAIN_GOLDEN: &str =
    "40804e79504df011ccbe7326898a9d7e489e01b445f483a199467584ddfb5726";
// blake2b-256("CONCORDIA_DOMAIN_V3_MAINNET\0" || len32("casper") || len32(package) || 0xa5*32)
const MAINNET_DOMAIN_GOLDEN: &str =
    "738f08998497f41853bacfa94833f5b301cbe3f3530e70f663f147255b27fcfd";

fn b(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn hex32(value: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in value {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(network_profile_testnet)]
mod testnet_profile {
    use super::*;
    use concordia_odra_governance_receipt_v3::{derive_deployment_domain, ValidationError};

    #[test]
    fn profile_pins_frozen_testnet_identity() {
        assert_eq!(CASPER_CHAIN_NAME, "casper-test");
        assert_eq!(CAIP2_NETWORK, "casper:casper-test");
        assert!(OFFICIAL_X402_SUPPORTED);
    }

    #[test]
    fn testnet_domain_separator_is_byte_frozen() {
        // Historical Testnet deployments derived exactly this domain; any
        // separator drift would break every committed golden vector.
        let domain = derive_deployment_domain("casper-test", b(0xa5)).unwrap();
        assert_eq!(hex32(domain), TESTNET_DOMAIN_GOLDEN);
    }

    #[test]
    fn testnet_build_rejects_mainnet_chain_identity() {
        assert_eq!(
            derive_deployment_domain("casper", b(0xa5)).unwrap_err(),
            ValidationError::InvalidEnvelopeField
        );
    }
}

#[cfg(network_profile_mainnet_native)]
mod mainnet_native_profile {
    use super::*;
    use concordia_odra_governance_receipt_v3::{
        derive_action_id, derive_deployment_domain, derive_envelope_hash, derive_transfer_id,
        CommonHeader, GovernanceReceiptV3, GovernanceReceiptV3Error, GovernanceReceiptV3InitArgs,
        NativeTransferV1, OfficialX402SettlementV1, ValidationError,
    };
    use odra::{
        casper_types::{U256, U512},
        host::{Deployer, HostEnv},
        prelude::Address,
    };

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
    }

    fn roles(env: &HostEnv) -> Roles {
        Roles {
            owner: env.get_account(0),
            proposer: env.get_account(1),
            finalizer: env.get_account(2),
            signer_a: env.get_account(3),
            signer_b: env.get_account(4),
            signer_c: env.get_account(5),
        }
    }

    fn init_args(roles: &Roles) -> GovernanceReceiptV3InitArgs {
        GovernanceReceiptV3InitArgs {
            proposer: raw(roles.proposer),
            finalizer: raw(roles.finalizer),
            signer_a: raw(roles.signer_a),
            signer_b: raw(roles.signer_b),
            signer_c: raw(roles.signer_c),
            threshold: 2,
            casper_chain_name: "casper".to_string(),
            installation_nonce: b(0xa5),
        }
    }

    fn deploy(
        env: &HostEnv,
        roles: &Roles,
    ) -> concordia_odra_governance_receipt_v3::GovernanceReceiptV3HostRef {
        env.set_caller(roles.owner);
        GovernanceReceiptV3::deploy(env, init_args(roles))
    }

    fn native_call(source: [u8; 32], recipient: [u8; 32]) -> (CommonHeader, NativeTransferV1) {
        let proposal_id = "DAO-MAINNET-CANARY-001";
        let proposal_nonce = b(0x10);
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
            deployment_domain: derive_deployment_domain("casper", b(0xa5)).unwrap(),
            casper_chain_name: "casper".to_string(),
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
        (header, body)
    }

    fn finalize_native(
        contract: &mut concordia_odra_governance_receipt_v3::GovernanceReceiptV3HostRef,
        header: &CommonHeader,
        body: &NativeTransferV1,
    ) -> odra::prelude::OdraResult<[u8; 32]> {
        contract.try_finalize_native_transfer(
            header.proposal_id.clone(),
            header.proposal_nonce,
            header.decision_code,
            header.requested_allocation_bps,
            header.approved_allocation_bps,
            header.action_kind,
            header.action_version,
            header.action_id,
            header.proposal_hash,
            header.policy_hash,
            header.plan_hash,
            header.final_card_hash,
            header.dissent_hash,
            header.agent_action_hash,
            header.preauth_evidence_root,
            header.authorized_metadata_root,
            body.asset_kind,
            body.source_account,
            body.recipient_account,
            body.amount_motes,
            body.treasury_snapshot_balance_motes,
            body.snapshot_block_hash,
            body.snapshot_block_height,
            body.transfer_id,
            body.action_nonce,
            body.execution_target.clone(),
            body.execution_version,
        )
    }

    #[test]
    fn profile_pins_truthful_mainnet_identity() {
        assert_eq!(CASPER_CHAIN_NAME, "casper");
        assert_eq!(CAIP2_NETWORK, "casper:casper");
        assert!(!OFFICIAL_X402_SUPPORTED);
    }

    #[test]
    fn mainnet_domain_separator_is_pinned_and_disjoint_from_testnet() {
        let domain = derive_deployment_domain("casper", b(0xa5)).unwrap();
        assert_eq!(hex32(domain), MAINNET_DOMAIN_GOLDEN);
        // Disjoint separator: even an identical nonce can never reproduce a
        // Testnet deployment domain on this build.
        assert_ne!(hex32(domain), TESTNET_DOMAIN_GOLDEN);
    }

    #[test]
    fn mainnet_build_rejects_casper_test_identity_everywhere() {
        // Derivation refuses the Testnet chain string outright…
        assert_eq!(
            derive_deployment_domain("casper-test", b(0xa5)).unwrap_err(),
            ValidationError::InvalidEnvelopeField
        );
        // …and so does the constructor: installing this artifact by lying
        // with `casper-test` (or any other string) is impossible.
        let env = odra_test::env();
        let accounts = roles(&env);
        env.set_caller(accounts.owner);
        for wrong_chain in ["casper-test", "casper-net-1", "", "CASPER"] {
            let mut args = init_args(&accounts);
            args.casper_chain_name = wrong_chain.to_string();
            assert_eq!(
                GovernanceReceiptV3::try_deploy(&env, args).err().unwrap(),
                GovernanceReceiptV3Error::InvalidEnvelopeField.into(),
                "chain {wrong_chain:?} must be rejected"
            );
        }
    }

    #[test]
    fn mainnet_deploy_accepts_truthful_chain_and_enforces_quorum_flow() {
        let env = odra_test::env();
        let accounts = roles(&env);
        let mut contract = deploy(&env, &accounts);
        assert_eq!(contract.casper_chain_name(), "casper");
        assert_eq!(
            hex32(contract.deployment_domain()),
            MAINNET_DOMAIN_GOLDEN
        );

        let (header, body) = native_call(raw(accounts.owner), raw(accounts.signer_c));
        let envelope_hash =
            derive_envelope_hash(&header, &body.canonical_bytes().unwrap()).unwrap();

        env.set_caller(accounts.proposer);
        contract.propose_envelope(header.proposal_id.clone(), envelope_hash);

        // Pre-quorum finalization must refuse with exactly QuorumNotMet (8).
        env.set_caller(accounts.finalizer);
        assert_eq!(
            finalize_native(&mut contract, &header, &body).err().unwrap(),
            GovernanceReceiptV3Error::QuorumNotMet.into()
        );

        env.set_caller(accounts.signer_a);
        contract.approve_envelope(header.proposal_id.clone(), envelope_hash);
        env.set_caller(accounts.signer_b);
        contract.approve_envelope(header.proposal_id.clone(), envelope_hash);

        // Wrong-envelope mutation after quorum must refuse before any state
        // change (recipient swapped => recomputed hash mismatches commitment).
        let (mut wrong_header, mut wrong_body) =
            native_call(raw(accounts.owner), raw(accounts.signer_c));
        wrong_body.recipient_account = raw(accounts.signer_b);
        let wrong_action_id = derive_action_id(
            1,
            wrong_body.action_nonce,
            &wrong_body.action_core_bytes().unwrap(),
        );
        wrong_header.action_id = wrong_action_id;
        wrong_body.transfer_id =
            derive_transfer_id(&wrong_header.proposal_id, wrong_header.proposal_nonce, wrong_action_id)
                .unwrap();
        env.set_caller(accounts.finalizer);
        assert_eq!(
            finalize_native(&mut contract, &wrong_header, &wrong_body)
                .err()
                .unwrap(),
            GovernanceReceiptV3Error::EnvelopeHashMismatch.into()
        );

        // The exact approved envelope finalizes once…
        assert_eq!(
            finalize_native(&mut contract, &header, &body).unwrap(),
            envelope_hash
        );
        assert!(contract.action_authorized(header.action_id));
        // …and never twice.
        assert_eq!(
            finalize_native(&mut contract, &header, &body).err().unwrap(),
            GovernanceReceiptV3Error::AlreadyFinalized.into()
        );
    }

    #[test]
    fn mainnet_rejects_official_x402_fail_closed() {
        // Validator level: an x402 header/body that is perfect by Testnet
        // rules still refuses on this profile with InvalidActionField (16).
        let (mut header, _) = native_call(b(0x51), b(0x52));
        header.action_kind = 2;
        header.decision_code = 1;
        header.requested_allocation_bps = 0;
        header.approved_allocation_bps = 0;
        assert_eq!(
            header.validate_basic().unwrap_err(),
            ValidationError::InvalidActionField
        );

        let x402_body = OfficialX402SettlementV1 {
            x402_version: 2,
            scheme: "exact".to_string(),
            caip2_network: "casper:casper-test".to_string(),
            wcspr_package: b(0x3d),
            wcspr_contract: b(0x03),
            token_name: "Wrapped CSPR".to_string(),
            token_symbol: "WCSPR".to_string(),
            eip712_domain_version: "1".to_string(),
            token_decimals: 9,
            payer: b(0x61),
            payee: b(0x62),
            value: U256::from(1_000_000u64),
            resource_url_hash: b(0x63),
            report_hash: b(0x64),
            payment_requirements_hash: b(0x65),
            signed_payment_payload_hash: b(0x66),
            eip712_auth_nonce: b(0x67),
            valid_after: 1,
            valid_before: 2,
            action_nonce: b(0x68),
            settlement_target: "cspr-cloud-facilitator".to_string(),
            settlement_version: 1,
        };
        assert_eq!(
            x402_body.validate_semantics().unwrap_err(),
            ValidationError::InvalidActionField
        );

        // Entry-point level: even with quorum satisfied for the committed
        // envelope, finalize_official_x402 refuses with the pinned outcome.
        let env = odra_test::env();
        let accounts = roles(&env);
        let mut contract = deploy(&env, &accounts);
        let x402_action_id =
            derive_action_id(2, x402_body.action_nonce, &x402_body.action_core_bytes().unwrap());
        header.action_id = x402_action_id;
        let envelope_hash =
            derive_envelope_hash(&header, &x402_body.canonical_bytes().unwrap());
        // Header canonical bytes already refuse on this profile, so the
        // envelope hash cannot even be derived for an x402 action…
        assert_eq!(envelope_hash.unwrap_err(), ValidationError::InvalidActionField);
        // …therefore commit an arbitrary 32-byte hash the way a hostile
        // proposer would, and prove the entry point still refuses.
        env.set_caller(accounts.proposer);
        contract.propose_envelope(header.proposal_id.clone(), b(0x7a));
        env.set_caller(accounts.signer_a);
        contract.approve_envelope(header.proposal_id.clone(), b(0x7a));
        env.set_caller(accounts.signer_b);
        contract.approve_envelope(header.proposal_id.clone(), b(0x7a));
        env.set_caller(accounts.finalizer);
        let refused = contract.try_finalize_official_x402(
            header.proposal_id.clone(),
            header.proposal_nonce,
            1,
            0,
            0,
            2,
            1,
            x402_action_id,
            header.proposal_hash,
            header.policy_hash,
            header.plan_hash,
            header.final_card_hash,
            header.dissent_hash,
            header.agent_action_hash,
            header.preauth_evidence_root,
            header.authorized_metadata_root,
            x402_body.x402_version,
            x402_body.scheme.clone(),
            x402_body.caip2_network.clone(),
            x402_body.wcspr_package,
            x402_body.wcspr_contract,
            x402_body.token_name.clone(),
            x402_body.token_symbol.clone(),
            x402_body.eip712_domain_version.clone(),
            x402_body.token_decimals,
            x402_body.payer,
            x402_body.payee,
            x402_body.value,
            x402_body.resource_url_hash,
            x402_body.report_hash,
            x402_body.payment_requirements_hash,
            x402_body.signed_payment_payload_hash,
            x402_body.eip712_auth_nonce,
            x402_body.valid_after,
            x402_body.valid_before,
            x402_body.action_nonce,
            x402_body.settlement_target.clone(),
            x402_body.settlement_version,
        );
        assert_eq!(
            refused.err().unwrap(),
            GovernanceReceiptV3Error::InvalidActionField.into()
        );
        assert!(!contract.finalized(header.proposal_id.clone()));
        assert!(!contract.action_authorized(x402_action_id));
    }
}
