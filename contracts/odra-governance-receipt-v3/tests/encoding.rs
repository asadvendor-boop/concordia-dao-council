use concordia_odra_governance_receipt_v3::{
    derive_action_id, derive_deployment_domain, derive_envelope_hash, derive_transfer_id,
    CommonHeader, NativeTransferV1, OfficialX402SettlementV1, ValidationError,
};
use odra::casper_types::{U256, U512};

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

fn native_fixture(proposal_id: &str, proposal_nonce: [u8; 32]) -> (CommonHeader, NativeTransferV1) {
    let action_nonce = b(0x44);
    let mut body = NativeTransferV1 {
        asset_kind: 0,
        source_account: b(0x41),
        recipient_account: b(0x42),
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
        deployment_domain: h("40804e79504df011ccbe7326898a9d7e489e01b445f483a199467584ddfb5726"),
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
    (header, body)
}

fn x402_fixture() -> (CommonHeader, OfficialX402SettlementV1) {
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
        resource_url_hash: h("20fc9888adc9639d9f0df5515e8f00cfc6692abec50dd1e7786602fbb8861798"),
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
    let header = CommonHeader {
        schema_version: 3,
        deployment_domain: h("40804e79504df011ccbe7326898a9d7e489e01b445f483a199467584ddfb5726"),
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
    };
    (header, body)
}

#[test]
fn deployment_domain_matches_gv_hdr_01() {
    let actual = derive_deployment_domain("casper-test", b(0xa5)).unwrap();
    assert_eq!(
        actual,
        h("40804e79504df011ccbe7326898a9d7e489e01b445f483a199467584ddfb5726")
    );
}

#[test]
fn native_gv_nt_01_matches_all_contract_derivations() {
    let (header, body) = native_fixture("DAO-PROP-V3-001", b(0x10));
    assert_eq!(
        header.action_id,
        h("adb7e7a923b960ece3d0f122cefa0b052b750f71ec99fcaf67c20f339e14c9e1")
    );
    assert_eq!(body.transfer_id, 2_386_608_944_735_597_299);
    assert_eq!(body.canonical_bytes().unwrap().len(), 296);
    assert_eq!(
        derive_envelope_hash(&header, &body.canonical_bytes().unwrap()).unwrap(),
        h("9b3b6c9ec91cbc6ffb657addce26b47172835e2a8337cf209eca78ac664ab646")
    );
}

#[test]
fn action_id_is_proposal_independent_but_native_transfer_id_is_not() {
    let (header_a, body_a) = native_fixture("DAO-PROP-V3-001", b(0x10));
    let (header_b, body_b) = native_fixture("DAO-PROP-V3-002", b(0x11));
    assert_eq!(header_a.action_id, header_b.action_id);
    assert_ne!(body_a.transfer_id, body_b.transfer_id);
    assert_eq!(body_b.transfer_id, 17_129_722_949_619_933_895);
}

#[test]
fn semantic_or_nonce_change_changes_native_action_id() {
    let (header, mut body) = native_fixture("DAO-PROP-V3-001", b(0x10));
    body.recipient_account = b(0x49);
    let changed_semantics =
        derive_action_id(1, body.action_nonce, &body.action_core_bytes().unwrap());
    assert_ne!(header.action_id, changed_semantics);
    assert_eq!(
        changed_semantics,
        h("c33bdbddafa6178a2d230091f1f85aa676de6798ff8083c9116b1cca4b370a4c")
    );
    let changed_nonce = derive_action_id(
        1,
        b(0x45),
        &native_fixture("DAO-PROP-V3-001", b(0x10))
            .1
            .action_core_bytes()
            .unwrap(),
    );
    assert_eq!(
        changed_nonce,
        h("c95dd8bc172fdcd5eb7c0ee79b509b9964fbb407397e7fdd4198c6ffc0cc2028")
    );
}

#[test]
fn official_x402_gv_x4_01_matches_action_and_envelope_hashes() {
    let (header, body) = x402_fixture();
    assert_eq!(
        header.action_id,
        h("047da89a2ea2f286e2fe84267f74e864d351f523adbe17eeb34a1b1641aed373")
    );
    assert_eq!(body.canonical_bytes().unwrap().len(), 464);
    assert_eq!(
        derive_envelope_hash(&header, &body.canonical_bytes().unwrap()).unwrap(),
        h("3902fc5ae46d5f337b18ad4e7acfa7c05b6b8c0b52d3a3c72aaf5d5286ae450d")
    );
}

#[test]
fn checked_u256_encoding_is_always_fixed_width_big_endian() {
    assert_eq!(
        OfficialX402SettlementV1::encode_value(U256::zero()),
        [0u8; 32]
    );
    let one = OfficialX402SettlementV1::encode_value(U256::one());
    assert_eq!(one[31], 1);
    assert!(one[..31].iter().all(|byte| *byte == 0));
    assert_eq!(
        OfficialX402SettlementV1::encode_value(U256::MAX),
        [0xff; 32]
    );
}

#[test]
fn invalid_header_vectors_fail_with_the_frozen_error_class() {
    let (mut header, _) = native_fixture("DAO-PROP-V3-001", b(0x10));
    header.proposal_id = "dao-prop-lowercase".to_string();
    assert_eq!(
        header.canonical_bytes().unwrap_err(),
        ValidationError::InvalidProposalId
    );

    header.proposal_id = "DAO-PROP-V3-001".to_string();
    header.requested_allocation_bps = 10_001;
    assert_eq!(
        header.canonical_bytes().unwrap_err(),
        ValidationError::InvalidEnvelopeField
    );
}

#[test]
fn native_allocation_math_is_checked_before_authorization() {
    let (_, mut body) = native_fixture("DAO-PROP-V3-001", b(0x10));
    body.treasury_snapshot_balance_motes = U512::MAX;
    assert_eq!(
        body.validate_semantics(10_000).unwrap_err(),
        ValidationError::InvalidActionField
    );
}

#[test]
fn x402_validity_window_is_a_cross_field_policy_invariant() {
    let (_, mut body) = x402_fixture();
    body.valid_before = body.valid_after;
    assert_eq!(
        body.validate_semantics().unwrap_err(),
        ValidationError::InvalidActionField
    );
}
