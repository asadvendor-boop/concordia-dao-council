#![no_std]
#![no_main]

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec,
};
use casper_contract::contract_api::{runtime, storage};
use casper_types::{
    CLType, EntityEntryPoint, EntryPointAccess, EntryPointPayment, EntryPointType, EntryPoints, Key,
    Parameter,
};

const CONTRACT_NAME: &str = "concordia_governance_receipt";
const PACKAGE_NAME: &str = "concordia_governance_receipt_package";
const ACCESS_UREF: &str = "concordia_governance_receipt_access_uref";

fn bytes32_to_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes.iter() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[no_mangle]
pub extern "C" fn store_governance_receipt() {
    let proposal_id: String = runtime::get_named_arg("proposal_id");
    let proposal_type: String = runtime::get_named_arg("proposal_type");
    let proposal_hash: [u8; 32] = runtime::get_named_arg("proposal_hash");
    let final_card_hash: [u8; 32] = runtime::get_named_arg("final_card_hash");
    let plan_hash: [u8; 32] = runtime::get_named_arg("plan_hash");
    let decision: String = runtime::get_named_arg("decision");
    let risk_level: String = runtime::get_named_arg("risk_level");
    let risk_score: u32 = runtime::get_named_arg("risk_score");
    let treasury_action: String = runtime::get_named_arg("treasury_action");
    let policy_hash: [u8; 32] = runtime::get_named_arg("policy_hash");
    let policy_version: String = runtime::get_named_arg("policy_version");
    let dissent_hash: [u8; 32] = runtime::get_named_arg("dissent_hash");
    let approved_allocation_bps: u32 = runtime::get_named_arg("approved_allocation_bps");
    let casper_network: String = runtime::get_named_arg("casper_network");
    let agent_council_version: String = runtime::get_named_arg("agent_council_version");
    let evidence_uri: String = runtime::get_named_arg("evidence_uri");
    let agent_action_hash: [u8; 32] = runtime::get_named_arg("agent_action_hash");

    let receipt = format!(
        "{{\"proposal_id\":\"{}\",\"proposal_type\":\"{}\",\"proposal_hash\":\"{}\",\"final_card_hash\":\"{}\",\"plan_hash\":\"{}\",\"decision\":\"{}\",\"risk_level\":\"{}\",\"risk_score\":{},\"treasury_action\":\"{}\",\"policy_hash\":\"{}\",\"policy_version\":\"{}\",\"dissent_hash\":\"{}\",\"approved_allocation_bps\":{},\"casper_network\":\"{}\",\"agent_council_version\":\"{}\",\"evidence_uri\":\"{}\",\"agent_action_hash\":\"{}\"}}",
        proposal_id,
        proposal_type,
        bytes32_to_hex(&proposal_hash),
        bytes32_to_hex(&final_card_hash),
        bytes32_to_hex(&plan_hash),
        decision,
        risk_level,
        risk_score,
        treasury_action,
        bytes32_to_hex(&policy_hash),
        policy_version,
        bytes32_to_hex(&dissent_hash),
        approved_allocation_bps,
        casper_network,
        agent_council_version,
        evidence_uri,
        bytes32_to_hex(&agent_action_hash)
    );

    let receipt_uref = storage::new_uref(receipt);
    runtime::put_key(&format!("concordia_receipt_{}", proposal_id), Key::URef(receipt_uref));
}

#[no_mangle]
pub extern "C" fn call() {
    let mut entry_points = EntryPoints::new();
    entry_points.add_entry_point(EntityEntryPoint::new(
        "store_governance_receipt",
        vec![
            Parameter::new("proposal_id", CLType::String),
            Parameter::new("proposal_type", CLType::String),
            Parameter::new("proposal_hash", CLType::ByteArray(32)),
            Parameter::new("final_card_hash", CLType::ByteArray(32)),
            Parameter::new("plan_hash", CLType::ByteArray(32)),
            Parameter::new("decision", CLType::String),
            Parameter::new("risk_level", CLType::String),
            Parameter::new("risk_score", CLType::U32),
            Parameter::new("treasury_action", CLType::String),
            Parameter::new("policy_hash", CLType::ByteArray(32)),
            Parameter::new("policy_version", CLType::String),
            Parameter::new("dissent_hash", CLType::ByteArray(32)),
            Parameter::new("approved_allocation_bps", CLType::U32),
            Parameter::new("casper_network", CLType::String),
            Parameter::new("agent_council_version", CLType::String),
            Parameter::new("evidence_uri", CLType::String),
            Parameter::new("agent_action_hash", CLType::ByteArray(32)),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    ));

    let (contract_hash, _contract_version) = storage::new_contract(
        entry_points,
        None,
        Some(PACKAGE_NAME.to_string()),
        Some(ACCESS_UREF.to_string()),
        None,
    );

    runtime::put_key(CONTRACT_NAME, Key::Hash(contract_hash.value()));
}
