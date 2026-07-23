use alloc::{string::String, vec::Vec};
use blake2::{
    digest::{consts::U32, Digest},
    Blake2b,
};
use odra::casper_types::{U256, U512};

pub const SCHEMA_VERSION: u32 = 3;
pub const ACTION_VERSION: u32 = 1;
pub const PACKAGE_KEY_NAME: &str = "concordia_governance_receipt_v3";
pub const NATIVE_TRANSFER_KIND: u8 = 1;
pub const OFFICIAL_X402_KIND: u8 = 2;

// --- Compile-time network profile -------------------------------------------
// Exactly one profile cfg is injected by build.rs from
// CONCORDIA_V3_NETWORK_PROFILE. These guards make a profile-less or
// double-profile compilation impossible even if build.rs is bypassed.
#[cfg(all(network_profile_testnet, network_profile_mainnet_native))]
compile_error!(
    "network profiles are mutually exclusive: both network_profile_testnet \
     and network_profile_mainnet_native are set"
);
#[cfg(not(any(network_profile_testnet, network_profile_mainnet_native)))]
compile_error!(
    "exactly one network profile is required: build with \
     CONCORDIA_V3_NETWORK_PROFILE=testnet or =mainnet-native"
);

#[cfg(network_profile_testnet)]
pub const CASPER_CHAIN_NAME: &str = "casper-test";
#[cfg(network_profile_mainnet_native)]
pub const CASPER_CHAIN_NAME: &str = "casper";

#[cfg(network_profile_testnet)]
pub const CAIP2_NETWORK: &str = "casper:casper-test";
#[cfg(network_profile_mainnet_native)]
pub const CAIP2_NETWORK: &str = "casper:casper";

/// OfficialX402SettlementV1 is a Testnet-proven WCSPR/CEP-18 flow. On the
/// Mainnet-native profile it stays disabled until every real Mainnet constant
/// (asset package, contract, decimals, scheme, facilitator) is independently
/// verified against a live Mainnet `/supported` observation; until then every
/// x402 action fails closed with `InvalidActionField` (User error: 16).
#[cfg(network_profile_testnet)]
pub const OFFICIAL_X402_SUPPORTED: bool = true;
#[cfg(network_profile_mainnet_native)]
pub const OFFICIAL_X402_SUPPORTED: bool = false;

// The Testnet separator is frozen history and must stay byte-identical; the
// Mainnet-native profile pins its own separator so the two deployment-domain
// spaces can never collide, even for equal chain-name/nonce inputs.
#[cfg(network_profile_testnet)]
const DOMAIN_SEPARATOR: &[u8] = b"CONCORDIA_DOMAIN_V3\0";
#[cfg(network_profile_mainnet_native)]
const DOMAIN_SEPARATOR: &[u8] = b"CONCORDIA_DOMAIN_V3_MAINNET\0";
const ENVELOPE_SEPARATOR: &[u8] = b"CONCORDIA_GOVERNANCE_ENVELOPE_V3\0";
const ACTION_ID_SEPARATOR: &[u8] = b"CONCORDIA_ACTION_ID_V3\0";
const TRANSFER_ID_SEPARATOR: &[u8] = b"CONCORDIA_TRANSFER_ID_V3\0";

pub const WCSPR_PACKAGE: [u8; 32] = [
    0x3d, 0x80, 0xdf, 0x21, 0xba, 0x4e, 0xe4, 0xd6, 0x6a, 0x2a, 0x1f, 0x60, 0xc3, 0x25, 0x70, 0xdd,
    0x56, 0x85, 0xe4, 0xb2, 0x79, 0xf6, 0x53, 0x81, 0x62, 0xa5, 0xfd, 0x13, 0x14, 0x84, 0x7c, 0x1e,
];

pub const WCSPR_CONTRACT: [u8; 32] = [
    0x03, 0x27, 0x06, 0xae, 0xae, 0x17, 0x0f, 0xaf, 0xb6, 0x40, 0x3c, 0xe3, 0xbe, 0xc5, 0x80, 0x62,
    0xf1, 0xc4, 0x28, 0x87, 0x10, 0x83, 0x8f, 0xe1, 0xdf, 0x98, 0xce, 0x4f, 0xf6, 0xc3, 0x5f, 0x4a,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    InvalidProposalId,
    InvalidEnvelopeField,
    InvalidActionField,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommonHeader {
    pub schema_version: u32,
    pub deployment_domain: [u8; 32],
    pub casper_chain_name: String,
    pub proposal_id: String,
    pub proposal_nonce: [u8; 32],
    pub decision_code: u8,
    pub requested_allocation_bps: u32,
    pub approved_allocation_bps: u32,
    pub action_kind: u8,
    pub action_version: u32,
    pub action_id: [u8; 32],
    pub proposal_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub plan_hash: [u8; 32],
    pub final_card_hash: [u8; 32],
    pub dissent_hash: [u8; 32],
    pub agent_action_hash: [u8; 32],
    pub preauth_evidence_root: [u8; 32],
    pub authorized_metadata_root: [u8; 32],
}

impl CommonHeader {
    pub fn validate_basic(&self) -> Result<(), ValidationError> {
        if !valid_proposal_id(&self.proposal_id) {
            return Err(ValidationError::InvalidProposalId);
        }
        if self.schema_version != SCHEMA_VERSION
            || self.casper_chain_name != CASPER_CHAIN_NAME
            || self.decision_code > 4
            || self.requested_allocation_bps > 10_000
            || self.approved_allocation_bps > 10_000
        {
            return Err(ValidationError::InvalidEnvelopeField);
        }
        if !matches!(self.action_kind, NATIVE_TRANSFER_KIND | OFFICIAL_X402_KIND)
            || self.action_version != ACTION_VERSION
        {
            return Err(ValidationError::InvalidActionField);
        }
        if !OFFICIAL_X402_SUPPORTED && self.action_kind == OFFICIAL_X402_KIND {
            return Err(ValidationError::InvalidActionField);
        }
        Ok(())
    }

    pub fn validate_semantics(&self) -> Result<(), ValidationError> {
        match self.action_kind {
            NATIVE_TRANSFER_KIND => match self.decision_code {
                1 if self.approved_allocation_bps > 0
                    && self.approved_allocation_bps == self.requested_allocation_bps =>
                {
                    Ok(())
                }
                2 if self.approved_allocation_bps > 0
                    && self.approved_allocation_bps < self.requested_allocation_bps =>
                {
                    Ok(())
                }
                _ => Err(ValidationError::InvalidEnvelopeField),
            },
            OFFICIAL_X402_KIND
                if self.decision_code == 1
                    && self.requested_allocation_bps == 0
                    && self.approved_allocation_bps == 0 =>
            {
                Ok(())
            }
            OFFICIAL_X402_KIND => Err(ValidationError::InvalidEnvelopeField),
            _ => Err(ValidationError::InvalidActionField),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ValidationError> {
        self.validate_basic()?;
        let mut out = Vec::with_capacity(460);
        put_u32(&mut out, self.schema_version);
        out.extend_from_slice(&self.deployment_domain);
        put_string(
            &mut out,
            &self.casper_chain_name,
            1,
            32,
            ValidationError::InvalidEnvelopeField,
        )?;
        put_string(
            &mut out,
            &self.proposal_id,
            1,
            64,
            ValidationError::InvalidProposalId,
        )?;
        out.extend_from_slice(&self.proposal_nonce);
        out.push(self.decision_code);
        put_u32(&mut out, self.requested_allocation_bps);
        put_u32(&mut out, self.approved_allocation_bps);
        out.push(self.action_kind);
        put_u32(&mut out, self.action_version);
        out.extend_from_slice(&self.action_id);
        out.extend_from_slice(&self.proposal_hash);
        out.extend_from_slice(&self.policy_hash);
        out.extend_from_slice(&self.plan_hash);
        out.extend_from_slice(&self.final_card_hash);
        out.extend_from_slice(&self.dissent_hash);
        out.extend_from_slice(&self.agent_action_hash);
        out.extend_from_slice(&self.preauth_evidence_root);
        out.extend_from_slice(&self.authorized_metadata_root);
        Ok(out)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTransferV1 {
    pub asset_kind: u8,
    pub source_account: [u8; 32],
    pub recipient_account: [u8; 32],
    pub amount_motes: U512,
    pub treasury_snapshot_balance_motes: U512,
    pub snapshot_block_hash: [u8; 32],
    pub snapshot_block_height: u64,
    pub transfer_id: u64,
    pub action_nonce: [u8; 32],
    pub execution_target: String,
    pub execution_version: u32,
}

impl NativeTransferV1 {
    pub fn validate_basic(&self) -> Result<(), ValidationError> {
        if is_zero32(&self.action_nonce) {
            return Err(ValidationError::InvalidActionField);
        }
        validate_printable(&self.execution_target, 1, 64)
            .map_err(|_| ValidationError::InvalidActionField)
    }

    pub fn validate_semantics(&self, approved_allocation_bps: u32) -> Result<(), ValidationError> {
        if self.asset_kind != 0
            || is_zero32(&self.source_account)
            || is_zero32(&self.recipient_account)
            || self.source_account == self.recipient_account
            || self.amount_motes.is_zero()
            || self.treasury_snapshot_balance_motes.is_zero()
            || self.execution_target != "native-transfer"
            || self.execution_version != 1
        {
            return Err(ValidationError::InvalidActionField);
        }
        let expected = self
            .treasury_snapshot_balance_motes
            .checked_mul(U512::from(approved_allocation_bps))
            .ok_or(ValidationError::InvalidActionField)?
            / U512::from(10_000u32);
        if self.amount_motes != expected {
            return Err(ValidationError::InvalidActionField);
        }
        Ok(())
    }

    pub fn action_core_bytes(&self) -> Result<Vec<u8>, ValidationError> {
        self.validate_basic()?;
        let mut out = Vec::with_capacity(256);
        out.push(self.asset_kind);
        out.extend_from_slice(&self.source_account);
        out.extend_from_slice(&self.recipient_account);
        put_u512(&mut out, self.amount_motes);
        put_u512(&mut out, self.treasury_snapshot_balance_motes);
        out.extend_from_slice(&self.snapshot_block_hash);
        put_u64(&mut out, self.snapshot_block_height);
        put_string(
            &mut out,
            &self.execution_target,
            1,
            64,
            ValidationError::InvalidActionField,
        )?;
        put_u32(&mut out, self.execution_version);
        Ok(out)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ValidationError> {
        self.validate_basic()?;
        let mut out = Vec::with_capacity(296);
        out.push(self.asset_kind);
        out.extend_from_slice(&self.source_account);
        out.extend_from_slice(&self.recipient_account);
        put_u512(&mut out, self.amount_motes);
        put_u512(&mut out, self.treasury_snapshot_balance_motes);
        out.extend_from_slice(&self.snapshot_block_hash);
        put_u64(&mut out, self.snapshot_block_height);
        put_u64(&mut out, self.transfer_id);
        out.extend_from_slice(&self.action_nonce);
        put_string(
            &mut out,
            &self.execution_target,
            1,
            64,
            ValidationError::InvalidActionField,
        )?;
        put_u32(&mut out, self.execution_version);
        Ok(out)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialX402SettlementV1 {
    pub x402_version: u32,
    pub scheme: String,
    pub caip2_network: String,
    pub wcspr_package: [u8; 32],
    pub wcspr_contract: [u8; 32],
    pub token_name: String,
    pub token_symbol: String,
    pub eip712_domain_version: String,
    pub token_decimals: u8,
    pub payer: [u8; 32],
    pub payee: [u8; 32],
    pub value: U256,
    pub resource_url_hash: [u8; 32],
    pub report_hash: [u8; 32],
    pub payment_requirements_hash: [u8; 32],
    pub signed_payment_payload_hash: [u8; 32],
    pub eip712_auth_nonce: [u8; 32],
    pub valid_after: u64,
    pub valid_before: u64,
    pub action_nonce: [u8; 32],
    pub settlement_target: String,
    pub settlement_version: u32,
}

impl OfficialX402SettlementV1 {
    pub fn validate_basic(&self) -> Result<(), ValidationError> {
        for (value, max) in [
            (&self.scheme, 16usize),
            (&self.caip2_network, 32),
            (&self.token_name, 32),
            (&self.token_symbol, 16),
            (&self.eip712_domain_version, 16),
            (&self.settlement_target, 64),
        ] {
            validate_printable(value, 1, max).map_err(|_| ValidationError::InvalidActionField)?;
        }
        if is_zero32(&self.action_nonce) {
            return Err(ValidationError::InvalidActionField);
        }
        Ok(())
    }

    pub fn validate_semantics(&self) -> Result<(), ValidationError> {
        if !OFFICIAL_X402_SUPPORTED {
            return Err(ValidationError::InvalidActionField);
        }
        if self.x402_version != 2
            || self.scheme != "exact"
            || self.caip2_network != CAIP2_NETWORK
            || self.wcspr_package != WCSPR_PACKAGE
            || self.wcspr_contract != WCSPR_CONTRACT
            || self.token_name != "Wrapped CSPR"
            || self.token_symbol != "WCSPR"
            || self.eip712_domain_version != "1"
            || self.token_decimals != 9
            || is_zero32(&self.payer)
            || is_zero32(&self.payee)
            || self.payer == self.payee
            || self.value.is_zero()
            || is_zero32(&self.resource_url_hash)
            || is_zero32(&self.report_hash)
            || is_zero32(&self.payment_requirements_hash)
            || is_zero32(&self.signed_payment_payload_hash)
            || is_zero32(&self.eip712_auth_nonce)
            || self.valid_before <= self.valid_after
            || self.settlement_target != "cspr-cloud-facilitator"
            || self.settlement_version != 1
        {
            return Err(ValidationError::InvalidActionField);
        }
        Ok(())
    }

    pub fn encode_value(value: U256) -> [u8; 32] {
        let mut encoded = [0u8; 32];
        value.to_big_endian(&mut encoded);
        encoded
    }

    pub fn action_core_bytes(&self) -> Result<Vec<u8>, ValidationError> {
        self.validate_basic()?;
        let mut out = Vec::with_capacity(432);
        self.put_core(&mut out)?;
        Ok(out)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ValidationError> {
        self.validate_basic()?;
        let mut out = Vec::with_capacity(464);
        self.put_prefix(&mut out)?;
        out.extend_from_slice(&self.action_nonce);
        put_string(
            &mut out,
            &self.settlement_target,
            1,
            64,
            ValidationError::InvalidActionField,
        )?;
        put_u32(&mut out, self.settlement_version);
        Ok(out)
    }

    fn put_core(&self, out: &mut Vec<u8>) -> Result<(), ValidationError> {
        self.put_prefix(out)?;
        put_string(
            out,
            &self.settlement_target,
            1,
            64,
            ValidationError::InvalidActionField,
        )?;
        put_u32(out, self.settlement_version);
        Ok(())
    }

    fn put_prefix(&self, out: &mut Vec<u8>) -> Result<(), ValidationError> {
        put_u32(out, self.x402_version);
        put_string(
            out,
            &self.scheme,
            1,
            16,
            ValidationError::InvalidActionField,
        )?;
        put_string(
            out,
            &self.caip2_network,
            1,
            32,
            ValidationError::InvalidActionField,
        )?;
        out.extend_from_slice(&self.wcspr_package);
        out.extend_from_slice(&self.wcspr_contract);
        put_string(
            out,
            &self.token_name,
            1,
            32,
            ValidationError::InvalidActionField,
        )?;
        put_string(
            out,
            &self.token_symbol,
            1,
            16,
            ValidationError::InvalidActionField,
        )?;
        put_string(
            out,
            &self.eip712_domain_version,
            1,
            16,
            ValidationError::InvalidActionField,
        )?;
        out.push(self.token_decimals);
        out.extend_from_slice(&self.payer);
        out.extend_from_slice(&self.payee);
        out.extend_from_slice(&Self::encode_value(self.value));
        out.extend_from_slice(&self.resource_url_hash);
        out.extend_from_slice(&self.report_hash);
        out.extend_from_slice(&self.payment_requirements_hash);
        out.extend_from_slice(&self.signed_payment_payload_hash);
        out.extend_from_slice(&self.eip712_auth_nonce);
        put_u64(out, self.valid_after);
        put_u64(out, self.valid_before);
        Ok(())
    }
}

pub fn derive_deployment_domain(
    casper_chain_name: &str,
    installation_nonce: [u8; 32],
) -> Result<[u8; 32], ValidationError> {
    if casper_chain_name != CASPER_CHAIN_NAME || is_zero32(&installation_nonce) {
        return Err(ValidationError::InvalidEnvelopeField);
    }
    let mut preimage = Vec::with_capacity(128);
    preimage.extend_from_slice(DOMAIN_SEPARATOR);
    put_string(
        &mut preimage,
        casper_chain_name,
        1,
        32,
        ValidationError::InvalidEnvelopeField,
    )?;
    put_string(
        &mut preimage,
        PACKAGE_KEY_NAME,
        1,
        64,
        ValidationError::InvalidEnvelopeField,
    )?;
    preimage.extend_from_slice(&installation_nonce);
    Ok(blake2b256(&preimage))
}

pub fn derive_action_id(
    action_kind: u8,
    action_nonce: [u8; 32],
    action_core_bytes: &[u8],
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(ACTION_ID_SEPARATOR.len() + 33 + action_core_bytes.len());
    preimage.extend_from_slice(ACTION_ID_SEPARATOR);
    preimage.push(action_kind);
    preimage.extend_from_slice(&action_nonce);
    preimage.extend_from_slice(action_core_bytes);
    blake2b256(&preimage)
}

pub fn derive_transfer_id(
    proposal_id: &str,
    proposal_nonce: [u8; 32],
    action_id: [u8; 32],
) -> Result<u64, ValidationError> {
    if !valid_proposal_id(proposal_id) {
        return Err(ValidationError::InvalidProposalId);
    }
    let mut preimage = Vec::with_capacity(160);
    preimage.extend_from_slice(TRANSFER_ID_SEPARATOR);
    put_string(
        &mut preimage,
        proposal_id,
        1,
        64,
        ValidationError::InvalidProposalId,
    )?;
    preimage.extend_from_slice(&proposal_nonce);
    preimage.extend_from_slice(&action_id);
    let digest = blake2b256(&preimage);
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    Ok(u64::from_be_bytes(first))
}

pub fn derive_envelope_hash(
    header: &CommonHeader,
    action_body_bytes: &[u8],
) -> Result<[u8; 32], ValidationError> {
    let header_bytes = header.canonical_bytes()?;
    let mut preimage =
        Vec::with_capacity(ENVELOPE_SEPARATOR.len() + header_bytes.len() + action_body_bytes.len());
    preimage.extend_from_slice(ENVELOPE_SEPARATOR);
    preimage.extend_from_slice(&header_bytes);
    preimage.extend_from_slice(action_body_bytes);
    Ok(blake2b256(&preimage))
}

pub fn valid_proposal_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'-')
}

pub fn is_zero32(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn validate_printable(value: &str, min: usize, max: usize) -> Result<(), ()> {
    if value.len() < min
        || value.len() > max
        || !value
            .as_bytes()
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte))
    {
        return Err(());
    }
    Ok(())
}

fn put_string(
    out: &mut Vec<u8>,
    value: &str,
    min: usize,
    max: usize,
    error: ValidationError,
) -> Result<(), ValidationError> {
    validate_printable(value, min, max).map_err(|_| error)?;
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u512(out: &mut Vec<u8>, value: U512) {
    let mut encoded = [0u8; 64];
    value.to_big_endian(&mut encoded);
    out.extend_from_slice(&encoded);
}

fn blake2b256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
