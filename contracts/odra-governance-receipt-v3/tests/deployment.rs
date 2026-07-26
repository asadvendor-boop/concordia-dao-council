use concordia_odra_governance_receipt_v3::{
    validated_deployment_init_args, DeploymentIdentity, DeploymentRoleInputs,
    DeploymentValidationError,
};

fn b(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn account(byte: u8) -> DeploymentIdentity {
    DeploymentIdentity::Account(b(byte))
}

fn valid_roles() -> DeploymentRoleInputs {
    DeploymentRoleInputs {
        proposer: account(2),
        finalizer: account(3),
        signer_a: account(4),
        signer_b: account(5),
        signer_c: account(6),
    }
}

#[test]
fn cfg_04_deployment_builder_rejects_contract_and_package_role_identities() {
    for (role_index, non_account) in [
        DeploymentIdentity::Contract(b(0x71)),
        DeploymentIdentity::ContractPackage(b(0x72)),
    ]
    .into_iter()
    .enumerate()
    {
        for target_role in 0..5 {
            let mut roles = valid_roles();
            match target_role {
                0 => roles.proposer = non_account,
                1 => roles.finalizer = non_account,
                2 => roles.signer_a = non_account,
                3 => roles.signer_b = non_account,
                4 => roles.signer_c = non_account,
                _ => unreachable!(),
            }
            match validated_deployment_init_args(
                account(1),
                roles,
                2,
                "casper-test".to_string(),
                b(0xa5),
            ) {
                Err(error) => assert_eq!(
                    error,
                    DeploymentValidationError::InvalidRoleAddress,
                    "identity variant {role_index}, role {target_role}"
                ),
                Ok(_) => panic!("identity variant {role_index}, role {target_role} was accepted"),
            }
        }
    }
}

#[test]
fn deployment_builder_emits_only_validated_account_bytes_for_the_odra_constructor() {
    let args = validated_deployment_init_args(
        account(1),
        valid_roles(),
        3,
        "casper-test".to_string(),
        b(0xa5),
    )
    .unwrap();
    assert_eq!(args.proposer, b(2));
    assert_eq!(args.finalizer, b(3));
    assert_eq!(args.signer_a, b(4));
    assert_eq!(args.signer_b, b(5));
    assert_eq!(args.signer_c, b(6));
    assert_eq!(args.threshold, 3);
    assert_eq!(args.casper_chain_name, "casper-test");
    assert_eq!(args.installation_nonce, b(0xa5));
}
