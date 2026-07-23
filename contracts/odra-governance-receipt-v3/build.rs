//! Compile-time network profile selection.
//!
//! The release pipeline is pinned to `cargo --locked odra build` (cargo-odra
//! 0.1.7), which forwards no cargo flags, so Cargo features cannot select the
//! network profile through the accepted command. Instead exactly one
//! `--cfg` is injected here from CONCORDIA_V3_NETWORK_PROFILE:
//!
//!   CONCORDIA_V3_NETWORK_PROFILE=testnet        -> cfg network_profile_testnet
//!   CONCORDIA_V3_NETWORK_PROFILE=mainnet-native -> cfg network_profile_mainnet_native
//!
//! An unset, empty, or unknown value fails the build. A "both profiles"
//! build is unexpressible through this single variable, and encoding.rs
//! carries compile_error! guards for both the neither- and the both-cfg
//! states so no bypass of this script can produce a profile-less artifact.

fn main() {
    println!("cargo:rerun-if-env-changed=CONCORDIA_V3_NETWORK_PROFILE");
    println!(
        "cargo:rustc-check-cfg=cfg(network_profile_testnet,network_profile_mainnet_native)"
    );
    let profile = std::env::var("CONCORDIA_V3_NETWORK_PROFILE").unwrap_or_default();
    match profile.as_str() {
        "testnet" => println!("cargo:rustc-cfg=network_profile_testnet"),
        "mainnet-native" => println!("cargo:rustc-cfg=network_profile_mainnet_native"),
        other => panic!(
            "CONCORDIA_V3_NETWORK_PROFILE must be exactly `testnet` or \
             `mainnet-native` (got {other:?}); refusing to build a \
             profile-less governance contract"
        ),
    }
    odra_build::build();
}
