#![cfg_attr(feature = "guest", no_std)]

use jolt::{end_cycle_tracking, start_cycle_tracking, TrustedAdvice};
use jolt_inlines_rsa::{
    rsa_verify_witness_pkcs1v15_sha256,
    Bytes2048,
};
use jolt_inlines_rsa::verify::{parse_pkcs1_modulus, verify_pkcs1v15_sha256_encoded};
use jolt_inlines_sha2::Sha256;
use zkemail_core::{DKIMInput, DKIMOutput, Rsa65537Witness2048};

#[jolt::provable(
    stack_size = 131072,
    memory_size = 1048576,
    max_input_size = 65536,
    max_trusted_advice_size = 16384
)]
fn verify_dkim(witness: TrustedAdvice<Rsa65537Witness2048>, input: DKIMInput) -> DKIMOutput {
    start_cycle_tracking("zkemail.sha256_headers");
    let mut hasher = Sha256::new();
    hasher.update(&input.signed_headers);
    let header_hash: [u8; 32] = hasher.finalize();
    end_cycle_tracking("zkemail.sha256_headers");

    start_cycle_tracking("zkemail.parse_public_key");
    let modulus = parse_pkcs1_modulus(&input.public_key_der).expect("invalid PKCS#1 DER public key");
    end_cycle_tracking("zkemail.parse_public_key");

    start_cycle_tracking("zkemail.bind_witness");
    assert!(input.signature.len() == 256, "signature must be 256 bytes");
    let signature = Bytes2048(input.signature.as_slice().try_into().expect("signature length"));
    end_cycle_tracking("zkemail.bind_witness");

    start_cycle_tracking("zkemail.rsa_verify");
    let verified = rsa_verify_witness_pkcs1v15_sha256(
        &witness,
        &modulus,
        &signature,
        &input.rsa_challenge_seed,
        &header_hash,
    );
    end_cycle_tracking("zkemail.rsa_verify");

    let from_domain_hash: [u8; 32] = Sha256::digest(&input.from_domain);
    let public_key_hash: [u8; 32] = Sha256::digest(&input.public_key_der);

    DKIMOutput {
        from_domain_hash,
        public_key_hash,
        verified,
    }
}

#[allow(dead_code)]
fn _assert_verify_helper_linked(encoded: &[u8; 256], hash: &[u8; 32]) -> bool {
    verify_pkcs1v15_sha256_encoded(encoded, hash)
}
