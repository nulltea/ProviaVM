#![cfg_attr(feature = "guest", no_std)]

use jolt::TrustedAdvice;
use jolt_inlines_rsa::verify::parse_pkcs1_modulus;
use jolt_inlines_rsa::verify_pkcs1v15_sha256_with_witness;
use jolt_inlines_sha2::Sha256;
use zkemail_core::{DKIMInputRef, DKIMOutput, Witness2048};

#[jolt::provable(stack_size = 131072, memory_size = 1048576, max_input_size = 65536, max_trusted_advice_size = 16384)]
fn verify_dkim(witness: TrustedAdvice<Witness2048>, input: DKIMInputRef<'_>) -> DKIMOutput {
    let mut hasher = Sha256::new();
    hasher.update(&input.signed_headers);
    let header_hash: [u8; 32] = hasher.finalize();

    let modulus = parse_pkcs1_modulus(&input.public_key_der).expect("invalid PKCS#1 DER public key");

    let signature_verified = verify_pkcs1v15_sha256_with_witness(
        &witness,
        &modulus,
        &input.signature,
        &input.rsa_challenge_seed,
        &header_hash,
    );

    let from_domain_hash: [u8; 32] = Sha256::digest(&input.from_domain);
    let public_key_hash: [u8; 32] = Sha256::digest(&input.public_key_der);

    DKIMOutput { from_domain_hash, public_key_hash, verified: signature_verified }
}
