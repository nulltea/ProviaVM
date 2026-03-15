#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use jolt_inlines_rsa::verify::{parse_pkcs1_modulus, rsa_verify_pkcs1v15_sha256};
use jolt_inlines_sha2::Sha256;
use zkemail_core::{DKIMInput, DKIMOutput};

#[jolt::provable(stack_size = 131072, memory_size = 1048576, max_input_size = 65536)]
fn verify_dkim(input: DKIMInput) -> DKIMOutput {
    // Hash the canonicalized signed headers
    let mut hasher = Sha256::new();
    hasher.update(&input.signed_headers);
    let header_hash: [u8; 32] = hasher.finalize();

    // Parse RSA modulus from PKCS#1 DER public key
    let n = parse_pkcs1_modulus(&input.public_key_der).expect("invalid PKCS#1 DER public key");

    // Convert signature to fixed-size array
    let mut sig_bytes = [0u8; 256];
    assert!(input.signature.len() == 256, "signature must be 256 bytes");
    sig_bytes.copy_from_slice(&input.signature);

    // Verify RSA PKCS#1 v1.5 signature with SHA-256 using Montgomery inline
    let verified = rsa_verify_pkcs1v15_sha256(&n, &sig_bytes, &header_hash);

    // Hash from_domain and public_key for output commitment
    let from_domain_hash: [u8; 32] = Sha256::digest(&input.from_domain);

    let public_key_hash: [u8; 32] = Sha256::digest(&input.public_key_der);

    DKIMOutput {
        from_domain_hash,
        public_key_hash,
        verified,
    }
}
