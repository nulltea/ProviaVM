#![cfg_attr(feature = "guest", no_std)]

use jolt::{TrustedAdvice, start_cycle_tracking, end_cycle_tracking};
use jolt_inlines_rsa::verify::{
    limbs_to_bytes_be_2048,
    parse_pkcs1_modulus,
    verify_pkcs1v15_sha256_encoded,
};
use jolt_inlines_sha2::Sha256;
use zkemail_core::{DKIMInput, DKIMOutput, Rsa65537Witness2048, RsaStepOp};

const RSA_CHECK_BASES: [u32; 8] = [
    0x9e37_79b1,
    0x7f4a_7c15,
    0x94d0_49bb,
    0x2545_f491,
    0x27d4_eb2d,
    0x1656_67b1,
    0x85eb_ca77,
    0xc2b2_ae3d,
];

#[jolt::provable(
    stack_size = 131072,
    memory_size = 1048576,
    max_input_size = 65536,
    max_trusted_advice_size = 16384
)]
fn verify_dkim(witness: TrustedAdvice<Rsa65537Witness2048>, input: DKIMInput) -> DKIMOutput {
    // Hash the canonicalized signed headers
    start_cycle_tracking("zkemail.sha256_headers");
    let mut hasher = Sha256::new();
    hasher.update(&input.signed_headers);
    let header_hash: [u8; 32] = hasher.finalize();
    end_cycle_tracking("zkemail.sha256_headers");

    start_cycle_tracking("zkemail.parse_public_key");
    // Parse RSA modulus from PKCS#1 DER public key
    let n = parse_pkcs1_modulus(&input.public_key_der).expect("invalid PKCS#1 DER public key");
    end_cycle_tracking("zkemail.parse_public_key");

    start_cycle_tracking("zkemail.bind_witness");
    let modulus_be = limbs_to_bytes_be_2048(&n);
    let witness_modulus = expect_256(&witness.modulus_be, "witness modulus length");
    assert!(modulus_be == witness_modulus, "witness modulus mismatch");

    let mut sig_bytes = [0u8; 256];
    assert!(input.signature.len() == 256, "signature must be 256 bytes");
    sig_bytes.copy_from_slice(&input.signature);
    let witness_signature = expect_256(&witness.signature_be, "witness signature length");
    assert!(sig_bytes == witness_signature, "witness signature mismatch");
    end_cycle_tracking("zkemail.bind_witness");

    start_cycle_tracking("zkemail.rsa_verify");
    let verified = verify_witness_rsa_65537(&witness, &header_hash);
    end_cycle_tracking("zkemail.rsa_verify");

    // Hash from_domain and public_key for output commitment
    let from_domain_hash: [u8; 32] = Sha256::digest(&input.from_domain);

    let public_key_hash: [u8; 32] = Sha256::digest(&input.public_key_der);

    DKIMOutput {
        from_domain_hash,
        public_key_hash,
        verified,
    }
}

fn verify_witness_rsa_65537(
    witness: &Rsa65537Witness2048,
    message_hash: &[u8; 32],
) -> bool {
    start_cycle_tracking("zkemail.rsa_chain");
    if witness.steps.len() != 17 {
        end_cycle_tracking("zkemail.rsa_chain");
        return false;
    }

    let modulus_be = expect_256(&witness.modulus_be, "witness modulus length");
    let signature_be = expect_256(&witness.signature_be, "witness signature length");
    let mut current = signature_be;

    for (step_idx, step) in witness.steps.iter().enumerate() {
        let expected_op = if step_idx < 16 { RsaStepOp::Square } else { RsaStepOp::MulBase };
        if step.op != expected_op {
            end_cycle_tracking("zkemail.rsa_chain");
            return false;
        }

        let quotient_be = expect_256(&step.quotient_be, "witness quotient length");
        let remainder_be = expect_256(&step.remainder_be, "witness remainder length");
        let rhs = if step_idx < 16 { current } else { signature_be };
        if !bytes_lt(&remainder_be, &modulus_be) {
            end_cycle_tracking("zkemail.rsa_chain");
            return false;
        }
        if !check_modular_step(&current, &rhs, &quotient_be, &modulus_be, &remainder_be) {
            end_cycle_tracking("zkemail.rsa_chain");
            return false;
        }

        current = remainder_be;
    }
    end_cycle_tracking("zkemail.rsa_chain");

    start_cycle_tracking("zkemail.rsa_pkcs1");
    let verified = verify_pkcs1v15_sha256_encoded(&current, message_hash);
    end_cycle_tracking("zkemail.rsa_pkcs1");
    verified
}

fn check_modular_step(
    lhs_be: &[u8; 256],
    rhs_be: &[u8; 256],
    quotient_be: &[u8; 256],
    modulus_be: &[u8; 256],
    remainder_be: &[u8; 256],
) -> bool {
    for &base in &RSA_CHECK_BASES {
        let lhs = bytes_be_fingerprint(lhs_be, base);
        let rhs = bytes_be_fingerprint(rhs_be, base);
        let quotient = bytes_be_fingerprint(quotient_be, base);
        let modulus = bytes_be_fingerprint(modulus_be, base);
        let remainder = bytes_be_fingerprint(remainder_be, base);
        let left = lhs.wrapping_mul(rhs);
        let right = quotient.wrapping_mul(modulus).wrapping_add(remainder);
        if left != right {
            return false;
        }
    }
    true
}

fn bytes_be_fingerprint(bytes: &[u8; 256], base: u32) -> u32 {
    let mut acc = 0u32;
    let mut chunk_idx = 0usize;
    while chunk_idx < 64 {
        let i = chunk_idx * 4;
        let limb = u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        acc = acc.wrapping_mul(base).wrapping_add(limb);
        chunk_idx += 1;
    }
    acc
}

fn bytes_lt(lhs: &[u8; 256], rhs: &[u8; 256]) -> bool {
    let mut i = 0usize;
    while i < 256 {
        if lhs[i] != rhs[i] {
            return lhs[i] < rhs[i];
        }
        i += 1;
    }
    false
}

fn expect_256(bytes: &[u8], message: &str) -> [u8; 256] {
    let mut out = [0u8; 256];
    assert!(bytes.len() == 256, "{message}");
    out.copy_from_slice(bytes);
    out
}
