#![cfg_attr(feature = "guest", no_std)]

use jolt::{TrustedAdvice, start_cycle_tracking, end_cycle_tracking};
use jolt_inlines_rsa::verify::{
    limbs_to_bytes_be_2048,
    parse_pkcs1_modulus,
    verify_pkcs1v15_sha256_encoded,
};
use jolt_inlines_sha2::Sha256;
use zkemail_core::{DKIMInput, DKIMOutput, Rsa65537Witness2048, RsaStepOp};

const RSA_CHECK_PRIMES: [(u32, u32); 4] = [
    (4_294_967_291, 5),
    (4_294_967_279, 17),
    (4_294_967_231, 65),
    (4_294_967_197, 99),
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
    let verified = verify_witness_rsa_65537(&witness, &input.rsa_challenge_seed, &header_hash);
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
    challenge_seed: &[u8; 32],
    message_hash: &[u8; 32],
) -> bool {
    start_cycle_tracking("zkemail.rsa_chain");
    if witness.steps.len() != 17 {
        end_cycle_tracking("zkemail.rsa_chain");
        return false;
    }

    let modulus_be = expect_256(&witness.modulus_be, "witness modulus length");
    let signature_be = expect_256(&witness.signature_be, "witness signature length");
    let challenge_bases = derive_challenge_bases(challenge_seed);
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
        if !check_modular_step(&current, &rhs, &quotient_be, &modulus_be, &remainder_be, &challenge_bases) {
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
    challenge_bases: &[u32; 4],
) -> bool {
    for (idx, &(prime, complement)) in RSA_CHECK_PRIMES.iter().enumerate() {
        let base = challenge_bases[idx];
        let lhs = bytes_be_fingerprint(lhs_be, base, prime, complement);
        let rhs = bytes_be_fingerprint(rhs_be, base, prime, complement);
        let quotient = bytes_be_fingerprint(quotient_be, base, prime, complement);
        let modulus = bytes_be_fingerprint(modulus_be, base, prime, complement);
        let remainder = bytes_be_fingerprint(remainder_be, base, prime, complement);
        let left = reduce_near_u32_prime((lhs as u64) * (rhs as u64), prime, complement);
        let right = reduce_near_u32_prime(
            (reduce_near_u32_prime((quotient as u64) * (modulus as u64), prime, complement) as u64)
                + (remainder as u64),
            prime,
            complement,
        );
        if left != right {
            return false;
        }
    }
    true
}

fn bytes_be_fingerprint(bytes: &[u8; 256], base: u32, prime: u32, complement: u32) -> u32 {
    let mut acc = 0u32;
    let mut chunk_idx = 0usize;
    while chunk_idx < 64 {
        let i = chunk_idx * 4;
        let limb = u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        acc = reduce_near_u32_prime((acc as u64) * (base as u64) + (limb as u64), prime, complement);
        chunk_idx += 1;
    }
    acc
}

fn reduce_near_u32_prime(mut value: u64, prime: u32, complement: u32) -> u32 {
    value = (value & 0xffff_ffff) + ((value >> 32) * complement as u64);
    value = (value & 0xffff_ffff) + ((value >> 32) * complement as u64);
    let prime_u64 = prime as u64;
    while value >= prime_u64 {
        value -= prime_u64;
    }
    value as u32
}

fn derive_challenge_bases(seed: &[u8; 32]) -> [u32; 4] {
    let mut bases = [0u32; 4];
    let mut i = 0usize;
    while i < RSA_CHECK_PRIMES.len() {
        let start = i * 4;
        let raw = u32::from_le_bytes([seed[start], seed[start + 1], seed[start + 2], seed[start + 3]]);
        let prime = RSA_CHECK_PRIMES[i].0;
        bases[i] = 2 + (raw % (prime - 3));
        i += 1;
    }
    bases
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
