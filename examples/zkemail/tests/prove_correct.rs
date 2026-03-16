// Ensure inline #[ctor] registers sequence builders.
use jolt_inlines_bigint as _;
use jolt_inlines_rsa as _;
use jolt_inlines_sha2 as _;

use provia_jolt_sdk::TrustedAdvice;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use sha2::Digest;

use jolt_core::host::Program;
use jolt_inlines_rsa::{build_witness_2048, witness_seed_from_commitment_bytes, Bytes2048, Witness2048};
use provia_worker::utils::test_utils::{
    build_test_fixture_from_parts, prove_test_fixture, verify_test_fixture, worker_test_lock, TestFixture,
};
use zkemail_core::DKIMInput;

fn configure_program() -> Program {
    let mut program = Program::new("zkemail-guest");
    #[cfg(feature = "rv64")]
    program.add_feature("rv64");
    program.set_func("verify_dkim");
    program.set_stack_size(131072);
    program.set_memory_size(1048576);
    program.set_max_input_size(65536);
    program.set_max_trusted_advice_size(16384);
    program
}

fn challenge_seed_from_witness(witness: &Witness2048) -> [u8; 32] {
    let witness_bytes = postcard::to_stdvec(witness).unwrap();
    witness_seed_from_commitment_bytes(&witness_bytes)
}

fn build_zkemail_fixture() -> (DKIMInput, Witness2048) {
    use jolt_inlines_rsa::verify::{parse_pkcs1_modulus, verify_pkcs1v15_sha256_encoded};
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::signature::{SignatureEncoding, Signer};

    let mut rng = ChaCha12Rng::seed_from_u64(42);
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = rsa::RsaPublicKey::from(&private_key);
    let signed_headers = b"from:test@example.com\r\nto:bob@example.com\r\n".to_vec();
    let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key);
    let signature_obj = signing_key.sign(&signed_headers);
    let signature = signature_obj.to_vec();
    let public_key_der = public_key.to_pkcs1_der().unwrap().to_vec();

    let mut input = DKIMInput {
        signed_headers,
        signature,
        public_key_der,
        from_domain: b"example.com".to_vec(),
        rsa_challenge_seed: [0u8; 32],
    };

    let modulus = parse_pkcs1_modulus(&input.public_key_der).unwrap();
    let signature = Bytes2048(input.signature.clone().try_into().unwrap());
    let header_hash: [u8; 32] = sha2::Sha256::digest(&input.signed_headers).into();
    let witness = build_witness_2048(&modulus, &signature);
    let final_be = jolt_inlines_rsa::verify::limbs_to_bytes_be_2048(&witness.steps[16].remainder_limbs.0);
    assert!(verify_pkcs1v15_sha256_encoded(&final_be, &header_hash));
    input.rsa_challenge_seed = challenge_seed_from_witness(&witness);

    (input, witness)
}

fn prove_zkemail_fixture() -> TestFixture {
    let mut program = configure_program();
    let (input, witness) = build_zkemail_fixture();
    let untrusted_advice = postcard::to_stdvec(&input).unwrap();
    let trusted_advice = postcard::to_stdvec(&TrustedAdvice::from(witness)).unwrap();

    let (shares, preprocessing, verifier_preprocessing, io_device, ram_k, padded_len) =
        build_test_fixture_from_parts(&mut program, vec![], untrusted_advice, trusted_advice);

    prove_test_fixture(shares, preprocessing, verifier_preprocessing, io_device, ram_k, padded_len)
}

#[test]
fn trace_only() {
    let _test_guard = worker_test_lock();
    let mut program = configure_program();

    let (input, prepared) = build_zkemail_fixture();
    let inputs = postcard::to_stdvec(&input).unwrap();
    let trusted_advice = postcard::to_stdvec(&TrustedAdvice::from(prepared)).unwrap();
    eprintln!("Serialized input size: {} bytes", inputs.len());
    eprintln!("Serialized trusted advice size: {} bytes", trusted_advice.len());

    let (trace, _memory, io_device) = program.trace(&[], &inputs, &trusted_advice);
    eprintln!("Trace length: {}", trace.len());
    eprintln!("Panic: {}", io_device.panic);
    assert!(!io_device.panic, "zkemail guest panicked");
}

#[test]
fn prove_correct() {
    let _test_guard = worker_test_lock();
    let fixture = prove_zkemail_fixture();
    verify_test_fixture(fixture).expect("Vanilla verification of zkemail MPC proof failed");
}
