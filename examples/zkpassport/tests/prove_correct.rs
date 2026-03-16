// Ensure inline #[ctor] registers sequence builders.
use jolt_inlines_sha2 as _;
use jolt_inlines_bigint as _;
use jolt_inlines_rsa as _;

use provia_jolt_sdk::TrustedAdvice;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

use jolt_core::host::Program;
use jolt_inlines_rsa::{build_witness_2048, witness_seed_from_commitment_bytes, Bytes2048, Witness2048};
use jolt_inlines_sha2::Sha256;
use provia_worker::utils::test_utils::{
    build_test_fixture_from_parts, prove_test_fixture, verify_test_fixture, worker_test_lock,
    TestFixture,
};
use zkpassport_core::PassportInput;

fn configure_program() -> Program {
    let mut program = Program::new("zkpassport-guest");
    #[cfg(feature = "rv64")]
    program.add_feature("rv64");
    program.set_func("verify_passport");
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

// DER helpers for fixture construction
fn der_seq(items: &[&[u8]]) -> Vec<u8> {
    der_constructed(0x30, items)
}

fn der_constructed(tag: u8, items: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = items.iter().map(|i| i.len()).sum();
    let mut buf = Vec::with_capacity(4 + total_len);
    buf.push(tag);
    if total_len < 0x80 {
        buf.push(total_len as u8);
    } else if total_len <= 0xFF {
        buf.push(0x81);
        buf.push(total_len as u8);
    } else {
        buf.push(0x82);
        buf.push((total_len >> 8) as u8);
        buf.push(total_len as u8);
    }
    for item in items {
        buf.extend_from_slice(item);
    }
    buf
}

fn build_zkpassport_fixture() -> (PassportInput, Witness2048) {
    use jolt_inlines_rsa::verify::parse_pkcs1_modulus;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::signature::{SignatureEncoding, Signer};

    let mut rng = ChaCha12Rng::seed_from_u64(42);
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = rsa::RsaPublicKey::from(&private_key);

    // Build TD3 MRZ (88 bytes)
    let mut mrz = [b'<'; 88];
    mrz[0] = b'P';
    mrz[2..5].copy_from_slice(b"UTO");
    mrz[5..25].copy_from_slice(b"ERIKSSON<<ANNA<MARIA");
    let line2 = &mut mrz[44..];
    line2[..10].copy_from_slice(b"L898902C36");
    line2[10..13].copy_from_slice(b"UTO");
    line2[13..19].copy_from_slice(b"000315"); // DOB: 2000-03-15
    line2[19] = b'0';
    line2[20] = b'F';
    line2[21..27].copy_from_slice(b"301231");
    line2[27] = b'0';

    // DG1 TLV: 0x61 || len || 0x5F1F || len || mrz
    let mut dg1 = Vec::with_capacity(93);
    dg1.push(0x61);
    dg1.push(91); // 2 + 1 + 88
    dg1.push(0x5F);
    dg1.push(0x1F);
    dg1.push(88);
    dg1.extend_from_slice(&mrz);

    let dg1_hash: [u8; 32] = Sha256::digest(&dg1);

    // LDS Security Object (minimal DER)
    let encap_content = {
        let dg_num = vec![0x02, 0x01, 1u8]; // INTEGER 1
        let dg_hash = {
            let mut v = vec![0x04, 32];
            v.extend_from_slice(&dg1_hash);
            v
        };
        let dg_hash_seq = der_seq(&[&dg_num, &dg_hash]);
        let dg_hashes = der_seq(&[&dg_hash_seq]);
        let oid_sha256: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let null = [0x05, 0x00];
        let hash_alg = der_seq(&[oid_sha256, &null]);
        let version = vec![0x02, 0x01, 0u8]; // INTEGER 0
        der_seq(&[&version, &hash_alg, &dg_hashes])
    };

    let content_digest: [u8; 32] = Sha256::digest(&encap_content);

    // signedAttrs (DER SET OF)
    let signed_attrs_der = {
        let oid_content_type: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
        let oid_id_data: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
        let oid_message_digest: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];

        let ct_value_set = der_constructed(0x31, &[oid_id_data]);
        let ct_attr = der_seq(&[oid_content_type, &ct_value_set]);
        let md_octet = {
            let mut v = vec![0x04, 32];
            v.extend_from_slice(&content_digest);
            v
        };
        let md_value_set = der_constructed(0x31, &[&md_octet]);
        let md_attr = der_seq(&[oid_message_digest, &md_value_set]);
        der_constructed(0x31, &[&ct_attr, &md_attr])
    };

    // RSA sign signedAttrs
    let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key);
    let signature: Vec<u8> = signing_key.sign(&signed_attrs_der).to_vec();
    let ds_pubkey_der = public_key.to_pkcs1_der().unwrap().to_vec();

    let modulus = parse_pkcs1_modulus(&ds_pubkey_der).unwrap();
    let sig_bytes = Bytes2048(signature.clone().try_into().unwrap());
    let witness = build_witness_2048(&modulus, &sig_bytes);

    let mut input = PassportInput {
        dg1,
        encap_content,
        signed_attrs_der,
        signature,
        ds_pubkey_der,
        rsa_challenge_seed: [0u8; 32],
        today_yyyymmdd: 20260315,
    };
    input.rsa_challenge_seed = challenge_seed_from_witness(&witness);

    (input, witness)
}

fn prove_zkpassport_fixture() -> TestFixture {
    let mut program = configure_program();
    let (input, witness) = build_zkpassport_fixture();
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

    let (input, witness) = build_zkpassport_fixture();
    let inputs = postcard::to_stdvec(&input).unwrap();
    let trusted_advice = postcard::to_stdvec(&TrustedAdvice::from(witness)).unwrap();
    eprintln!("Serialized input size: {} bytes", inputs.len());
    eprintln!("Serialized trusted advice size: {} bytes", trusted_advice.len());

    let (trace, _memory, io_device) = program.trace(&[], &inputs, &trusted_advice);
    eprintln!("Trace length: {}", trace.len());
    eprintln!("Panic: {}", io_device.panic);
    assert!(!io_device.panic, "zkpassport guest panicked");
}

#[test]
fn prove_correct() {
    let _test_guard = worker_test_lock();
    let fixture = prove_zkpassport_fixture();
    verify_test_fixture(fixture).expect("Vanilla verification of zkpassport MPC proof failed");
}
