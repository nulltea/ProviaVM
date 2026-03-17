#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use jolt::TrustedAdvice;
use jolt_inlines_rsa::verify::parse_pkcs1_modulus;
use jolt_inlines_rsa::verify_pkcs1v15_sha256_with_witness;
use jolt_inlines_sha2::Sha256;
use zkpassport_core::{
    contains_subsequence, is_over_18, parse_td3_mrz, unwrap_dg1_to_mrz, PassportInputRef, PassportOutput, Witness2048,
};

#[jolt::provable(stack_size = 131072, memory_size = 1048576, max_input_size = 65536, max_trusted_advice_size = 16384)]
fn verify_passport(witness: TrustedAdvice<Witness2048>, input: PassportInputRef<'_>) -> PassportOutput {
    let dg1_hash: [u8; 32] = Sha256::digest(input.dg1);
    assert!(contains_subsequence(input.encap_content, &dg1_hash), "DG1 hash not found in LDS Security Object");

    let content_digest: [u8; 32] = Sha256::digest(input.encap_content);
    assert!(contains_subsequence(input.signed_attrs_der, &content_digest), "content digest not found in signedAttrs");

    let attrs_hash: [u8; 32] = Sha256::digest(input.signed_attrs_der);
    let modulus = parse_pkcs1_modulus(input.ds_pubkey_der).expect("invalid DS public key");

    let signature_verified = verify_pkcs1v15_sha256_with_witness(
        &witness,
        &modulus,
        &input.signature,
        &input.rsa_challenge_seed,
        &attrs_hash,
    );
    assert!(signature_verified, "SOD signature verification failed");

    let mrz = unwrap_dg1_to_mrz(input.dg1).expect("failed to unwrap DG1 to MRZ");
    let parsed = parse_td3_mrz(mrz).expect("failed to parse TD3 MRZ");
    let over_18 = is_over_18(parsed.dob_yymmdd, input.today_yyyymmdd);

    PassportOutput { passive_auth_valid: true, over_18, issuing_country: parsed.issuing_country }
}
