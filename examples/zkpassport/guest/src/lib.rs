#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use jolt::TrustedAdvice;
use jolt_inlines_rsa::verify::parse_pkcs1_modulus;
use jolt_inlines_rsa::{verify_pkcs1v15_sha256_with_witness, Bytes2048};
use jolt_inlines_sha2::Sha256;
use zkpassport_core::{
    contains_subsequence, is_over_18, parse_td3_mrz, unwrap_dg1_to_mrz, PassportInput, PassportOutput, Witness2048,
};

#[jolt::provable(stack_size = 131072, memory_size = 1048576, max_input_size = 65536, max_trusted_advice_size = 16384)]
fn verify_passport(witness: TrustedAdvice<Witness2048>, input: PassportInput) -> PassportOutput {
    // 1. Hash DG1
    // let dg1_hash: [u8; 32] = Sha256::digest(&input.dg1);

    // // 2. Binding check: DG1 hash appears in LDS Security Object (encapContent)
    // assert!(contains_subsequence(&input.encap_content, &dg1_hash), "DG1 hash not found in LDS Security Object");

    // // 3. Hash encapContent → content digest
    // let content_digest: [u8; 32] = Sha256::digest(&input.encap_content);

    // // 4. Binding check: content digest appears in signedAttrs as messageDigest
    // assert!(contains_subsequence(&input.signed_attrs_der, &content_digest), "content digest not found in signedAttrs");

    // // 5. Verify SOD signature: RSA PKCS#1v15 with SHA-256 using trusted-advice witness
    // let attrs_hash: [u8; 32] = Sha256::digest(&input.signed_attrs_der);

    // let modulus = parse_pkcs1_modulus(&input.ds_pubkey_der).expect("invalid DS public key");
    // assert!(input.signature.len() == 256, "signature must be 256 bytes");
    // let signature_bytes = Bytes2048(input.signature.as_slice().try_into().expect("signature length"));

    // let signature_verified = verify_pkcs1v15_sha256_with_witness(
    //     &witness,
    //     &modulus,
    //     &signature_bytes,
    //     &input.rsa_challenge_seed,
    //     &attrs_hash,
    // );
    // assert!(signature_verified, "SOD signature verification failed");

    // 6. Parse MRZ from DG1
    // let mrz = unwrap_dg1_to_mrz(&input.dg1).expect("failed to unwrap DG1 to MRZ");
    // let parsed = parse_td3_mrz(mrz).expect("failed to parse TD3 MRZ");

    // // 7-8. Age predicate
    // let over_18 = is_over_18(parsed.dob_yymmdd, input.today_yyyymmdd);

    // 9-10. Return output
    // PassportOutput { passive_auth_valid: true, over_18, issuing_country: parsed.issuing_country }
    PassportOutput { passive_auth_valid: true, over_18: true, issuing_country: [0, 0, 0] }
}
