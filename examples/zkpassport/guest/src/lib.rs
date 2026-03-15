#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use zkpassport_core::{
    contains_subsequence, is_over_18, parse_td3_mrz, unwrap_dg1_to_mrz, PassportInput, PassportOutput,
};

#[jolt::provable(stack_size = 131072, memory_size = 1048576, max_input_size = 65536)]
fn verify_passport(input: PassportInput) -> PassportOutput {
    // 1. Hash DG1
    let dg1_hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(&input.dg1);
        h.finalize().into()
    };

    // 2. Binding check: DG1 hash appears in LDS Security Object (encapContent)
    assert!(contains_subsequence(&input.encap_content, &dg1_hash), "DG1 hash not found in LDS Security Object");

    // 3. Hash encapContent → content digest
    let content_digest: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(&input.encap_content);
        h.finalize().into()
    };

    // 4. Binding check: content digest appears in signedAttrs as messageDigest
    assert!(contains_subsequence(&input.signed_attrs_der, &content_digest), "content digest not found in signedAttrs");

    // 5. Verify SOD signature: RSA PKCS#1v15 over SHA-256(signedAttrs)
    let attrs_hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(&input.signed_attrs_der);
        h.finalize().into()
    };

    let ds_pubkey = RsaPublicKey::from_pkcs1_der(&input.ds_pubkey_der).expect("invalid DS public key");
    let scheme = Pkcs1v15Sign::new::<Sha256>();
    ds_pubkey.verify(scheme, &attrs_hash, &input.signature).expect("SOD signature verification failed");

    // 6. Parse MRZ from DG1
    let mrz = unwrap_dg1_to_mrz(&input.dg1).expect("failed to unwrap DG1 to MRZ");
    let parsed = parse_td3_mrz(mrz).expect("failed to parse TD3 MRZ");

    // 7-8. Age predicate
    let over_18 = is_over_18(parsed.dob_yymmdd, input.today_yyyymmdd);

    // 9-10. Return output
    PassportOutput { passive_auth_valid: true, over_18, issuing_country: parsed.issuing_country }
}
