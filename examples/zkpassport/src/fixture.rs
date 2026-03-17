use jolt_inlines_sha2::Sha256;
/// Synthetic fixture generation for testing without real passport data.
///
/// Generates a self-consistent PassportInput with:
/// - A fake TD3 MRZ with a chosen DOB
/// - DG1 wrapped in proper TLV structure
/// - A minimal LDS Security Object containing hash(DG1)
/// - CMS signedAttrs containing hash(LDS SO)
/// - A real RSA PKCS#1v15 signature over hash(signedAttrs)
/// - The corresponding DS public key
use rand::CryptoRng;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use zkpassport_core::PassportInput;

/// OID for SHA-256: 2.16.840.1.101.3.4.2.1
const OID_SHA256: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// OID for id-data (CMS content type): 1.2.840.113549.1.7.1
const OID_ID_DATA: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];

/// OID for id-contentType (CMS attribute): 1.2.840.113549.1.9.3
const OID_CONTENT_TYPE: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];

/// OID for id-messageDigest (CMS attribute): 1.2.840.113549.1.9.4
const OID_MESSAGE_DIGEST: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];

/// Generate a synthetic PassportInput with the given DOB and today's date.
///
/// `dob_yymmdd`: 6 ASCII chars, e.g. b"000315" for 2000-03-15
/// `today_yyyymmdd`: e.g. 20260315
pub fn generate_fixture(dob_yymmdd: &[u8; 6], today_yyyymmdd: u32) -> PassportInput {
    generate_fixture_with_rng(dob_yymmdd, today_yyyymmdd, &mut ChaCha12Rng::seed_from_u64(42))
}

/// Generate a synthetic PassportInput using a caller-supplied RNG (for determinism in tests).
pub fn generate_fixture_with_rng(
    dob_yymmdd: &[u8; 6],
    today_yyyymmdd: u32,
    rng: &mut (impl CryptoRng + RngCore),
) -> PassportInput {
    // 1. Generate RSA key pair
    let private_key = RsaPrivateKey::new(rng, 2048).expect("RSA keygen");
    let public_key = private_key.to_public_key();

    // 2. Build TD3 MRZ (88 bytes)
    let mrz = build_td3_mrz(b"UTO", dob_yymmdd);

    // 3. Wrap in DG1 TLV: 0x61 || len || 0x5F1F || len || mrz
    let dg1 = build_dg1(&mrz);

    // 4. Hash DG1
    let dg1_hash: [u8; 32] = Sha256::digest(&dg1);

    // 5. Build LDS Security Object (encapContent)
    let encap_content = build_lds_security_object(&dg1_hash);

    // 6. Hash encapContent → messageDigest value
    let content_digest: [u8; 32] = Sha256::digest(&encap_content);

    // 7. Build signedAttrs (DER SET OF)
    let signed_attrs_der = build_signed_attrs(&content_digest);

    // 8. Sign signedAttrs with RSA PKCS#1v15-SHA256
    let signing_key = SigningKey::<sha2::Sha256>::new(private_key);
    let signature: Vec<u8> = signing_key.sign(&signed_attrs_der).to_vec();

    // 9. Serialize DS public key as PKCS#1 DER
    let ds_pubkey_der = public_key.to_pkcs1_der().expect("PKCS#1 encode").as_bytes().to_vec();

    PassportInput {
        dg1,
        encap_content,
        signed_attrs_der,
        signature,
        rsa_challenge_seed: [0u8; 32],
        ds_pubkey_der,
        today_yyyymmdd,
    }
}

/// Build a TD3 MRZ with the given issuing country and DOB.
/// Fills remaining fields with plausible filler.
fn build_td3_mrz(country: &[u8; 3], dob: &[u8; 6]) -> [u8; 88] {
    let mut mrz = [b'<'; 88];

    // Line 1: P<UTOERIKSSON<<ANNA<MARIA...
    mrz[0] = b'P';
    mrz[1] = b'<';
    mrz[2] = country[0];
    mrz[3] = country[1];
    mrz[4] = country[2];
    // Name: ERIKSSON<<ANNA<MARIA (fill from position 5)
    let name = b"ERIKSSON<<ANNA<MARIA";
    mrz[5..5 + name.len()].copy_from_slice(name);

    // Line 2: document number + check + nationality + DOB + check + sex + expiry + ...
    let line2 = &mut mrz[44..];
    // Doc number: L898902C3 + check digit 6
    line2[..10].copy_from_slice(b"L898902C36");
    // Nationality
    line2[10] = country[0];
    line2[11] = country[1];
    line2[12] = country[2];
    // DOB YYMMDD
    line2[13..19].copy_from_slice(dob);
    // DOB check digit (simplified: just use '0')
    line2[19] = b'0';
    // Sex
    line2[20] = b'F';
    // Expiry YYMMDD (far future)
    line2[21..27].copy_from_slice(b"301231");
    // Expiry check
    line2[27] = b'0';

    mrz
}

fn build_dg1(mrz: &[u8; 88]) -> Vec<u8> {
    // Inner: 0x5F1F || length(88) || mrz
    let mut inner = Vec::with_capacity(91);
    inner.push(0x5F);
    inner.push(0x1F);
    inner.push(88); // length
    inner.extend_from_slice(mrz);

    // Outer: 0x61 || length || inner
    let mut dg1 = Vec::with_capacity(93);
    dg1.push(0x61);
    der_push_length(&mut dg1, inner.len());
    dg1.extend_from_slice(&inner);
    dg1
}

/// Build a minimal LDS Security Object (ICAO 9303 Part 10).
///
/// LDSSecurityObject ::= SEQUENCE {
///   version          INTEGER (0),
///   hashAlgorithm    AlgorithmIdentifier (SHA-256),
///   dataGroupHashValues SEQUENCE OF DataGroupHash
/// }
/// DataGroupHash ::= SEQUENCE {
///   dataGroupNumber  INTEGER,
///   dataGroupHashValue OCTET STRING
/// }
fn build_lds_security_object(dg1_hash: &[u8; 32]) -> Vec<u8> {
    // DataGroupHash for DG1
    let dg_num = der_integer(1);
    let dg_hash_val = der_octet_string(dg1_hash);
    let dg_hash_seq = der_sequence(&[&dg_num, &dg_hash_val]);

    // dataGroupHashValues (SEQUENCE OF — just one entry)
    let dg_hashes = der_sequence(&[&dg_hash_seq]);

    // hashAlgorithm: AlgorithmIdentifier = SEQUENCE { OID, NULL }
    let null = [0x05, 0x00];
    let hash_alg = der_sequence(&[OID_SHA256, &null]);

    // version
    let version = der_integer(0);

    // Top-level SEQUENCE
    der_sequence(&[&version, &hash_alg, &dg_hashes])
}

/// Build CMS signedAttrs (DER-encoded SET OF).
///
/// signedAttrs contains:
///   contentType attribute (OID id-data)
///   messageDigest attribute (hash of encapContent)
///
/// Per CMS spec, for signature computation the IMPLICIT [0] tag
/// is replaced with EXPLICIT SET OF (0x31).
fn build_signed_attrs(content_digest: &[u8; 32]) -> Vec<u8> {
    // contentType attribute: SEQUENCE { OID, SET { OID id-data } }
    let ct_value_set = der_set(&[OID_ID_DATA]);
    let ct_attr = der_sequence(&[OID_CONTENT_TYPE, &ct_value_set]);

    // messageDigest attribute: SEQUENCE { OID, SET { OCTET STRING digest } }
    let md_octet = der_octet_string(content_digest);
    let md_value_set = der_set(&[&md_octet]);
    let md_attr = der_sequence(&[OID_MESSAGE_DIGEST, &md_value_set]);

    // SET OF { contentType, messageDigest }
    der_set(&[&ct_attr, &md_attr])
}

// ---------------------------------------------------------------------------
// DER encoding helpers
// ---------------------------------------------------------------------------

fn der_push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xFF {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    der_constructed(0x30, items)
}

fn der_set(items: &[&[u8]]) -> Vec<u8> {
    der_constructed(0x31, items)
}

fn der_constructed(tag: u8, items: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = items.iter().map(|i| i.len()).sum();
    let mut buf = Vec::with_capacity(4 + total_len);
    buf.push(tag);
    der_push_length(&mut buf, total_len);
    for item in items {
        buf.extend_from_slice(item);
    }
    buf
}

fn der_integer(val: u8) -> Vec<u8> {
    vec![0x02, 0x01, val]
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.push(0x04);
    der_push_length(&mut buf, data.len());
    buf.extend_from_slice(data);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;
    use zkpassport_core::{contains_subsequence, is_over_18, parse_td3_mrz, unwrap_dg1_to_mrz};

    #[test]
    fn test_fixture_round_trip() {
        let input = generate_fixture(b"000315", 20260315);

        // DG1 unwraps to valid MRZ
        let mrz = unwrap_dg1_to_mrz(&input.dg1).expect("unwrap DG1");
        let parsed = parse_td3_mrz(mrz).expect("parse MRZ");
        assert_eq!(&parsed.issuing_country, b"UTO");
        assert_eq!(&parsed.dob_yymmdd, b"000315");
        assert!(is_over_18(parsed.dob_yymmdd, 20260315));

        // DG1 hash is in encap_content
        let dg1_hash: [u8; 32] = Sha256::digest(&input.dg1);
        assert!(contains_subsequence(&input.encap_content, &dg1_hash));

        // encap_content hash is in signed_attrs
        let content_digest: [u8; 32] = Sha256::digest(&input.encap_content);
        assert!(contains_subsequence(&input.signed_attrs_der, &content_digest));

        // RSA signature verifies
        let pubkey = RsaPublicKey::from_pkcs1_der(&input.ds_pubkey_der).expect("decode pubkey");
        let verifying_key = VerifyingKey::<sha2::Sha256>::new(pubkey);
        let sig = rsa::pkcs1v15::Signature::try_from(input.signature.as_slice()).expect("sig");
        verifying_key.verify(&input.signed_attrs_der, &sig).expect("RSA signature must verify");
    }
}
