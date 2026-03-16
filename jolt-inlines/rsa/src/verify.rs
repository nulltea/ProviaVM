//! RSA PKCS#1 v1.5 SHA-256 signature verification.

use crate::modpow::modpow_65537;
use crate::witness::{
    accumulate_residue_error, advance_seeded_weight_state, limbs_lt, sampled_step_checks, seeded_weight_state_init,
    seeded_weights, Bytes2048, Residues2048, StepOp, Witness2048,
};
use crate::{Limb, LIMBS_2048, LIMB_BYTES};

const SHA256_DIGEST_INFO: [u8; 19] =
    [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

/// Verify an RSA PKCS#1 v1.5 signature with SHA-256.
///
/// - `n`: RSA modulus as limbs (2048-bit, little-endian)
/// - `signature`: 2048-bit signature as bytes (big-endian, 256 bytes)
/// - `message_hash`: SHA-256 hash of the message (32 bytes)
///
/// Returns `true` if the signature is valid.
pub fn rsa_verify_pkcs1v15_sha256(n: &[Limb; LIMBS_2048], signature: &[u8; 256], message_hash: &[u8; 32]) -> bool {
    let sig_limbs = bytes_be_to_limbs_2048(signature);

    let result = modpow_65537(&sig_limbs, n);

    let result_bytes = limbs_to_bytes_be_2048(&result);
    verify_pkcs1v15_sha256_encoded(&result_bytes, message_hash)
}

pub fn verify_pkcs1v15_sha256_with_witness(
    witness: &Witness2048,
    modulus: &[Limb; LIMBS_2048],
    signature: &Bytes2048,
    challenge_seed: &[u8; 32],
    message_hash: &[u8; 32],
) -> bool {
    let modulus_bytes = Bytes2048::from(limbs_to_bytes_be_2048(modulus));
    if witness.modulus != modulus_bytes || witness.signature != *signature {
        return false;
    }

    let modulus_residues = Residues2048::from_bytes(&witness.modulus);
    let signature_residues = Residues2048::from_bytes(&witness.signature);
    let mut current_residues = signature_residues;
    let mut aggregated_error = [0u32; 4];
    let mut seeded_weight_state = seeded_weight_state_init(challenge_seed);
    let sampled_step_checks = sampled_step_checks(challenge_seed);
    let modulus_limbs = bytes_be_to_limbs_2048(modulus_bytes.as_array());

    for (step_idx, step) in witness.steps.iter().enumerate() {
        let expected_op = if step_idx < 16 { StepOp::Square } else { StepOp::MulBase };
        if step.op != expected_op || !limbs_lt(&step.remainder_limbs.0, &modulus_limbs) {
            return false;
        }

        let rhs_residues = if step_idx < 16 { current_residues } else { signature_residues };
        let remainder_residues = Residues2048(step.remainder_residues);
        if sampled_step_checks[step_idx]
            && Residues2048::from_limbs(&step.remainder_limbs.0).0 != step.remainder_residues
        {
            return false;
        }

        accumulate_residue_error(
            &mut aggregated_error,
            &seeded_weights(&seeded_weight_state),
            &current_residues,
            &rhs_residues,
            &Residues2048(step.quotient_residues),
            &modulus_residues,
            &remainder_residues,
        );
        advance_seeded_weight_state(&mut seeded_weight_state, step_idx);

        current_residues = remainder_residues;
    }

    aggregated_error.iter().all(|&value| value == 0)
        && verify_pkcs1v15_sha256_encoded_limbs(&witness.steps[16].remainder_limbs.0, message_hash)
}

pub fn verify_pkcs1v15_sha256_encoded(result_bytes: &[u8; 256], message_hash: &[u8; 32]) -> bool {
    // Check PKCS#1 v1.5 padding:
    // Expected format: 0x00 0x01 [0xFF padding] 0x00 [DigestInfo] [hash]
    // DigestInfo for SHA-256 (DER encoded):
    // 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
    // result_bytes[0] must be 0x00
    if result_bytes[0] != 0x00 {
        return false;
    }
    // result_bytes[1] must be 0x01
    if result_bytes[1] != 0x01 {
        return false;
    }

    // Find the 0x00 separator after the 0xFF padding
    let hash_with_info_len = 32 + SHA256_DIGEST_INFO.len(); // 51 bytes
    let separator_idx = 256 - hash_with_info_len - 1; // index of 0x00 separator

    // All bytes from index 2 to separator_idx-1 must be 0xFF
    for i in 2..separator_idx {
        if result_bytes[i] != 0xFF {
            return false;
        }
    }

    // Separator must be 0x00
    if result_bytes[separator_idx] != 0x00 {
        return false;
    }

    // Check DigestInfo
    let di_start = separator_idx + 1;
    if result_bytes[di_start..di_start + 19] != SHA256_DIGEST_INFO {
        return false;
    }

    // Check hash
    let hash_start = di_start + 19;
    result_bytes[hash_start..hash_start + 32] == *message_hash
}

#[inline(always)]
fn encoded_byte_at(encoded: &[Limb; LIMBS_2048], byte_idx_be: usize) -> u8 {
    let byte_idx_le = 255 - byte_idx_be;
    let limb_idx = byte_idx_le / LIMB_BYTES;
    let byte_in_limb = byte_idx_le % LIMB_BYTES;
    ((encoded[limb_idx] >> (8 * byte_in_limb)) & 0xff) as u8
}

fn verify_pkcs1v15_sha256_encoded_limbs(encoded: &[Limb; LIMBS_2048], message_hash: &[u8; 32]) -> bool {
    if encoded_byte_at(encoded, 0) != 0x00 {
        return false;
    }
    if encoded_byte_at(encoded, 1) != 0x01 {
        return false;
    }

    let hash_with_info_len = 32 + SHA256_DIGEST_INFO.len();
    let separator_idx = 256 - hash_with_info_len - 1;

    let mut i = 2usize;
    while i < separator_idx {
        if encoded_byte_at(encoded, i) != 0xff {
            return false;
        }
        i += 1;
    }

    if encoded_byte_at(encoded, separator_idx) != 0x00 {
        return false;
    }

    let di_start = separator_idx + 1;
    let mut j = 0usize;
    while j < SHA256_DIGEST_INFO.len() {
        if encoded_byte_at(encoded, di_start + j) != SHA256_DIGEST_INFO[j] {
            return false;
        }
        j += 1;
    }

    let hash_start = di_start + SHA256_DIGEST_INFO.len();
    let mut k = 0usize;
    while k < 32 {
        if encoded_byte_at(encoded, hash_start + k) != message_hash[k] {
            return false;
        }
        k += 1;
    }

    true
}

/// Convert big-endian bytes to little-endian limbs.
pub fn bytes_be_to_limbs_2048(bytes: &[u8; 256]) -> [Limb; LIMBS_2048] {
    let mut limbs = [0 as Limb; LIMBS_2048];
    for i in 0..LIMBS_2048 {
        let mut buf = [0u8; LIMB_BYTES];
        for j in 0..LIMB_BYTES {
            // bytes is big-endian: bytes[0] is MSB
            // limbs[0] is LSB limb, within each limb byte[0] is LSB
            buf[j] = bytes[255 - i * LIMB_BYTES - j];
        }
        #[cfg(feature = "rv64")]
        {
            limbs[i] = u64::from_le_bytes(buf);
        }
        #[cfg(not(feature = "rv64"))]
        {
            limbs[i] = u32::from_le_bytes(buf);
        }
    }
    limbs
}

/// Convert little-endian limbs to big-endian bytes.
pub fn limbs_to_bytes_be_2048(limbs: &[Limb; LIMBS_2048]) -> [u8; 256] {
    let mut bytes = [0u8; 256];
    for i in 0..LIMBS_2048 {
        let le = limbs[i].to_le_bytes();
        for j in 0..LIMB_BYTES {
            bytes[255 - i * LIMB_BYTES - j] = le[j];
        }
    }
    bytes
}

/// Decode a little-endian serialized Montgomery inverse.
pub fn n0inv_from_le_bytes(bytes: &[u8; 8]) -> Limb {
    #[cfg(feature = "rv64")]
    {
        u64::from_le_bytes(*bytes)
    }
    #[cfg(not(feature = "rv64"))]
    {
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }
}

/// Parse a PKCS#1 DER-encoded RSA public key and extract the modulus as limbs.
///
/// PKCS#1 format: SEQUENCE { INTEGER(n), INTEGER(e) }
/// Returns `None` if parsing fails or the modulus is not 2048-bit.
pub fn parse_pkcs1_modulus(der: &[u8]) -> Option<[Limb; LIMBS_2048]> {
    let mut pos = 0;

    // SEQUENCE tag
    if der.get(pos).copied()? != 0x30 {
        return None;
    }
    pos += 1;
    let (_seq_len, consumed) = parse_der_length(&der[pos..])?;
    pos += consumed;

    // First INTEGER: modulus n
    if der.get(pos).copied()? != 0x02 {
        return None;
    }
    pos += 1;
    let (n_len, consumed) = parse_der_length(&der[pos..])?;
    pos += consumed;

    let n_bytes = der.get(pos..pos + n_len)?;
    pos += n_len;

    // Skip leading zero byte if present (sign padding)
    let n_bytes = if !n_bytes.is_empty() && n_bytes[0] == 0x00 { &n_bytes[1..] } else { n_bytes };

    // Must be exactly 256 bytes (2048 bits)
    if n_bytes.len() != 256 {
        return None;
    }

    // Second INTEGER: exponent e (verify it's 65537)
    if der.get(pos).copied()? != 0x02 {
        return None;
    }
    pos += 1;
    let (e_len, consumed) = parse_der_length(&der[pos..])?;
    pos += consumed;

    let e_bytes = der.get(pos..pos + e_len)?;

    // Parse exponent and verify it's 65537
    let mut e: u32 = 0;
    for &b in e_bytes {
        e = e.checked_shl(8)?.checked_add(b as u32)?;
    }
    if e != 65537 {
        return None;
    }

    // Convert big-endian modulus bytes to little-endian limbs
    let n_be: &[u8; 256] = n_bytes.try_into().ok()?;
    Some(bytes_be_to_limbs_2048(n_be))
}

/// Parse a DER length field. Returns (length, bytes_consumed).
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first < 0x80 {
        Some((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = len.checked_shl(8)?.checked_add(*data.get(1 + i)? as usize)?;
        }
        Some((len, 1 + num_bytes))
    }
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::*;
    use rand::Rng;

    fn valid_encoded_message(message_hash: &[u8; 32]) -> [u8; 256] {
        let mut encoded = [0xffu8; 256];
        encoded[0] = 0x00;
        encoded[1] = 0x01;
        let separator_idx = 256 - (32 + SHA256_DIGEST_INFO.len()) - 1;
        encoded[separator_idx] = 0x00;
        let di_start = separator_idx + 1;
        encoded[di_start..di_start + SHA256_DIGEST_INFO.len()].copy_from_slice(&SHA256_DIGEST_INFO);
        let hash_start = di_start + SHA256_DIGEST_INFO.len();
        encoded[hash_start..hash_start + 32].copy_from_slice(message_hash);
        encoded
    }

    #[test]
    fn test_parse_pkcs1_modulus() {
        // Build a minimal PKCS#1 DER for a 2048-bit key with e=65537
        // SEQUENCE { INTEGER(n with leading 0x00), INTEGER(65537) }
        let mut n_bytes = [0xABu8; 256];
        n_bytes[0] = 0x80; // high bit set, so DER will have leading 0x00

        // INTEGER for n: tag(1) + length(3: 82 01 01) + leading_zero(1) + data(256) = 261 bytes
        // INTEGER for e: tag(1) + length(1: 03) + data(3: 01 00 01) = 5 bytes
        // SEQUENCE length = 261 + 5 = 266

        let mut der = Vec::new();
        // SEQUENCE
        der.push(0x30);
        // SEQUENCE length: 266 = 0x010A
        der.push(0x82);
        der.push(0x01);
        der.push(0x0A);
        // INTEGER n
        der.push(0x02);
        // n length: 257 (256 + 1 leading zero) = 0x0101
        der.push(0x82);
        der.push(0x01);
        der.push(0x01);
        der.push(0x00); // leading zero (sign padding)
        der.extend_from_slice(&n_bytes);
        // INTEGER e = 65537 = 0x010001
        der.push(0x02);
        der.push(0x03);
        der.push(0x01);
        der.push(0x00);
        der.push(0x01);

        let result = parse_pkcs1_modulus(&der);
        assert!(result.is_some(), "should parse valid PKCS#1 DER");

        let limbs = result.unwrap();
        // Convert back to bytes and verify
        let mut reconstructed = [0u8; 256];
        for i in 0..LIMBS_2048 {
            let le = limbs[i].to_le_bytes();
            for j in 0..LIMB_BYTES {
                reconstructed[255 - i * LIMB_BYTES - j] = le[j];
            }
        }
        assert_eq!(reconstructed, n_bytes);
    }

    #[test]
    fn test_parse_pkcs1_rejects_wrong_exponent() {
        let n_bytes = [0xABu8; 256];
        let mut der = Vec::new();
        der.push(0x30);
        der.push(0x82);
        der.push(0x01);
        der.push(0x0A);
        der.push(0x02);
        der.push(0x82);
        der.push(0x01);
        der.push(0x01);
        der.push(0x00);
        der.extend_from_slice(&n_bytes);
        // Wrong exponent: 3 instead of 65537
        der.push(0x02);
        der.push(0x01);
        der.push(0x03);

        assert!(parse_pkcs1_modulus(&der).is_none(), "should reject e != 65537");
    }

    #[test]
    fn test_bytes_be_limbs_roundtrip() {
        let mut bytes = [0u8; 256];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let limbs = bytes_be_to_limbs_2048(&bytes);
        let back = limbs_to_bytes_be_2048(&limbs);
        assert_eq!(bytes, back);
    }

    #[test]
    fn test_verify_pkcs1v15_sha256_encoded_limbs_matches_valid_block() {
        let message_hash = [0x42u8; 32];
        let encoded = valid_encoded_message(&message_hash);
        let encoded_limbs = bytes_be_to_limbs_2048(&encoded);

        assert!(verify_pkcs1v15_sha256_encoded(&encoded, &message_hash));
        assert!(verify_pkcs1v15_sha256_encoded_limbs(&encoded_limbs, &message_hash));
    }

    #[test]
    fn test_verify_pkcs1v15_sha256_encoded_limbs_rejects_wrong_head_byte() {
        let message_hash = [0x11u8; 32];
        let mut encoded = valid_encoded_message(&message_hash);
        encoded[0] ^= 1;
        let encoded_limbs = bytes_be_to_limbs_2048(&encoded);

        assert!(!verify_pkcs1v15_sha256_encoded(&encoded, &message_hash));
        assert!(!verify_pkcs1v15_sha256_encoded_limbs(&encoded_limbs, &message_hash));
    }

    #[test]
    fn test_verify_pkcs1v15_sha256_encoded_limbs_rejects_wrong_second_byte() {
        let message_hash = [0x12u8; 32];
        let mut encoded = valid_encoded_message(&message_hash);
        encoded[1] ^= 1;
        let encoded_limbs = bytes_be_to_limbs_2048(&encoded);

        assert!(!verify_pkcs1v15_sha256_encoded(&encoded, &message_hash));
        assert!(!verify_pkcs1v15_sha256_encoded_limbs(&encoded_limbs, &message_hash));
    }

    #[test]
    fn test_verify_pkcs1v15_sha256_encoded_limbs_rejects_wrong_padding_byte() {
        let message_hash = [0x13u8; 32];
        let mut encoded = valid_encoded_message(&message_hash);
        encoded[17] = 0x7f;
        let encoded_limbs = bytes_be_to_limbs_2048(&encoded);

        assert!(!verify_pkcs1v15_sha256_encoded(&encoded, &message_hash));
        assert!(!verify_pkcs1v15_sha256_encoded_limbs(&encoded_limbs, &message_hash));
    }

    #[test]
    fn test_verify_pkcs1v15_sha256_encoded_limbs_rejects_wrong_separator() {
        let message_hash = [0x14u8; 32];
        let mut encoded = valid_encoded_message(&message_hash);
        let separator_idx = 256 - (32 + SHA256_DIGEST_INFO.len()) - 1;
        encoded[separator_idx] = 0x01;
        let encoded_limbs = bytes_be_to_limbs_2048(&encoded);

        assert!(!verify_pkcs1v15_sha256_encoded(&encoded, &message_hash));
        assert!(!verify_pkcs1v15_sha256_encoded_limbs(&encoded_limbs, &message_hash));
    }

    #[test]
    fn test_verify_pkcs1v15_sha256_encoded_limbs_rejects_wrong_digest_info() {
        let message_hash = [0x15u8; 32];
        let mut encoded = valid_encoded_message(&message_hash);
        let di_start = (256 - (32 + SHA256_DIGEST_INFO.len()) - 1) + 1;
        encoded[di_start + 3] ^= 1;
        let encoded_limbs = bytes_be_to_limbs_2048(&encoded);

        assert!(!verify_pkcs1v15_sha256_encoded(&encoded, &message_hash));
        assert!(!verify_pkcs1v15_sha256_encoded_limbs(&encoded_limbs, &message_hash));
    }

    #[test]
    fn test_verify_pkcs1v15_sha256_encoded_limbs_rejects_wrong_hash_byte() {
        let message_hash = [0x16u8; 32];
        let mut encoded = valid_encoded_message(&message_hash);
        encoded[255] ^= 1;
        let encoded_limbs = bytes_be_to_limbs_2048(&encoded);

        assert!(!verify_pkcs1v15_sha256_encoded(&encoded, &message_hash));
        assert!(!verify_pkcs1v15_sha256_encoded_limbs(&encoded_limbs, &message_hash));
    }

    #[test]
    fn test_verify_pkcs1v15_sha256_encoded_limbs_matches_byte_path_for_random_limbs() {
        let mut rng = rand::thread_rng();
        for _ in 0..512 {
            let mut limbs = [0 as Limb; LIMBS_2048];
            for limb in &mut limbs {
                *limb = rng.gen::<Limb>();
            }
            let message_hash: [u8; 32] = rng.gen();
            let bytes = limbs_to_bytes_be_2048(&limbs);
            assert_eq!(
                verify_pkcs1v15_sha256_encoded_limbs(&limbs, &message_hash),
                verify_pkcs1v15_sha256_encoded(&bytes, &message_hash),
            );
        }
    }

    #[test]
    fn test_rsa_verify_e2e() {
        use rsa::pkcs1::EncodeRsaPublicKey;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Signer;
        use sha2::Sha256;

        // Generate a 2048-bit RSA key pair
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);

        // Sign a message
        let message = b"Hello, DKIM verification test!";
        let mut hasher = <Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, message);
        let hash: [u8; 32] = sha2::Digest::finalize(hasher).into();

        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign(message);
        let sig_bytes: alloc::vec::Vec<u8> = rsa::signature::SignatureEncoding::to_vec(&signature);
        assert_eq!(sig_bytes.len(), 256);

        let mut sig_arr = [0u8; 256];
        sig_arr.copy_from_slice(&sig_bytes);

        // Parse modulus from DER
        let der = public_key.to_pkcs1_der().unwrap();
        let n_limbs = parse_pkcs1_modulus(der.as_bytes()).expect("failed to parse DER");

        // Verify with our implementation
        let result = rsa_verify_pkcs1v15_sha256(&n_limbs, &sig_arr, &hash);
        assert!(result, "RSA signature should verify");

        // Verify with wrong hash fails
        let mut bad_hash = hash;
        bad_hash[0] ^= 0xFF;
        let bad_result = rsa_verify_pkcs1v15_sha256(&n_limbs, &sig_arr, &bad_hash);
        assert!(!bad_result, "RSA signature should NOT verify with wrong hash");
    }
}
