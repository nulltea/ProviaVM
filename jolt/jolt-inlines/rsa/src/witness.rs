use alloc::vec::Vec;
use core::fmt;

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Digest;

use crate::verify::{bytes_be_to_limbs_2048, limbs_to_bytes_be_2048};
use crate::{Limb, LIMBS_2048};

const RSA_CHECK_PRIMES: [(u32, u32); 4] = [
    (4_294_967_291, 5),
    (4_294_967_279, 17),
    (4_294_967_231, 65),
    (4_294_967_197, 99),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Bytes2048(pub [u8; 256]);

impl Bytes2048 {
    pub fn as_array(&self) -> &[u8; 256] {
        &self.0
    }
}

impl From<[u8; 256]> for Bytes2048 {
    fn from(value: [u8; 256]) -> Self {
        Self(value)
    }
}

impl Default for Bytes2048 {
    fn default() -> Self {
        Self([0u8; 256])
    }
}

impl Serialize for Bytes2048 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes2048 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Bytes2048Visitor;

        impl<'de> Visitor<'de> for Bytes2048Visitor {
            type Value = Bytes2048;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly 256 bytes")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                if value.len() != 256 {
                    return Err(E::invalid_length(value.len(), &self));
                }
                let mut out = [0u8; 256];
                out.copy_from_slice(value);
                Ok(Bytes2048(out))
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                self.visit_bytes(&value)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut out = [0u8; 256];
                let mut idx = 0usize;
                while idx < 256 {
                    out[idx] = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| A::Error::invalid_length(idx, &self))?;
                    idx += 1;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(A::Error::invalid_length(257, &self));
                }
                Ok(Bytes2048(out))
            }
        }

        deserializer.deserialize_bytes(Bytes2048Visitor)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Limbs2048(pub [Limb; LIMBS_2048]);

impl Default for Limbs2048 {
    fn default() -> Self {
        Self([0 as Limb; LIMBS_2048])
    }
}

impl Serialize for Limbs2048 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = [0u8; 256];
        encode_limbs_le(&self.0, &mut bytes);
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for Limbs2048 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Limbs2048Visitor;

        impl<'de> Visitor<'de> for Limbs2048Visitor {
            type Value = Limbs2048;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exactly 256 little-endian limb bytes")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                if value.len() != 256 {
                    return Err(E::invalid_length(value.len(), &self));
                }
                let mut out = [0u8; 256];
                out.copy_from_slice(value);
                Ok(Limbs2048(decode_limbs_le(&out)))
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                self.visit_bytes(&value)
            }
        }

        deserializer.deserialize_bytes(Limbs2048Visitor)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step2048 {
    pub quotient_residues: [u32; 4],
    pub remainder_residues: [u32; 4],
    pub remainder_limbs: Limbs2048,
}

impl Default for Step2048 {
    fn default() -> Self {
        Self {
            quotient_residues: [0u32; 4],
            remainder_residues: [0u32; 4],
            remainder_limbs: Limbs2048::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witness2048 {
    pub steps: [Step2048; 17],
}

#[cfg(feature = "host")]
pub fn witness_seed_from_commitment_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut seed_input = b"rsa-witness-challenge-v1".to_vec();
    seed_input.extend_from_slice(bytes);
    sha2::Sha256::digest(&seed_input).into()
}

#[cfg(feature = "host")]
pub fn witness_seed_from_commitment<C>(
    commitment: &C,
) -> Result<[u8; 32], ark_serialize::SerializationError>
where
    C: ark_serialize::CanonicalSerialize,
{
    let mut bytes = Vec::new();
    commitment.serialize_compressed(&mut bytes)?;
    Ok(witness_seed_from_commitment_bytes(&bytes))
}

#[cfg(feature = "host")]
pub fn build_witness_2048(
    modulus: &[Limb; LIMBS_2048],
    signature: &Bytes2048,
) -> Witness2048 {
    use num_bigint::BigUint;

    let modulus_bytes = Bytes2048::from(limbs_to_bytes_be_2048(modulus));
    let modulus_bn = BigUint::from_bytes_be(&modulus_bytes.0);
    let signature_bn = BigUint::from_bytes_be(&signature.0);
    let mut steps = [Step2048::default(); 17];
    let mut current = signature_bn.clone();

    for (step_idx, step) in steps.iter_mut().enumerate() {
        let (lhs, rhs) = if step_idx < 16 { (&current, &current) } else { (&current, &signature_bn) };
        let product = lhs * rhs;
        let quotient = &product / &modulus_bn;
        let remainder = &product % &modulus_bn;
        let remainder_limbs = Limbs2048(biguint_to_limbs_2048(&remainder));
        *step = Step2048 {
            quotient_residues: Residues2048::from_bytes(&biguint_to_bytes2048(&quotient)).0,
            remainder_residues: Residues2048::from_limbs(&remainder_limbs.0).0,
            remainder_limbs,
        };
        current = remainder;
    }

    Witness2048 { steps }
}

#[cfg(feature = "host")]
pub fn validate_witness_2048(
    modulus: &[Limb; LIMBS_2048],
    signature: &Bytes2048,
    witness: &Witness2048,
) -> bool {
    use num_bigint::BigUint;

    let modulus_bytes = Bytes2048::from(limbs_to_bytes_be_2048(modulus));
    let modulus_bn = BigUint::from_bytes_be(&modulus_bytes.0);
    let signature_bn = BigUint::from_bytes_be(&signature.0);
    let mut current = signature_bn.clone();

    for (step_idx, step) in witness.steps.iter().enumerate() {
        let rhs = if step_idx < 16 { &current } else { &signature_bn };
        let quotient_bn = (&current * rhs) / &modulus_bn;
        let quotient = biguint_to_bytes2048(&quotient_bn);
        let remainder = BigUint::from_bytes_be(&limbs_to_bytes_be_2048(&step.remainder_limbs.0));
        if Residues2048::from_bytes(&quotient).0 != step.quotient_residues
            || Residues2048::from_limbs(&step.remainder_limbs.0).0 != step.remainder_residues
            || remainder >= modulus_bn.clone()
        {
            return false;
        }
        if &current * rhs != quotient_bn * &modulus_bn + &remainder {
            return false;
        }
        current = remainder;
    }

    true
}

#[derive(Clone, Copy)]
pub(crate) struct Residues2048(pub(crate) [u32; 4]);

impl Residues2048 {
    pub(crate) fn from_bytes(bytes: &Bytes2048) -> Self {
        Self::from_limbs(&bytes_be_to_limbs_2048(bytes.as_array()))
    }

    pub(crate) fn from_limbs(limbs: &[Limb; LIMBS_2048]) -> Self {
        Self(residues_from_limbs(limbs))
    }
}

#[inline(always)]
fn residues_from_limbs(limbs: &[Limb; LIMBS_2048]) -> [u32; 4] {
    let (prime0, complement0) = RSA_CHECK_PRIMES[0];
    let (prime1, complement1) = RSA_CHECK_PRIMES[1];
    let (prime2, complement2) = RSA_CHECK_PRIMES[2];
    let (prime3, complement3) = RSA_CHECK_PRIMES[3];

    let mut acc0 = 0u32;
    let mut acc1 = 0u32;
    let mut acc2 = 0u32;
    let mut acc3 = 0u32;

    #[cfg(feature = "rv64")]
    {
        let mut idx = LIMBS_2048;
        while idx > 0 {
            idx -= 1;
            let limb = limbs[idx];
            let hi = (limb >> 32) as u32;
            let lo = limb as u32;

            acc0 = fold_residue_digit(acc0, hi, prime0, complement0);
            acc1 = fold_residue_digit(acc1, hi, prime1, complement1);
            acc2 = fold_residue_digit(acc2, hi, prime2, complement2);
            acc3 = fold_residue_digit(acc3, hi, prime3, complement3);

            acc0 = fold_residue_digit(acc0, lo, prime0, complement0);
            acc1 = fold_residue_digit(acc1, lo, prime1, complement1);
            acc2 = fold_residue_digit(acc2, lo, prime2, complement2);
            acc3 = fold_residue_digit(acc3, lo, prime3, complement3);
        }
    }

    #[cfg(not(feature = "rv64"))]
    {
        let mut idx = LIMBS_2048;
        while idx > 0 {
            idx -= 1;
            let limb = limbs[idx];
            acc0 = fold_residue_digit(acc0, limb, prime0, complement0);
            acc1 = fold_residue_digit(acc1, limb, prime1, complement1);
            acc2 = fold_residue_digit(acc2, limb, prime2, complement2);
            acc3 = fold_residue_digit(acc3, limb, prime3, complement3);
        }
    }

    [acc0, acc1, acc2, acc3]
}

pub(crate) fn accumulate_residue_error(
    aggregated_error: &mut [u32; 4],
    weights: &[u32; 4],
    lhs: &Residues2048,
    rhs: &Residues2048,
    quotient: &Residues2048,
    modulus: &Residues2048,
    remainder: &Residues2048,
) {
    let mut i = 0usize;
    while i < RSA_CHECK_PRIMES.len() {
        let (prime, complement) = RSA_CHECK_PRIMES[i];
        let left = reduce_near_u32_prime((lhs.0[i] as u64) * (rhs.0[i] as u64), prime, complement);
        let right_mul =
            reduce_near_u32_prime((quotient.0[i] as u64) * (modulus.0[i] as u64), prime, complement);
        let right = reduce_near_u32_prime((right_mul as u64) + (remainder.0[i] as u64), prime, complement);
        let error = add_mod(left, neg_mod(right, prime), prime, complement);
        let weighted_error = reduce_near_u32_prime((weights[i] as u64) * (error as u64), prime, complement);
        aggregated_error[i] = add_mod(aggregated_error[i], weighted_error, prime, complement);
        i += 1;
    }
}

fn limbs_mod_prime(limbs: &[Limb; LIMBS_2048], prime: u32, complement: u32) -> u32 {
    #[cfg(feature = "rv64")]
    {
        let mut acc = 0u32;
        let mut idx = LIMBS_2048;
        while idx > 0 {
            idx -= 1;
            let limb = limbs[idx];
            let hi = (limb >> 32) as u32;
            let lo = limb as u32;
            acc = reduce_near_u32_prime((acc as u64) * (complement as u64) + (hi as u64), prime, complement);
            acc = reduce_near_u32_prime((acc as u64) * (complement as u64) + (lo as u64), prime, complement);
        }
        acc
    }
    #[cfg(not(feature = "rv64"))]
    {
        let mut acc = 0u32;
        let mut idx = LIMBS_2048;
        while idx > 0 {
            idx -= 1;
            let limb = limbs[idx];
            acc = reduce_near_u32_prime((acc as u64) * (complement as u64) + (limb as u64), prime, complement);
        }
        acc
    }
}

#[inline(always)]
fn fold_residue_digit(acc: u32, digit: u32, prime: u32, complement: u32) -> u32 {
    reduce_near_u32_prime((acc as u64) * (complement as u64) + (digit as u64), prime, complement)
}

pub(crate) fn limbs_lt(lhs: &[Limb; LIMBS_2048], rhs: &[Limb; LIMBS_2048]) -> bool {
    let mut idx = LIMBS_2048;
    while idx > 0 {
        idx -= 1;
        if lhs[idx] != rhs[idx] {
            return lhs[idx] < rhs[idx];
        }
    }
    false
}

fn encode_limbs_le(limbs: &[Limb; LIMBS_2048], out: &mut [u8; 256]) {
    let mut idx = 0usize;
    while idx < LIMBS_2048 {
        #[cfg(feature = "rv64")]
        {
            out[idx * 8..(idx + 1) * 8].copy_from_slice(&limbs[idx].to_le_bytes());
        }
        #[cfg(not(feature = "rv64"))]
        {
            out[idx * 4..(idx + 1) * 4].copy_from_slice(&limbs[idx].to_le_bytes());
        }
        idx += 1;
    }
}

fn decode_limbs_le(bytes: &[u8; 256]) -> [Limb; LIMBS_2048] {
    let mut limbs = [0 as Limb; LIMBS_2048];
    let mut idx = 0usize;
    while idx < LIMBS_2048 {
        #[cfg(feature = "rv64")]
        {
            let start = idx * 8;
            limbs[idx] = Limb::from_le_bytes(bytes[start..start + 8].try_into().unwrap());
        }
        #[cfg(not(feature = "rv64"))]
        {
            let start = idx * 4;
            limbs[idx] = Limb::from_le_bytes(bytes[start..start + 4].try_into().unwrap());
        }
        idx += 1;
    }
    limbs
}

fn reduce_near_u32_prime(value: u64, prime: u32, complement: u32) -> u32 {
    let mut folded = (value & 0xffff_ffff) + ((value >> 32) * complement as u64);
    folded = (folded & 0xffff_ffff) + ((folded >> 32) * complement as u64);
    let prime_u64 = prime as u64;
    if folded >= prime_u64 {
        folded -= prime_u64;
    }
    if folded >= prime_u64 {
        folded -= prime_u64;
    }
    if folded >= prime_u64 {
        folded -= prime_u64;
    }
    folded as u32
}

pub(crate) fn seeded_weight_state_init(seed: &[u8; 32]) -> [u32; 4] {
    let mut state = [0u32; 4];
    let mut i = 0usize;
    while i < RSA_CHECK_PRIMES.len() {
        let start = i * 4;
        state[i] = u32::from_le_bytes([seed[start], seed[start + 1], seed[start + 2], seed[start + 3]])
            .wrapping_add(0x9e37_79b9u32.wrapping_mul((i as u32) + 1));
        i += 1;
    }
    state
}

pub(crate) fn sampled_step_checks(seed: &[u8; 32]) -> [bool; 17] {
    let mut checks = [false; 17];
    checks[16] = true;
    let mut i = 0usize;
    while i < 4 {
        let start = i * 4;
        let raw = u32::from_le_bytes([seed[start], seed[start + 1], seed[start + 2], seed[start + 3]]);
        checks[(raw as usize) % 16] = true;
        i += 1;
    }
    checks
}

pub(crate) fn seeded_weights(state: &[u32; 4]) -> [u32; 4] {
    let mut weights = [0u32; 4];
    let mut i = 0usize;
    while i < weights.len() {
        weights[i] = state[i] | 1;
        i += 1;
    }
    weights
}

pub(crate) fn advance_seeded_weight_state(state: &mut [u32; 4], step_idx: usize) {
    let mut i = 0usize;
    while i < state.len() {
        state[i] = state[i]
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223u32 ^ (((step_idx as u32) + 1) << (i as u32)));
        i += 1;
    }
}

fn add_mod(lhs: u32, rhs: u32, prime: u32, complement: u32) -> u32 {
    reduce_near_u32_prime((lhs as u64) + (rhs as u64), prime, complement)
}

fn neg_mod(value: u32, prime: u32) -> u32 {
    if value == 0 {
        0
    } else {
        prime - value
    }
}

#[cfg(feature = "host")]
fn biguint_to_bytes2048(value: &num_bigint::BigUint) -> Bytes2048 {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 256];
    let start = 256 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    Bytes2048(out)
}

#[cfg(feature = "host")]
fn biguint_to_limbs_2048(value: &num_bigint::BigUint) -> [Limb; LIMBS_2048] {
    bytes_be_to_limbs_2048(biguint_to_bytes2048(value).as_array())
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::*;
    use crate::verify::{bytes_be_to_limbs_2048, parse_pkcs1_modulus, verify_pkcs1v15_sha256_with_witness};
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_reduce_near_u32_prime_matches_mod() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for &(prime, complement) in &RSA_CHECK_PRIMES {
            for _ in 0..10_000 {
                let value = rng.gen::<u64>();
                assert_eq!(reduce_near_u32_prime(value, prime, complement), (value % (prime as u64)) as u32);
            }
            for &value in &[0, 1, u32::MAX as u64, u64::MAX, (prime as u64) * (prime as u64 - 1)] {
                assert_eq!(reduce_near_u32_prime(value, prime, complement), (value % (prime as u64)) as u32);
            }
        }
    }

    #[test]
    fn test_bytes2048_serde_roundtrip() {
        let mut bytes = [0u8; 256];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let wrapped = Bytes2048(bytes);
        let encoded = postcard::to_stdvec(&wrapped).unwrap();
        let decoded = postcard::from_bytes::<Bytes2048>(&encoded).unwrap();
        assert_eq!(wrapped, decoded);
    }

    #[test]
    fn test_residues_from_limbs_matches_per_prime_scan() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        for _ in 0..1024 {
            let mut limbs = [0 as Limb; LIMBS_2048];
            for limb in &mut limbs {
                *limb = rng.gen::<Limb>();
            }
            let residues = residues_from_limbs(&limbs);
            let expected = [
                limbs_mod_prime(&limbs, RSA_CHECK_PRIMES[0].0, RSA_CHECK_PRIMES[0].1),
                limbs_mod_prime(&limbs, RSA_CHECK_PRIMES[1].0, RSA_CHECK_PRIMES[1].1),
                limbs_mod_prime(&limbs, RSA_CHECK_PRIMES[2].0, RSA_CHECK_PRIMES[2].1),
                limbs_mod_prime(&limbs, RSA_CHECK_PRIMES[3].0, RSA_CHECK_PRIMES[3].1),
            ];
            assert_eq!(residues, expected);
        }
    }

    #[test]
    fn test_build_and_verify_trusted_advice_witness() {
        use rsa::pkcs1::EncodeRsaPublicKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Digest;

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let public_key_der = public_key.to_pkcs1_der().unwrap().to_vec();
        let modulus = parse_pkcs1_modulus(&public_key_der).unwrap();
        let message = b"from:test@example.com\r\nto:bob@example.com\r\n";
        let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key);
        let signature = Bytes2048(signing_key.sign(message).to_vec().try_into().unwrap());
        let witness = build_witness_2048(&modulus, &signature);
        let challenge_seed = witness_seed_from_commitment_bytes(b"witness-commitment");
        let hash: [u8; 32] = sha2::Sha256::digest(message).into();
        assert!(validate_witness_2048(&modulus, &signature, &witness));
        assert!(verify_pkcs1v15_sha256_with_witness(
            &witness,
            &modulus,
            &signature,
            &challenge_seed,
            &hash,
        ));
    }

    #[test]
    fn test_rejects_wrong_trusted_advice_witness_step() {
        use rsa::pkcs1::EncodeRsaPublicKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Digest;

        let mut rng = rand::rngs::StdRng::seed_from_u64(43);
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let public_key_der = public_key.to_pkcs1_der().unwrap();
        let modulus = parse_pkcs1_modulus(public_key_der.as_bytes()).unwrap();
        let message = b"subject:test\r\n";
        let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key);
        let signature = Bytes2048(signing_key.sign(message).to_vec().try_into().unwrap());
        let mut witness = build_witness_2048(&modulus, &signature);
        witness.steps[3].quotient_residues[0] ^= 1;
        let hash: [u8; 32] = sha2::Sha256::digest(message).into();
        let challenge_seed = witness_seed_from_commitment_bytes(b"witness-commitment");
        assert!(!validate_witness_2048(&modulus, &signature, &witness));
        assert!(!verify_pkcs1v15_sha256_with_witness(
            &witness,
            &modulus,
            &signature,
            &challenge_seed,
            &hash,
        ));
    }

    #[test]
    fn test_rejects_wrong_signature_binding() {
        let modulus = bytes_be_to_limbs_2048(&[0x11u8; 256]);
        let witness = Witness2048 { steps: [Step2048::default(); 17] };
        assert!(!verify_pkcs1v15_sha256_with_witness(
            &witness,
            &modulus,
            &Bytes2048([0x33u8; 256]),
            &[0u8; 32],
            &[0u8; 32],
        ));
    }

    #[test]
    fn test_rejects_sampled_bad_remainder_residue() {
        use rsa::pkcs1::EncodeRsaPublicKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Digest;

        let mut rng = rand::rngs::StdRng::seed_from_u64(44);
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let public_key_der = public_key.to_pkcs1_der().unwrap();
        let modulus = parse_pkcs1_modulus(public_key_der.as_bytes()).unwrap();
        let message = b"sampled-residue-check";
        let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key);
        let signature = Bytes2048(signing_key.sign(message).to_vec().try_into().unwrap());
        let mut witness = build_witness_2048(&modulus, &signature);
        let challenge_seed = witness_seed_from_commitment_bytes(b"witness-commitment");
        let sampled_checks = sampled_step_checks(&challenge_seed);
        let tampered_idx = sampled_checks[..16].iter().position(|&check| check).unwrap_or(0);
        witness.steps[tampered_idx].remainder_residues[0] ^= 1;
        let hash: [u8; 32] = sha2::Sha256::digest(message).into();
        assert!(!verify_pkcs1v15_sha256_with_witness(
            &witness,
            &modulus,
            &signature,
            &challenge_seed,
            &hash,
        ));
    }
}
