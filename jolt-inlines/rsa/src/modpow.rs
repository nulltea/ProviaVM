//! Modular exponentiation for RSA using Montgomery multiplication inline.

use crate::mont_mul::sdk::{compute_n0inv, mont_mul_2048, mont_square_2048, MontContext2048};
use crate::{Limb, LIMBS_2048};

/// Host-prepared Montgomery constants for a fixed RSA modulus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedModulus2048 {
    pub modulus: [Limb; LIMBS_2048],
    pub n0inv: Limb,
    pub rr: [Limb; LIMBS_2048],
}

/// A prepared modulus whose Montgomery metadata has been validated once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedPreparedModulus2048 {
    pub modulus: [Limb; LIMBS_2048],
    pub n0inv: Limb,
    pub rr: [Limb; LIMBS_2048],
}

impl PreparedModulus2048 {
    pub fn from_modulus(modulus: [Limb; LIMBS_2048]) -> Self {
        let n0inv = compute_n0inv(modulus[0]);
        let rr = compute_rr(&modulus);
        Self { modulus, n0inv, rr }
    }

    pub fn validate(&self) -> Option<ValidatedPreparedModulus2048> {
        if compute_n0inv(self.modulus[0]) != self.n0inv {
            return None;
        }

        if self.rr != compute_rr(&self.modulus) {
            return None;
        }

        Some(ValidatedPreparedModulus2048 {
            modulus: self.modulus,
            n0inv: self.n0inv,
            rr: self.rr,
        })
    }

    pub fn checked_context(&self) -> Option<MontContext2048> {
        self.validate().map(|validated| validated.context())
    }
}

impl ValidatedPreparedModulus2048 {
    pub fn context(&self) -> MontContext2048 {
        MontContext2048::from_prepared(self.modulus, self.n0inv)
    }
}

/// Compute base^65537 mod modulus using Montgomery multiplication.
pub fn modpow_65537(base: &[Limb; LIMBS_2048], modulus: &[Limb; LIMBS_2048]) -> [Limb; LIMBS_2048] {
    let prepared = PreparedModulus2048::from_modulus(*modulus);
    let validated = prepared
        .validate()
        .expect("invalid RSA prepared modulus");
    modpow_65537_prepared(base, &validated)
}

/// Compute base^65537 mod modulus using host-prepared Montgomery constants.
pub fn modpow_65537_prepared(
    base: &[Limb; LIMBS_2048],
    prepared: &ValidatedPreparedModulus2048,
) -> [Limb; LIMBS_2048] {
    let mut ctx = prepared.context();

    mont_mul_2048(&mut ctx, base, &prepared.rr);
    let mont_base = ctx.z;

    let mut acc = mont_base;
    for _ in 0..16 {
        mont_square_2048(&mut ctx, &acc);
        acc = ctx.z;
    }

    mont_mul_2048(&mut ctx, &acc, &mont_base);
    acc = ctx.z;

    let mut one = [0 as Limb; LIMBS_2048];
    one[0] = 1;
    mont_mul_2048(&mut ctx, &acc, &one);

    ctx.z
}

pub(crate) fn compute_r_mod(m: &[Limb; LIMBS_2048]) -> [Limb; LIMBS_2048] {
    let mut r_mod_m = [0 as Limb; LIMBS_2048];
    let mut borrow: Limb = 0;
    for i in 0..LIMBS_2048 {
        let (d, b) = (0 as Limb).overflowing_sub(m[i]);
        let (d2, b2) = d.overflowing_sub(borrow);
        r_mod_m[i] = d2;
        borrow = (b as Limb) + (b2 as Limb);
    }
    reduce_if_gte(&mut r_mod_m, m);
    r_mod_m
}

fn compute_rr(m: &[Limb; LIMBS_2048]) -> [Limb; LIMBS_2048] {
    let limb_bits = core::mem::size_of::<Limb>() * 8;
    let total_bits = limb_bits * LIMBS_2048;
    let mut rr = compute_r_mod(m);
    for _ in 0..total_bits {
        mod_double(&mut rr, m);
    }
    rr
}

fn mod_double(rr: &mut [Limb; LIMBS_2048], m: &[Limb; LIMBS_2048]) {
    let limb_bits = (core::mem::size_of::<Limb>() * 8) as u32;
    let mut carry: Limb = 0;
    for limb in rr.iter_mut() {
        let new_carry = *limb >> (limb_bits - 1);
        *limb = (*limb << 1) | carry;
        carry = new_carry;
    }
    if carry != 0 {
        sub_in_place(rr, m);
    } else {
        reduce_if_gte(rr, m);
    }
}

fn reduce_if_gte(x: &mut [Limb; LIMBS_2048], m: &[Limb; LIMBS_2048]) {
    let mut ge = true;
    for i in (0..LIMBS_2048).rev() {
        if x[i] > m[i] {
            ge = true;
            break;
        }
        if x[i] < m[i] {
            ge = false;
            break;
        }
    }
    if ge {
        sub_in_place(x, m);
    }
}

fn sub_in_place(x: &mut [Limb; LIMBS_2048], y: &[Limb; LIMBS_2048]) {
    let mut borrow: Limb = 0;
    for i in 0..LIMBS_2048 {
        let (d1, b1) = x[i].overflowing_sub(y[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        x[i] = d2;
        borrow = (b1 as Limb) + (b2 as Limb);
    }
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::*;

    #[test]
    fn test_modpow_65537_small() {
        use num_bigint_dig::BigUint;
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(999);
        let mut m = [0 as Limb; LIMBS_2048];
        for limb in m.iter_mut() {
            *limb = rng.gen();
        }
        m[0] |= 1;
        m[LIMBS_2048 - 1] |= 1 << (core::mem::size_of::<Limb>() * 8 - 1);

        let mut base = [0 as Limb; LIMBS_2048];
        for limb in base.iter_mut() {
            *limb = rng.gen();
        }
        base[LIMBS_2048 - 1] &= m[LIMBS_2048 - 1] >> 1;

        let result = modpow_65537(&base, &m);

        let base_bn = limbs_to_biguint(&base);
        let m_bn = limbs_to_biguint(&m);
        let expected_bn = base_bn.modpow(&BigUint::from(65537u32), &m_bn);
        let expected = biguint_to_limbs(&expected_bn);

        assert_eq!(result, expected, "modpow_65537 result mismatch");
    }

    #[test]
    fn test_prepared_modulus_roundtrip() {
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(12345);
        let mut modulus = [0 as Limb; LIMBS_2048];
        for limb in modulus.iter_mut() {
            *limb = rng.gen();
        }
        modulus[0] |= 1;
        modulus[LIMBS_2048 - 1] |= 1 << (core::mem::size_of::<Limb>() * 8 - 1);

        let prepared = PreparedModulus2048::from_modulus(modulus);
        assert!(prepared.validate().is_some());
    }

    fn limbs_to_biguint(limbs: &[Limb; LIMBS_2048]) -> num_bigint_dig::BigUint {
        let mut bytes = [0u8; LIMBS_2048 * core::mem::size_of::<Limb>()];
        for (i, &limb) in limbs.iter().enumerate() {
            let le = limb.to_le_bytes();
            let start = i * core::mem::size_of::<Limb>();
            bytes[start..start + le.len()].copy_from_slice(&le);
        }
        num_bigint_dig::BigUint::from_bytes_le(&bytes)
    }

    fn biguint_to_limbs(bn: &num_bigint_dig::BigUint) -> [Limb; LIMBS_2048] {
        let bytes = bn.to_bytes_le();
        let mut limbs = [0 as Limb; LIMBS_2048];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = i * core::mem::size_of::<Limb>();
            if start >= bytes.len() {
                break;
            }
            let end = (start + core::mem::size_of::<Limb>()).min(bytes.len());
            let mut buf = [0u8; 8];
            buf[..end - start].copy_from_slice(&bytes[start..end]);
            #[cfg(feature = "rv64")]
            {
                *limb = u64::from_le_bytes(buf);
            }
            #[cfg(not(feature = "rv64"))]
            {
                *limb = u32::from_le_bytes(buf[..4].try_into().unwrap());
            }
        }
        limbs
    }
}
