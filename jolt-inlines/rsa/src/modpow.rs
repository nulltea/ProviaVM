//! Modular exponentiation for RSA using Montgomery multiplication inline.

use crate::{Limb, LIMBS_2048};
use crate::mont_mul::sdk::{compute_n0inv, mont_mul_2048, MontContext2048};

/// Compute base^65537 mod modulus using Montgomery multiplication.
///
/// Specialized for e = 65537 = 2^16 + 1 (standard RSA public exponent).
/// Requires only 19 Montgomery multiplications.
pub fn modpow_65537(base: &[Limb; LIMBS_2048], modulus: &[Limb; LIMBS_2048]) -> [Limb; LIMBS_2048] {
    let mut ctx = MontContext2048::new(*modulus);

    // Compute R^2 mod m (needed to convert to Montgomery form)
    let rr = compute_rr(modulus);

    // Convert base to Montgomery form: mont_base = base * R mod m
    mont_mul_2048(&mut ctx, base, &rr);
    let mont_base = ctx.z;

    // Square 16 times: acc = mont_base^(2^16)
    let mut acc = mont_base;
    for _ in 0..16 {
        mont_mul_2048(&mut ctx, &acc, &acc);
        acc = ctx.z;
    }

    // Multiply by base: acc = mont_base^(2^16 + 1) = mont_base^65537
    mont_mul_2048(&mut ctx, &acc, &mont_base);
    acc = ctx.z;

    // Convert back from Montgomery form: result = acc * 1 * R^{-1} mod m
    let mut one = [0 as Limb; LIMBS_2048];
    one[0] = 1;
    mont_mul_2048(&mut ctx, &acc, &one);

    ctx.z
}

/// Compute R^2 mod m where R = 2^(LIMB_BITS * LIMBS_2048).
/// Uses repeated doubling: start with R mod m, then square.
fn compute_rr(m: &[Limb; LIMBS_2048]) -> [Limb; LIMBS_2048] {
    // First compute R mod m.
    // R = 2^(LIMB_BITS * LIMBS_2048).
    // R mod m = R - m * floor(R/m).
    // Since m < R and m has high bit set, R mod m = R - m.
    // But R doesn't fit in LIMBS_2048 limbs. Instead:
    // R mod m = (2^(LIMB_BITS*LIMBS_2048)) mod m
    // = -m mod 2^(LIMB_BITS*LIMBS_2048) when m < R and high bit of m is set
    // = twos_complement(m)
    let mut r_mod_m = [0 as Limb; LIMBS_2048];
    let mut borrow: Limb = 0;
    for i in 0..LIMBS_2048 {
        let (d, b) = (0 as Limb).overflowing_sub(m[i]);
        let (d2, b2) = d.overflowing_sub(borrow);
        r_mod_m[i] = d2;
        borrow = (b as Limb) + (b2 as Limb);
    }
    // r_mod_m might be >= m, reduce once
    reduce_if_gte(&mut r_mod_m, m);

    // Now compute R^2 mod m = (R mod m)^2 mod m
    // Use Montgomery: mont(R mod m, R mod m) = (R mod m)^2 * R^{-1} mod m
    // That gives R mod m, not R^2.
    // Instead, compute R^2 mod m by repeated doubling of R mod m:
    // Start with r = R mod m
    // Double r LIMB_BITS*LIMBS_2048 times: r = 2*r mod m each time
    // After n doublings: r = 2^n * R mod m = R * 2^n mod m
    // When n = LIMB_BITS*LIMBS_2048: r = R * R mod m = R^2 mod m
    let limb_bits = core::mem::size_of::<Limb>() * 8;
    let total_bits = limb_bits * LIMBS_2048;
    let mut rr = r_mod_m;
    for _ in 0..total_bits {
        mod_double(&mut rr, m);
    }
    rr
}

/// rr = 2 * rr mod m
fn mod_double(rr: &mut [Limb; LIMBS_2048], m: &[Limb; LIMBS_2048]) {
    let limb_bits = (core::mem::size_of::<Limb>() * 8) as u32;
    // Left shift by 1
    let mut carry: Limb = 0;
    for limb in rr.iter_mut() {
        let new_carry = *limb >> (limb_bits - 1);
        *limb = (*limb << 1) | carry;
        carry = new_carry;
    }
    // If carry or rr >= m, subtract m
    if carry != 0 {
        sub_in_place(rr, m);
    } else {
        reduce_if_gte(rr, m);
    }
}

fn reduce_if_gte(x: &mut [Limb; LIMBS_2048], m: &[Limb; LIMBS_2048]) {
    // Check if x >= m
    let mut ge = true;
    for i in (0..LIMBS_2048).rev() {
        if x[i] > m[i] { ge = true; break; }
        if x[i] < m[i] { ge = false; break; }
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
        // Use a known RSA-style test: base^65537 mod m
        // We verify against num-bigint-dig's modpow
        use num_bigint_dig::BigUint;
        use num_traits::One;

        // Create a deterministic 2048-bit odd modulus
        use rand::{SeedableRng, Rng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(999);
        let mut m = [0 as Limb; LIMBS_2048];
        for limb in m.iter_mut() { *limb = rng.gen(); }
        m[0] |= 1; // odd
        m[LIMBS_2048 - 1] |= 1 << (core::mem::size_of::<Limb>() * 8 - 1); // high bit

        // Create a base < m
        let mut base = [0 as Limb; LIMBS_2048];
        for limb in base.iter_mut() { *limb = rng.gen(); }
        // Ensure base < m by clearing high limb
        base[LIMBS_2048 - 1] &= m[LIMBS_2048 - 1] >> 1;

        // Our implementation
        let result = modpow_65537(&base, &m);

        // Reference: num-bigint-dig
        let base_bn = limbs_to_biguint(&base);
        let m_bn = limbs_to_biguint(&m);
        let e_bn = BigUint::from(65537u32);
        let expected_bn = base_bn.modpow(&e_bn, &m_bn);
        let expected = biguint_to_limbs(&expected_bn);

        assert_eq!(result, expected, "modpow_65537 result mismatch");
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
            if start >= bytes.len() { break; }
            let end = (start + core::mem::size_of::<Limb>()).min(bytes.len());
            let mut buf = [0u8; 8]; // max limb size
            buf[..end - start].copy_from_slice(&bytes[start..end]);
            #[cfg(feature = "rv64")]
            { *limb = u64::from_le_bytes(buf); }
            #[cfg(not(feature = "rv64"))]
            { *limb = u32::from_le_bytes(buf[..4].try_into().unwrap()); }
        }
        limbs
    }
}
