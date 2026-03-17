//! Host-side Montgomery multiplication for 2048-bit integers.

use crate::{Limb, LIMBS_2048};

#[cfg(feature = "rv64")]
type DoubleLimb = u128;
#[cfg(not(feature = "rv64"))]
type DoubleLimb = u64;

const LIMB_BITS: u32 = (core::mem::size_of::<Limb>() * 8) as u32;

/// Montgomery multiplication: z = x * y * R^{-1} mod m
/// where R = 2^(LIMB_BITS * LIMBS_2048).
///
/// Uses a CIOS-style Montgomery reduction with an `(n + 2)` limb workspace.
pub fn montgomery_mul(
    z: &mut [Limb; LIMBS_2048],
    x: &[Limb; LIMBS_2048],
    y: &[Limb; LIMBS_2048],
    m: &[Limb; LIMBS_2048],
    k: Limb,
) {
    let n = LIMBS_2048;
    let mut t = [0 as Limb; LIMBS_2048 + 2];

    for i in 0..n {
        let mut carry = 0 as Limb;
        for j in 0..n {
            let product = (x[j] as DoubleLimb) * (y[i] as DoubleLimb)
                + (t[j] as DoubleLimb)
                + (carry as DoubleLimb);
            t[j] = product as Limb;
            carry = (product >> LIMB_BITS) as Limb;
        }

        let acc = (t[n] as DoubleLimb) + (carry as DoubleLimb);
        t[n] = acc as Limb;
        t[n + 1] = t[n + 1].wrapping_add((acc >> LIMB_BITS) as Limb);

        let u = t[0].wrapping_mul(k);
        carry = 0;
        for j in 0..n {
            let product = (u as DoubleLimb) * (m[j] as DoubleLimb)
                + (t[j] as DoubleLimb)
                + (carry as DoubleLimb);
            if j > 0 {
                t[j - 1] = product as Limb;
            }
            carry = (product >> LIMB_BITS) as Limb;
        }

        let acc = (t[n] as DoubleLimb) + (carry as DoubleLimb);
        t[n - 1] = acc as Limb;
        t[n] = t[n + 1].wrapping_add((acc >> LIMB_BITS) as Limb);
        t[n + 1] = 0;
    }

    if t[n] != 0 || geq(&t[..n], m) {
        sub_vv(z, &t[..n], m);
    } else {
        z.copy_from_slice(&t[..n]);
    }
}

/// Montgomery squaring: z = x^2 * R^{-1} mod m.
pub fn montgomery_square(
    z: &mut [Limb; LIMBS_2048],
    x: &[Limb; LIMBS_2048],
    m: &[Limb; LIMBS_2048],
    k: Limb,
) {
    montgomery_mul(z, x, x, m, k);
}

#[inline]
fn geq(x: &[Limb], y: &[Limb; LIMBS_2048]) -> bool {
    for i in (0..LIMBS_2048).rev() {
        if x[i] > y[i] {
            return true;
        }
        if x[i] < y[i] {
            return false;
        }
    }
    true
}

#[inline]
fn sub_vv(z: &mut [Limb; LIMBS_2048], x: &[Limb], y: &[Limb; LIMBS_2048]) {
    let mut borrow: Limb = 0;
    for i in 0..LIMBS_2048 {
        let (diff1, b1) = x[i].overflowing_sub(y[i]);
        let (diff2, b2) = diff1.overflowing_sub(borrow);
        z[i] = diff2;
        borrow = (b1 as Limb) + (b2 as Limb);
    }
}
