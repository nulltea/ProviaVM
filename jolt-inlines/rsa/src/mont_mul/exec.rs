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
/// Uses the SOS (Separated Operand Scanning) method from
/// Gueron, "Efficient Software Implementations of Modular Exponentiation".
pub fn montgomery_mul(
    z: &mut [Limb; LIMBS_2048],
    x: &[Limb; LIMBS_2048],
    y: &[Limb; LIMBS_2048],
    m: &[Limb; LIMBS_2048],
    k: Limb,
) {
    let n = LIMBS_2048;

    // Working buffer: 2n limbs
    let mut zz = [0 as Limb; LIMBS_2048 * 2];
    let mut c: Limb = 0;

    for i in 0..n {
        // Pass 1: zz[i..n+i] += x[0..n] * y[i]
        let c2 = add_mul_vvw(&mut zz[i..n + i], x, y[i]);

        // Montgomery reduction factor
        let t = zz[i].wrapping_mul(k);

        // Pass 2: zz[i..n+i] += m[0..n] * t
        let c3 = add_mul_vvw(&mut zz[i..n + i], m, t);

        // Accumulate carries
        let cx = c.wrapping_add(c2);
        let cy = cx.wrapping_add(c3);
        zz[n + i] = cy;
        c = if cx < c2 || cy < c3 { 1 } else { 0 };
    }

    // Extract result: upper half or subtract m
    if c == 0 {
        z.copy_from_slice(&zz[n..2 * n]);
    } else {
        sub_vv(z, &zz[n..2 * n], m);
    }
}

/// z[0..] += x[0..] * y, returns carry.
#[inline]
fn add_mul_vvw(z: &mut [Limb], x: &[Limb; LIMBS_2048], y: Limb) -> Limb {
    let mut carry: Limb = 0;
    for (zi, &xi) in z.iter_mut().zip(x.iter()) {
        let product = (xi as DoubleLimb) * (y as DoubleLimb) + (*zi as DoubleLimb) + (carry as DoubleLimb);
        *zi = product as Limb;
        carry = (product >> LIMB_BITS) as Limb;
    }
    carry
}

/// z = x - y, assumes x >= y.
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
