//! Guest/host API for Montgomery multiplication of 2048-bit integers.

use crate::{Limb, LIMBS_2048};

/// Context for repeated Montgomery multiplications with the same modulus.
///
/// Memory layout (contiguous, used by inline instruction):
/// - `z[0..LIMBS_2048]`:       output / low half of the SOS workspace
/// - `modulus[0..LIMBS_2048]`: modulus m (set once)
/// - `n0inv`:                  -m^{-1} mod 2^LIMB_BITS (set once)
/// - `_scratch[0..LIMBS_2048]`: high half of the SOS workspace
/// - `_scratch[LIMBS_2048]`:   carry scratch for rv32 phase splitting
#[repr(C)]
pub struct MontContext2048 {
    pub z: [Limb; LIMBS_2048],
    pub modulus: [Limb; LIMBS_2048],
    pub n0inv: Limb,
    /// Scratch area used by the inline instruction (zz_hi + carry).
    /// Do not read or write directly.
    pub _scratch: [Limb; LIMBS_2048 + 1],
}

impl MontContext2048 {
    /// Create a new context with the given modulus.
    /// Computes n0inv = -m^{-1} mod 2^LIMB_BITS automatically.
    pub fn new(modulus: [Limb; LIMBS_2048]) -> Self {
        Self::from_prepared(modulus, compute_n0inv(modulus[0]))
    }

    /// Create a context using host-prepared modulus metadata.
    pub fn from_prepared(modulus: [Limb; LIMBS_2048], n0inv: Limb) -> Self {
        Self { z: [0; LIMBS_2048], modulus, n0inv, _scratch: [0; LIMBS_2048 + 1] }
    }
}

/// Perform one Montgomery multiplication: z = x * y * R^{-1} mod m
///
/// The result is written to `ctx.z`.
/// `ctx.modulus` and `ctx.n0inv` must be set before calling.
#[cfg(feature = "rv64")]
#[inline(always)]
pub fn mont_mul_2048(ctx: &mut MontContext2048, x: &[Limb; LIMBS_2048], y: &[Limb; LIMBS_2048]) {
    unsafe {
        let ctx_ptr = ctx as *mut MontContext2048 as *mut Limb;
        mont_mul_2048_inline(x.as_ptr(), y.as_ptr(), ctx_ptr);
    }
}

#[cfg(not(feature = "rv64"))]
#[inline(always)]
pub fn mont_mul_2048(ctx: &mut MontContext2048, x: &[Limb; LIMBS_2048], y: &[Limb; LIMBS_2048]) {
    unsafe {
        let ctx_ptr = ctx as *mut MontContext2048 as *mut Limb;
        mont_mul_2048_p1_inline(x.as_ptr(), y.as_ptr(), ctx_ptr);
        mont_mul_2048_p2_inline(x.as_ptr(), y.as_ptr(), ctx_ptr);
    }
}

/// Perform one Montgomery squaring: z = x^2 * R^{-1} mod m
#[cfg(feature = "rv64")]
#[inline(always)]
pub fn mont_square_2048(ctx: &mut MontContext2048, x: &[Limb; LIMBS_2048]) {
    unsafe {
        let ctx_ptr = ctx as *mut MontContext2048 as *mut Limb;
        mont_square_2048_inline(x.as_ptr(), ctx_ptr);
    }
}

/// Perform one Montgomery squaring: z = x^2 * R^{-1} mod m
#[cfg(not(feature = "rv64"))]
#[inline(always)]
pub fn mont_square_2048(ctx: &mut MontContext2048, x: &[Limb; LIMBS_2048]) {
    unsafe {
        let ctx_ptr = ctx as *mut MontContext2048 as *mut Limb;
        mont_square_2048_p1_inline(x.as_ptr(), ctx_ptr);
        mont_square_2048_p2_inline(x.as_ptr(), ctx_ptr);
    }
}

// ---- rv64: single inline ----

#[cfg(all(not(feature = "host"), feature = "rv64"))]
unsafe fn mont_mul_2048_inline(x: *const Limb, y: *const Limb, ctx: *mut Limb) {
    use crate::{INLINE_OPCODE, MONT_MUL_2048_FUNCT3, MONT_MUL_2048_FUNCT7};
    core::arch::asm!(
        ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
        opcode = const INLINE_OPCODE,
        funct3 = const MONT_MUL_2048_FUNCT3,
        funct7 = const MONT_MUL_2048_FUNCT7,
        rd = in(reg) ctx,
        rs1 = in(reg) x,
        rs2 = in(reg) y,
        options(nostack)
    );
}

#[cfg(all(feature = "host", feature = "rv64"))]
unsafe fn mont_mul_2048_inline(x: *const Limb, y: *const Limb, ctx: *mut Limb) {
    use crate::mont_mul::exec;
    let x_arr = &*(x as *const [Limb; LIMBS_2048]);
    let ctx_ref = &mut *(ctx as *mut MontContext2048);
    let y_arr = &*(y as *const [Limb; LIMBS_2048]);
    exec::montgomery_mul(
        &mut ctx_ref.z,
        x_arr,
        y_arr,
        &ctx_ref.modulus,
        ctx_ref.n0inv,
    );
}

#[cfg(all(not(feature = "host"), feature = "rv64"))]
unsafe fn mont_square_2048_inline(x: *const Limb, ctx: *mut Limb) {
    use crate::{INLINE_OPCODE, MONT_SQUARE_2048_FUNCT3, MONT_SQUARE_2048_FUNCT7};
    core::arch::asm!(
        ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
        opcode = const INLINE_OPCODE,
        funct3 = const MONT_SQUARE_2048_FUNCT3,
        funct7 = const MONT_SQUARE_2048_FUNCT7,
        rd = in(reg) ctx,
        rs1 = in(reg) x,
        rs2 = in(reg) x,
        options(nostack)
    );
}

#[cfg(all(feature = "host", feature = "rv64"))]
unsafe fn mont_square_2048_inline(x: *const Limb, ctx: *mut Limb) {
    use crate::mont_mul::exec;
    let x_arr = &*(x as *const [Limb; LIMBS_2048]);
    let ctx_ref = &mut *(ctx as *mut MontContext2048);
    exec::montgomery_square(&mut ctx_ref.z, x_arr, &ctx_ref.modulus, ctx_ref.n0inv);
}

// ---- rv32: two-phase split ----

#[cfg(all(not(feature = "host"), not(feature = "rv64")))]
unsafe fn mont_mul_2048_p1_inline(x: *const Limb, y: *const Limb, ctx: *mut Limb) {
    use crate::{INLINE_OPCODE, MONT_MUL_2048_P1_FUNCT3, MONT_MUL_2048_P1_FUNCT7};
    core::arch::asm!(
        ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
        opcode = const INLINE_OPCODE,
        funct3 = const MONT_MUL_2048_P1_FUNCT3,
        funct7 = const MONT_MUL_2048_P1_FUNCT7,
        rd = in(reg) ctx,
        rs1 = in(reg) x,
        rs2 = in(reg) y,
        options(nostack)
    );
}

#[cfg(all(not(feature = "host"), not(feature = "rv64")))]
unsafe fn mont_mul_2048_p2_inline(x: *const Limb, y: *const Limb, ctx: *mut Limb) {
    use crate::{INLINE_OPCODE, MONT_MUL_2048_P2_FUNCT3, MONT_MUL_2048_P2_FUNCT7};
    core::arch::asm!(
        ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
        opcode = const INLINE_OPCODE,
        funct3 = const MONT_MUL_2048_P2_FUNCT3,
        funct7 = const MONT_MUL_2048_P2_FUNCT7,
        rd = in(reg) ctx,
        rs1 = in(reg) x,
        rs2 = in(reg) y,
        options(nostack)
    );
}

#[cfg(all(not(feature = "host"), not(feature = "rv64")))]
unsafe fn mont_square_2048_p1_inline(x: *const Limb, ctx: *mut Limb) {
    use crate::{INLINE_OPCODE, MONT_SQUARE_2048_P1_FUNCT3, MONT_SQUARE_2048_P1_FUNCT7};
    core::arch::asm!(
        ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
        opcode = const INLINE_OPCODE,
        funct3 = const MONT_SQUARE_2048_P1_FUNCT3,
        funct7 = const MONT_SQUARE_2048_P1_FUNCT7,
        rd = in(reg) ctx,
        rs1 = in(reg) x,
        rs2 = in(reg) x,
        options(nostack)
    );
}

#[cfg(all(not(feature = "host"), not(feature = "rv64")))]
unsafe fn mont_square_2048_p2_inline(x: *const Limb, ctx: *mut Limb) {
    use crate::{INLINE_OPCODE, MONT_SQUARE_2048_P2_FUNCT3, MONT_SQUARE_2048_P2_FUNCT7};
    core::arch::asm!(
        ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
        opcode = const INLINE_OPCODE,
        funct3 = const MONT_SQUARE_2048_P2_FUNCT3,
        funct7 = const MONT_SQUARE_2048_P2_FUNCT7,
        rd = in(reg) ctx,
        rs1 = in(reg) x,
        rs2 = in(reg) x,
        options(nostack)
    );
}

#[cfg(all(feature = "host", not(feature = "rv64")))]
unsafe fn mont_mul_2048_p1_inline(x: *const Limb, y: *const Limb, ctx: *mut Limb) {
    // Host: run the full multiplication in phase 1, phase 2 is a no-op.
    use crate::mont_mul::exec;
    let x_arr = &*(x as *const [Limb; LIMBS_2048]);
    let ctx_ref = &mut *(ctx as *mut MontContext2048);
    let y_arr = &*(y as *const [Limb; LIMBS_2048]);
    exec::montgomery_mul(
        &mut ctx_ref.z,
        x_arr,
        y_arr,
        &ctx_ref.modulus,
        ctx_ref.n0inv,
    );
}

#[cfg(all(feature = "host", not(feature = "rv64")))]
unsafe fn mont_mul_2048_p2_inline(
    _x: *const Limb,
    _y: *const Limb,
    _ctx: *mut Limb,
) {
    // No-op on host: phase 1 already computed the full result.
}

#[cfg(all(feature = "host", not(feature = "rv64")))]
unsafe fn mont_square_2048_p1_inline(x: *const Limb, ctx: *mut Limb) {
    use crate::mont_mul::exec;
    let x_arr = &*(x as *const [Limb; LIMBS_2048]);
    let ctx_ref = &mut *(ctx as *mut MontContext2048);
    exec::montgomery_square(&mut ctx_ref.z, x_arr, &ctx_ref.modulus, ctx_ref.n0inv);
}

#[cfg(all(feature = "host", not(feature = "rv64")))]
unsafe fn mont_square_2048_p2_inline(_x: *const Limb, _ctx: *mut Limb) {
    // No-op on host: phase 1 already computed the full result.
}

/// Compute n0inv = -m^{-1} mod 2^LIMB_BITS using Newton-Raphson iteration.
/// Algorithm from Dumas, "On Newton–Raphson Iteration for Multiplicative
/// Inverses Modulo Prime Powers".
pub fn compute_n0inv(m0: Limb) -> Limb {
    debug_assert!(m0 & 1 == 1, "modulus must be odd");

    #[cfg(feature = "rv64")]
    {
        let mut k0: i128 = 2 - m0 as i128;
        let mut t: i128 = (m0 as i128) - 1;
        let mut i = 1u32;
        while i < 64 {
            t = t.wrapping_mul(t);
            k0 = k0.wrapping_mul(t + 1);
            i <<= 1;
        }
        (-k0) as u64
    }
    #[cfg(not(feature = "rv64"))]
    {
        let mut k0: i64 = 2 - m0 as i64;
        let mut t: i64 = (m0 as i64) - 1;
        let mut i = 1u32;
        while i < 32 {
            t = t.wrapping_mul(t);
            k0 = k0.wrapping_mul(t + 1);
            i <<= 1;
        }
        (-k0) as u32
    }
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::*;
    use num_bigint_dig::{BigInt, BigUint, ToBigInt};
    use num_integer::Integer;
    use num_traits::{One, Signed};
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_mont_mul_matches_biguint() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xA11CE);
        let modulus = sample_modulus(&mut rng);
        let x = sample_below_modulus(&mut rng, &modulus);
        let y = sample_below_modulus(&mut rng, &modulus);

        let mut ctx = MontContext2048::new(modulus);
        mont_mul_2048(&mut ctx, &x, &y);

        let expected = montgomery_reference(&x, &y, &modulus);
        assert_eq!(ctx.z, expected);
    }

    #[test]
    fn test_mont_square_matches_biguint() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5A0A1E);
        let modulus = sample_modulus(&mut rng);
        let x = sample_below_modulus(&mut rng, &modulus);

        let mut ctx = MontContext2048::new(modulus);
        mont_square_2048(&mut ctx, &x);

        let expected = montgomery_reference(&x, &x, &modulus);
        assert_eq!(ctx.z, expected);
    }

    fn montgomery_reference(
        x: &[Limb; LIMBS_2048],
        y: &[Limb; LIMBS_2048],
        modulus: &[Limb; LIMBS_2048],
    ) -> [Limb; LIMBS_2048] {
        let modulus_bn = limbs_to_biguint(modulus);
        let x_bn = limbs_to_biguint(x);
        let y_bn = limbs_to_biguint(y);
        let r_bn = BigUint::one() << (core::mem::size_of::<Limb>() * 8 * LIMBS_2048);
        let r_inv = mod_inverse(&r_bn, &modulus_bn);
        let expected = (x_bn * y_bn * r_inv) % modulus_bn;
        biguint_to_limbs(&expected)
    }

    fn mod_inverse(value: &BigUint, modulus: &BigUint) -> BigUint {
        let modulus_bigint = modulus.to_bigint().unwrap();
        let egcd = value.to_bigint().unwrap().extended_gcd(&modulus_bigint);
        assert_eq!(egcd.gcd, BigInt::one());

        let mut inverse = egcd.x % &modulus_bigint;
        if inverse.is_negative() {
            inverse += &modulus_bigint;
        }
        inverse.to_biguint().unwrap()
    }

    fn sample_modulus(rng: &mut rand::rngs::StdRng) -> [Limb; LIMBS_2048] {
        let mut modulus = [0 as Limb; LIMBS_2048];
        for limb in modulus.iter_mut() {
            *limb = rng.gen();
        }
        modulus[0] |= 1;
        modulus[LIMBS_2048 - 1] |= 1 << (core::mem::size_of::<Limb>() * 8 - 1);
        modulus
    }

    fn sample_below_modulus(
        rng: &mut rand::rngs::StdRng,
        modulus: &[Limb; LIMBS_2048],
    ) -> [Limb; LIMBS_2048] {
        loop {
            let mut candidate = [0 as Limb; LIMBS_2048];
            for limb in candidate.iter_mut() {
                *limb = rng.gen();
            }
            candidate[LIMBS_2048 - 1] &= modulus[LIMBS_2048 - 1];
            if limbs_to_biguint(&candidate) < limbs_to_biguint(modulus) {
                return candidate;
            }
        }
    }

    fn limbs_to_biguint(limbs: &[Limb; LIMBS_2048]) -> BigUint {
        let mut bytes = [0u8; LIMBS_2048 * core::mem::size_of::<Limb>()];
        for (i, &limb) in limbs.iter().enumerate() {
            let le = limb.to_le_bytes();
            let start = i * core::mem::size_of::<Limb>();
            bytes[start..start + le.len()].copy_from_slice(&le);
        }
        BigUint::from_bytes_le(&bytes)
    }

    fn biguint_to_limbs(value: &BigUint) -> [Limb; LIMBS_2048] {
        let bytes = value.to_bytes_le();
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
