//! Guest/host API for Montgomery multiplication of 2048-bit integers.

use crate::{Limb, LIMBS_2048};

/// Context for repeated Montgomery multiplications with the same modulus.
///
/// Memory layout (contiguous, used by inline instruction):
/// - `z[0..LIMBS_2048]`:     output (LIMBS_2048 limbs)
/// - `modulus[0..LIMBS_2048]`: modulus m (LIMBS_2048 limbs, set once)
/// - `n0inv`:                 -m^{-1} mod 2^LIMB_BITS (set once)
#[repr(C)]
pub struct MontContext2048 {
    pub z: [Limb; LIMBS_2048],
    pub modulus: [Limb; LIMBS_2048],
    pub n0inv: Limb,
}

impl MontContext2048 {
    /// Create a new context with the given modulus.
    /// Computes n0inv = -m^{-1} mod 2^LIMB_BITS automatically.
    pub fn new(modulus: [Limb; LIMBS_2048]) -> Self {
        let n0inv = compute_n0inv(modulus[0]);
        Self {
            z: [0; LIMBS_2048],
            modulus,
            n0inv,
        }
    }
}

/// Perform one Montgomery multiplication: z = x * y * R^{-1} mod m
///
/// The result is written to `ctx.z`.
/// `ctx.modulus` and `ctx.n0inv` must be set before calling.
#[inline(always)]
pub fn mont_mul_2048(ctx: &mut MontContext2048, x: &[Limb; LIMBS_2048], y: &[Limb; LIMBS_2048]) {
    unsafe {
        mont_mul_2048_inline(
            x.as_ptr(),
            y.as_ptr(),
            ctx as *mut MontContext2048 as *mut Limb,
        );
    }
}

/// Low-level inline instruction (guest — emits custom RISC-V instruction).
///
/// # Safety
/// - `x` and `y`: valid pointers to LIMBS_2048 limbs (256 bytes each)
/// - `ctx`: valid pointer to MontContext2048 layout
#[cfg(not(feature = "host"))]
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

/// Host version — calls exec implementation.
#[cfg(feature = "host")]
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
