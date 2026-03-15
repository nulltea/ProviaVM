//! BigInt multiplication implementation optimized for Jolt zkVM.
//!
//! This module provides 256-bit × 256-bit = 512-bit multiplication.

use super::{INPUT_LIMBS, LIMB_BYTES, OUTPUT_LIMBS};

/// Limb type: u64 on rv64, u32 on rv32.
#[cfg(feature = "rv64")]
pub type Limb = u64;
#[cfg(not(feature = "rv64"))]
pub type Limb = u32;

/// Performs 256-bit × 256-bit multiplication
///
/// # Arguments
/// * `lhs` - First 256-bit operand as limbs (little-endian)
/// * `rhs` - Second 256-bit operand as limbs (little-endian)
///
/// # Returns
/// * 512-bit result as limbs (little-endian)
#[inline(always)]
pub fn bigint256_mul(lhs: [Limb; INPUT_LIMBS], rhs: [Limb; INPUT_LIMBS]) -> [Limb; OUTPUT_LIMBS] {
    let mut result = [0 as Limb; OUTPUT_LIMBS];
    unsafe {
        bigint256_mul_inline(lhs.as_ptr(), rhs.as_ptr(), result.as_mut_ptr());
    }
    result
}

/// Low-level interface to the BigInt multiplication inline instruction
///
/// # Safety
/// - All pointers must be valid and properly aligned
/// - `a` and `b` must point to at least 32 bytes of readable memory
/// - `result` must point to at least 64 bytes of writable memory
#[cfg(not(feature = "host"))]
pub unsafe fn bigint256_mul_inline(a: *const Limb, b: *const Limb, result: *mut Limb) {
    use super::{BIGINT256_MUL_FUNCT3, BIGINT256_MUL_FUNCT7, INLINE_OPCODE};
    core::arch::asm!(
        ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
        opcode = const INLINE_OPCODE,
        funct3 = const BIGINT256_MUL_FUNCT3,
        funct7 = const BIGINT256_MUL_FUNCT7,
        rd = in(reg) result,
        rs1 = in(reg) a,
        rs2 = in(reg) b,
        options(nostack)
    );
}

/// Host version — calls exec implementation directly.
///
/// # Safety
/// - All pointers must be valid and properly aligned
/// - `a` and `b` must point to at least 32 bytes of readable memory
/// - `result` must point to at least 64 bytes of writable memory
#[cfg(feature = "host")]
pub unsafe fn bigint256_mul_inline(a: *const Limb, b: *const Limb, result: *mut Limb) {
    use crate::multiplication::exec;

    let a_array = *(a as *const [Limb; INPUT_LIMBS]);
    let b_array = *(b as *const [Limb; INPUT_LIMBS]);
    let result_array = exec::bigint_mul(a_array, b_array);
    core::ptr::copy_nonoverlapping(result_array.as_ptr(), result, OUTPUT_LIMBS);
}
