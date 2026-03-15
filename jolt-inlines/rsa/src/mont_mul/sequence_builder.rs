//! Sequence builder for the Montgomery multiplication inline instruction.
//!
//! Generates virtual RISC-V instructions that compute:
//!   z = x * y * R^{-1} mod m
//!
//! Memory layout (via FormatInline):
//! - rs1 → x: LIMBS_2048 limbs (256 bytes on rv32)
//! - rs2 → y: LIMBS_2048 limbs (256 bytes on rv32)
//! - rd  → context area:
//!     [0..256)     output z (LIMBS_2048 limbs)
//!     [256..512)   modulus m (LIMBS_2048 limbs)
//!     [512..516)   n0inv k (1 limb)

use tracer::instruction::{
    add::ADD,
    format::format_inline::FormatInline,
    mul::MUL,
    mulhu::MULHU,
    sltu::SLTU,
    sub::SUB,
    Instruction,
};

#[cfg(feature = "rv64")]
use tracer::instruction::{ld::LD, sd::SD};
#[cfg(not(feature = "rv64"))]
use tracer::instruction::{lw::LW, sw::SW};

use tracer::utils::{inline_helpers::InstrAssembler, virtual_registers::VirtualRegisterGuard};

use crate::{LIMBS_2048, LIMB_BYTES};

/// Byte offset from rd to start of modulus m.
const M_OFFSET: i64 = (LIMBS_2048 * LIMB_BYTES) as i64;
/// Byte offset from rd to n0inv.
const K_OFFSET: i64 = 2 * (LIMBS_2048 * LIMB_BYTES) as i64;
/// Byte offset to the scratch area in z (we use z[0..2*LIMBS_2048] as workspace).
/// The context's z field is only LIMBS_2048 limbs, but we need 2*LIMBS_2048 for the
/// intermediate product. We store the extra LIMBS_2048 limbs after the n0inv field.
const ZZ_HI_OFFSET: i64 = K_OFFSET + LIMB_BYTES as i64;

/// Virtual registers used:
/// - yi:    current y[i] limb
/// - t:     Montgomery factor (zz[i] * k)
/// - k_reg: n0inv value
/// - carry: running carry
/// - t0, t1, t2, t3: temporaries for mul-accumulate
const NUM_VREGS: usize = 8;

struct MontMulBuilder {
    asm: InstrAssembler,
    vr: [VirtualRegisterGuard; NUM_VREGS],
    ops: FormatInline,
}

impl MontMulBuilder {
    fn new(asm: InstrAssembler, ops: FormatInline) -> Self {
        let vr = core::array::from_fn(|_| asm.allocator.allocate_for_inline());
        Self { asm, vr, ops }
    }

    // Virtual register accessors
    fn yi(&self) -> u8 { *self.vr[0] }
    fn t_reg(&self) -> u8 { *self.vr[1] }
    fn k_reg(&self) -> u8 { *self.vr[2] }
    fn carry(&self) -> u8 { *self.vr[3] }
    fn t0(&self) -> u8 { *self.vr[4] }
    fn t1(&self) -> u8 { *self.vr[5] }
    fn t2(&self) -> u8 { *self.vr[6] }
    fn t3(&self) -> u8 { *self.vr[7] }

    // Context pointer (rd)
    fn ctx(&self) -> u8 { self.ops.rs3 }
    // x pointer (rs1)
    fn x_ptr(&self) -> u8 { self.ops.rs1 }
    // y pointer (rs2)
    fn y_ptr(&self) -> u8 { self.ops.rs2 }

    fn emit_load(&mut self, rd: u8, rs1: u8, imm: i64) {
        #[cfg(feature = "rv64")]
        self.asm.emit_ld::<LD>(rd, rs1, imm);
        #[cfg(not(feature = "rv64"))]
        self.asm.emit_ld::<LW>(rd, rs1, imm);
    }

    fn emit_store(&mut self, rs1: u8, rs2: u8, imm: i64) {
        #[cfg(feature = "rv64")]
        self.asm.emit_s::<SD>(rs1, rs2, imm);
        #[cfg(not(feature = "rv64"))]
        self.asm.emit_s::<SW>(rs1, rs2, imm);
    }

    /// Byte offset for zz[idx] in the context area.
    /// zz[0..LIMBS_2048] is stored at z offset (0..M_OFFSET).
    /// zz[LIMBS_2048..2*LIMBS_2048] is stored at ZZ_HI_OFFSET.
    fn zz_offset(&self, idx: usize) -> i64 {
        if idx < LIMBS_2048 {
            (idx * LIMB_BYTES) as i64
        } else {
            ZZ_HI_OFFSET + ((idx - LIMBS_2048) * LIMB_BYTES) as i64
        }
    }

    fn build(mut self) -> Vec<Instruction> {
        let n = LIMBS_2048;

        // Load n0inv into register
        self.emit_load(self.k_reg(), self.ctx(), K_OFFSET);

        // Initialize zz[0..2n] = 0 by storing zeros via ctx pointer
        // Use t0 = 0 as the zero source
        self.asm.emit_r::<ADD>(self.t0(), 0, 0); // t0 = 0
        for idx in 0..2 * n {
            self.emit_store(self.ctx(), self.t0(), self.zz_offset(idx));
        }

        // c = 0
        self.asm.emit_r::<ADD>(self.carry(), 0, 0);

        for i in 0..n {
            // Load y[i]
            self.emit_load(self.yi(), self.y_ptr(), (i * LIMB_BYTES) as i64);

            // Pass 1: zz[i..n+i] += x[0..n] * y[i]
            // Returns carry in self.t1()
            self.add_mul_vvw_pass(i, true);
            // Save c2 in yi (yi is free during pass 2 which uses t_reg as factor)
            self.asm.emit_r::<ADD>(self.yi(), self.t1(), 0); // yi = c2

            // t = zz[i] * k (Montgomery factor)
            self.emit_load(self.t_reg(), self.ctx(), self.zz_offset(i));
            self.asm.emit_r::<MUL>(self.t_reg(), self.t_reg(), self.k_reg());

            // Pass 2: zz[i..n+i] += m[0..n] * t
            self.add_mul_vvw_pass(i, false);
            // c3 is in t1

            // zz[n+i] = c + c2 + c3
            // cx = c + c2
            self.asm.emit_r::<ADD>(self.t3(), self.carry(), self.yi());
            // cy = cx + c3
            let t3 = self.t3();
            self.asm.emit_r::<ADD>(self.t0(), t3, self.t1());
            // Store zz[n+i] = cy
            self.emit_store(self.ctx(), self.t0(), self.zz_offset(n + i));

            // c = (cx < c2) | (cy < c3)
            self.asm.emit_r::<SLTU>(self.carry(), t3, self.yi()); // cx < c2
            let tmp_carry = self.carry();
            self.asm.emit_r::<SLTU>(self.t2(), self.t0(), self.t1()); // cy < c3
            // c = carry_bit1 | carry_bit2 (they're 0 or 1, so ADD works as OR)
            self.asm.emit_r::<ADD>(self.carry(), tmp_carry, self.t2());
        }

        // Final: if c == 0, copy zz[n..2n] to z[0..n]
        //         else z = zz[n..2n] - m
        // For simplicity: always copy zz[n..2n] to z, then conditionally subtract.
        // Since c is 0 or 1, we use c as a mask via multiply.

        // Copy zz[n..2n] → z[0..n]
        for idx in 0..n {
            self.emit_load(self.t0(), self.ctx(), self.zz_offset(n + idx));
            self.emit_store(self.ctx(), self.t0(), (idx * LIMB_BYTES) as i64);
        }

        // Conditional subtract: if c != 0, z -= m
        // carry register holds c (0 or 1)
        // borrow = 0
        self.asm.emit_r::<ADD>(self.t2(), 0, 0); // borrow = 0
        for idx in 0..n {
            // Load z[idx]
            self.emit_load(self.t0(), self.ctx(), (idx * LIMB_BYTES) as i64);
            // Load m[idx]
            self.emit_load(self.t1(), self.ctx(), M_OFFSET + (idx * LIMB_BYTES) as i64);
            // masked_m = m[idx] * c (if c=0, subtract nothing)
            self.asm.emit_r::<MUL>(self.t1(), self.t1(), self.carry());
            // z[idx] = z[idx] - masked_m - borrow
            self.asm.emit_r::<SUB>(self.t3(), self.t0(), self.t1());
            self.asm.emit_r::<SLTU>(self.yi(), self.t0(), self.t1()); // borrow from sub
            self.asm.emit_r::<SUB>(self.t0(), self.t3(), self.t2());
            self.asm.emit_r::<SLTU>(self.t1(), self.t3(), self.t2()); // borrow from borrow-sub
            self.asm.emit_r::<ADD>(self.t2(), self.yi(), self.t1()); // total borrow
            self.emit_store(self.ctx(), self.t0(), (idx * LIMB_BYTES) as i64);
        }

        drop(self.vr);
        self.asm.finalize_inline()
    }

    /// Emit add_mul_vvw: zz[base..base+n] += src[0..n] * factor
    /// If `use_x` is true, src = x (rs1) and factor = yi.
    /// If `use_x` is false, src = m (in ctx at M_OFFSET) and factor = t_reg.
    /// After return, the carry is in t1.
    fn add_mul_vvw_pass(&mut self, base: usize, use_x: bool) {
        let n = LIMBS_2048;
        let factor = if use_x { self.yi() } else { self.t_reg() };

        // Initialize carry = 0 (in t1)
        self.asm.emit_r::<ADD>(self.t1(), 0, 0); // carry in t1

        for j in 0..n {
            let zz_idx = base + j;

            // Load src[j]
            if use_x {
                self.emit_load(self.t0(), self.x_ptr(), (j * LIMB_BYTES) as i64);
            } else {
                self.emit_load(self.t0(), self.ctx(), M_OFFSET + (j * LIMB_BYTES) as i64);
            }

            // hi = MULHU(src[j], factor)
            self.asm.emit_r::<MULHU>(self.t3(), self.t0(), factor);
            // lo = MUL(src[j], factor)
            self.asm.emit_r::<MUL>(self.t0(), self.t0(), factor);

            // Load zz[base+j]
            self.emit_load(self.t2(), self.ctx(), self.zz_offset(zz_idx));

            // zz[base+j] += lo
            self.asm.emit_r::<ADD>(self.t2(), self.t2(), self.t0());
            // carry1 = (zz < lo)
            self.asm.emit_r::<SLTU>(self.t0(), self.t2(), self.t0());

            // zz[base+j] += prev_carry (t1)
            self.asm.emit_r::<ADD>(self.t2(), self.t2(), self.t1());
            // carry2 = (zz < prev_carry)
            self.asm.emit_r::<SLTU>(self.t1(), self.t2(), self.t1());

            // Store zz[base+j]
            self.emit_store(self.ctx(), self.t2(), self.zz_offset(zz_idx));

            // new_carry = hi + carry1 + carry2
            self.asm.emit_r::<ADD>(self.t1(), self.t1(), self.t0());
            self.asm.emit_r::<ADD>(self.t1(), self.t1(), self.t3());
        }
        // carry remains in t1
    }
}

/// Entry point for the inline registry.
pub fn mont_mul_2048_sequence_builder(
    asm: InstrAssembler,
    operands: FormatInline,
) -> Vec<Instruction> {
    MontMulBuilder::new(asm, operands).build()
}
