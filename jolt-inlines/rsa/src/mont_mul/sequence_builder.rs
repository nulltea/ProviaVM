//! Sequence builder for the Montgomery multiplication inline instruction.
//!
//! Generates virtual RISC-V instructions that compute:
//!   z = x * y * R^{-1} mod m
//!
//! Memory layout (via FormatInline):
//! - rs1 -> x: LIMBS_2048 limbs
//! - rs2 -> y: LIMBS_2048 limbs
//! - rd  -> context area:
//!     [0..n*LB)              output z / zz_lo workspace
//!     [n*LB..2n*LB)          modulus m
//!     [2n*LB..2n*LB+LB)      n0inv k
//!     [2n*LB+LB..3n*LB+LB)   zz_hi scratch
//!     [3n*LB+LB..3n*LB+2*LB) carry scratch (rv32 inter-phase transfer)

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

use crate::{LIMB_BYTES, LIMBS_2048};

const M_OFFSET: i64 = (LIMBS_2048 * LIMB_BYTES) as i64;
const K_OFFSET: i64 = 2 * (LIMBS_2048 * LIMB_BYTES) as i64;
const ZZ_HI_OFFSET: i64 = K_OFFSET + LIMB_BYTES as i64;
const CARRY_OFFSET: i64 = ZZ_HI_OFFSET + (LIMBS_2048 * LIMB_BYTES) as i64;
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

    fn yi(&self) -> u8 { *self.vr[0] }
    fn t_reg(&self) -> u8 { *self.vr[1] }
    fn k_reg(&self) -> u8 { *self.vr[2] }
    fn carry(&self) -> u8 { *self.vr[3] }
    fn t0(&self) -> u8 { *self.vr[4] }
    fn t1(&self) -> u8 { *self.vr[5] }
    fn t2(&self) -> u8 { *self.vr[6] }
    fn t3(&self) -> u8 { *self.vr[7] }

    fn ctx(&self) -> u8 { self.ops.rs3 }
    fn x_ptr(&self) -> u8 { self.ops.rs1 }
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

    fn zz_offset(&self, idx: usize) -> i64 {
        if idx < LIMBS_2048 {
            (idx * LIMB_BYTES) as i64
        } else {
            ZZ_HI_OFFSET + ((idx - LIMBS_2048) * LIMB_BYTES) as i64
        }
    }

    fn emit_init(&mut self) {
        let n = LIMBS_2048;
        self.emit_load(self.k_reg(), self.ctx(), K_OFFSET);
        self.asm.emit_r::<ADD>(self.t0(), 0, 0);
        for idx in 0..2 * n {
            self.emit_store(self.ctx(), self.t0(), self.zz_offset(idx));
        }
        self.asm.emit_r::<ADD>(self.carry(), 0, 0);
    }

    fn emit_outer_loop(&mut self, start: usize, end: usize, square: bool) {
        let n = LIMBS_2048;
        for i in start..end {
            let factor_ptr = if square { self.x_ptr() } else { self.y_ptr() };
            self.emit_load(self.yi(), factor_ptr, (i * LIMB_BYTES) as i64);
            self.add_mul_vvw_pass(i, true);
            self.asm.emit_r::<ADD>(self.yi(), self.t1(), 0);
            self.emit_load(self.t_reg(), self.ctx(), self.zz_offset(i));
            self.asm.emit_r::<MUL>(self.t_reg(), self.t_reg(), self.k_reg());
            self.add_mul_vvw_pass(i, false);
            self.asm.emit_r::<ADD>(self.t3(), self.carry(), self.yi());
            let t3 = self.t3();
            self.asm.emit_r::<ADD>(self.t0(), t3, self.t1());
            self.emit_store(self.ctx(), self.t0(), self.zz_offset(n + i));
            self.asm.emit_r::<SLTU>(self.carry(), t3, self.yi());
            let tmp_carry = self.carry();
            self.asm.emit_r::<SLTU>(self.t2(), self.t0(), self.t1());
            self.asm.emit_r::<ADD>(self.carry(), tmp_carry, self.t2());
        }
    }

    fn emit_final_reduction(&mut self) {
        let n = LIMBS_2048;
        for idx in 0..n {
            self.emit_load(self.t0(), self.ctx(), self.zz_offset(n + idx));
            self.emit_store(self.ctx(), self.t0(), (idx * LIMB_BYTES) as i64);
        }

        self.asm.emit_r::<ADD>(self.t2(), 0, 0);
        for idx in 0..n {
            self.emit_load(self.t0(), self.ctx(), (idx * LIMB_BYTES) as i64);
            self.emit_load(self.t1(), self.ctx(), M_OFFSET + (idx * LIMB_BYTES) as i64);
            self.asm.emit_r::<SUB>(self.t3(), self.t0(), self.t1());
            self.asm.emit_r::<SLTU>(self.yi(), self.t0(), self.t1());
            self.asm.emit_r::<SUB>(self.t0(), self.t3(), self.t2());
            self.asm.emit_r::<SLTU>(self.t1(), self.t3(), self.t2());
            self.asm.emit_r::<ADD>(self.t2(), self.yi(), self.t1());
        }

        self.asm.emit_r::<SLTU>(self.t3(), 0, self.carry());
        self.asm.emit_r::<SLTU>(self.t1(), self.t2(), 1);
        self.asm.emit_r::<ADD>(self.t2(), self.t1(), self.t3());
        self.asm.emit_r::<SLTU>(self.t2(), 0, self.t2());

        self.asm.emit_r::<ADD>(self.carry(), 0, 0);
        for idx in 0..n {
            self.emit_load(self.t0(), self.ctx(), (idx * LIMB_BYTES) as i64);
            self.emit_load(self.t1(), self.ctx(), M_OFFSET + (idx * LIMB_BYTES) as i64);
            self.asm.emit_r::<MUL>(self.t1(), self.t1(), self.t2());
            self.asm.emit_r::<SUB>(self.t3(), self.t0(), self.t1());
            self.asm.emit_r::<SLTU>(self.yi(), self.t0(), self.t1());
            self.asm.emit_r::<SUB>(self.t0(), self.t3(), self.carry());
            self.asm.emit_r::<SLTU>(self.t1(), self.t3(), self.carry());
            self.asm.emit_r::<ADD>(self.carry(), self.yi(), self.t1());
            self.emit_store(self.ctx(), self.t0(), (idx * LIMB_BYTES) as i64);
        }
    }

    fn finalize(self) -> Vec<Instruction> {
        drop(self.vr);
        self.asm.finalize_inline()
    }

    fn add_mul_vvw_pass(&mut self, base: usize, use_x: bool) {
        let n = LIMBS_2048;
        let factor = if use_x { self.yi() } else { self.t_reg() };

        self.asm.emit_r::<ADD>(self.t1(), 0, 0);

        for j in 0..n {
            let zz_idx = base + j;

            if use_x {
                self.emit_load(self.t0(), self.x_ptr(), (j * LIMB_BYTES) as i64);
            } else {
                self.emit_load(self.t0(), self.ctx(), M_OFFSET + (j * LIMB_BYTES) as i64);
            }

            self.asm.emit_r::<MULHU>(self.t3(), self.t0(), factor);
            self.asm.emit_r::<MUL>(self.t0(), self.t0(), factor);
            self.emit_load(self.t2(), self.ctx(), self.zz_offset(zz_idx));
            self.asm.emit_r::<ADD>(self.t2(), self.t2(), self.t0());
            self.asm.emit_r::<SLTU>(self.t0(), self.t2(), self.t0());
            self.asm.emit_r::<ADD>(self.t2(), self.t2(), self.t1());
            self.asm.emit_r::<SLTU>(self.t1(), self.t2(), self.t1());
            self.emit_store(self.ctx(), self.t2(), self.zz_offset(zz_idx));
            self.asm.emit_r::<ADD>(self.t1(), self.t1(), self.t0());
            self.asm.emit_r::<ADD>(self.t1(), self.t1(), self.t3());
        }
    }
}

#[cfg(feature = "rv64")]
pub fn mont_mul_2048_sequence_builder(
    asm: InstrAssembler,
    operands: FormatInline,
) -> Vec<Instruction> {
    let mut builder = MontMulBuilder::new(asm, operands);
    builder.emit_init();
    builder.emit_outer_loop(0, LIMBS_2048, false);
    builder.emit_final_reduction();
    builder.finalize()
}

#[cfg(feature = "rv64")]
pub fn mont_square_2048_sequence_builder(
    asm: InstrAssembler,
    operands: FormatInline,
) -> Vec<Instruction> {
    let mut builder = MontMulBuilder::new(asm, operands);
    builder.emit_init();
    builder.emit_outer_loop(0, LIMBS_2048, true);
    builder.emit_final_reduction();
    builder.finalize()
}

#[cfg(not(feature = "rv64"))]
pub fn mont_mul_2048_p1_sequence_builder(
    asm: InstrAssembler,
    operands: FormatInline,
) -> Vec<Instruction> {
    let mut builder = MontMulBuilder::new(asm, operands);
    builder.emit_init();
    builder.emit_outer_loop(0, crate::SPLIT_AT, false);
    builder.emit_store(builder.ctx(), builder.carry(), CARRY_OFFSET);
    builder.finalize()
}

#[cfg(not(feature = "rv64"))]
pub fn mont_mul_2048_p2_sequence_builder(
    asm: InstrAssembler,
    operands: FormatInline,
) -> Vec<Instruction> {
    let mut builder = MontMulBuilder::new(asm, operands);
    builder.emit_load(builder.k_reg(), builder.ctx(), K_OFFSET);
    builder.emit_load(builder.carry(), builder.ctx(), CARRY_OFFSET);
    builder.emit_outer_loop(crate::SPLIT_AT, LIMBS_2048, false);
    builder.emit_final_reduction();
    builder.finalize()
}

#[cfg(not(feature = "rv64"))]
pub fn mont_square_2048_p1_sequence_builder(
    asm: InstrAssembler,
    operands: FormatInline,
) -> Vec<Instruction> {
    let mut builder = MontMulBuilder::new(asm, operands);
    builder.emit_init();
    builder.emit_outer_loop(0, crate::SPLIT_AT, true);
    builder.emit_store(builder.ctx(), builder.carry(), CARRY_OFFSET);
    builder.finalize()
}

#[cfg(not(feature = "rv64"))]
pub fn mont_square_2048_p2_sequence_builder(
    asm: InstrAssembler,
    operands: FormatInline,
) -> Vec<Instruction> {
    let mut builder = MontMulBuilder::new(asm, operands);
    builder.emit_load(builder.k_reg(), builder.ctx(), K_OFFSET);
    builder.emit_load(builder.carry(), builder.ctx(), CARRY_OFFSET);
    builder.emit_outer_loop(crate::SPLIT_AT, LIMBS_2048, true);
    builder.emit_final_reduction();
    builder.finalize()
}
