use core::array;

use tracer::instruction::{
    add::ADD,
    format::format_inline::FormatInline,
    mul::MUL,
    mulhu::MULHU,
    sltu::SLTU,
    Instruction,
};

#[cfg(feature = "rv64")]
use tracer::instruction::{ld::LD, sd::SD};
#[cfg(not(feature = "rv64"))]
use tracer::instruction::{lw::LW, sw::SW};

use tracer::utils::{inline_helpers::InstrAssembler, virtual_registers::VirtualRegisterGuard};

use super::{INPUT_LIMBS, LIMB_BYTES, OUTPUT_LIMBS};

/// Number of virtual registers needed for BigInt multiplication
/// Layout:
/// - a[0..INPUT_LIMBS]: First operand limbs
/// - b[0..INPUT_LIMBS]: Second operand limbs
/// - s[0..OUTPUT_LIMBS]: Result accumulator limbs
/// - t[0..4]: Temporary registers for multiplication and carry
const NEEDED_REGISTERS: usize = INPUT_LIMBS + INPUT_LIMBS + OUTPUT_LIMBS + 4;

struct BigIntMulSequenceBuilder {
    asm: InstrAssembler,
    vr: [VirtualRegisterGuard; NEEDED_REGISTERS],
    operands: FormatInline,
}

impl BigIntMulSequenceBuilder {
    fn new(asm: InstrAssembler, operands: FormatInline) -> Self {
        let vr = array::from_fn(|_| asm.allocator.allocate_for_inline());
        BigIntMulSequenceBuilder { asm, vr, operands }
    }

    fn a(&self, i: usize) -> u8 {
        *self.vr[i]
    }
    fn b(&self, i: usize) -> u8 {
        *self.vr[INPUT_LIMBS + i]
    }
    fn s(&self, i: usize) -> u8 {
        *self.vr[INPUT_LIMBS + INPUT_LIMBS + i]
    }
    fn t(&self, i: usize) -> u8 {
        *self.vr[INPUT_LIMBS + INPUT_LIMBS + OUTPUT_LIMBS + i]
    }

    fn build(mut self) -> Vec<Instruction> {
        // Load operands from memory
        for i in 0..INPUT_LIMBS {
            self.emit_load(self.a(i), self.operands.rs1, i as i64 * LIMB_BYTES as i64);
        }
        for i in 0..INPUT_LIMBS {
            self.emit_load(self.b(i), self.operands.rs2, i as i64 * LIMB_BYTES as i64);
        }

        // Initialize result accumulator to zero
        for i in 0..OUTPUT_LIMBS {
            self.asm.emit_r::<ADD>(self.s(i), 0, 0);
        }

        // Schoolbook multiplication
        for i in 0..INPUT_LIMBS {
            for j in 0..INPUT_LIMBS {
                self.mul_and_accumulate(i, j);
            }
        }

        // Store result to memory
        for i in 0..OUTPUT_LIMBS {
            self.emit_store(self.operands.rs3, self.s(i), i as i64 * LIMB_BYTES as i64);
        }

        drop(self.vr);
        self.asm.finalize_inline()
    }

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

    /// MUL-ACC pattern: A[i] × B[j] → accumulate into R[k], R[k+1], ... with carry
    fn mul_and_accumulate(&mut self, i: usize, j: usize) {
        let k = i + j;
        let ai = self.a(i);
        let bj = self.b(j);
        let sk = self.s(k);
        let t0 = self.t(0);
        let t1 = self.t(1);
        let t2 = self.t(2);

        // t1 = high(a[i] * b[j])
        self.asm.emit_r::<MULHU>(t1, ai, bj);
        // t0 = low(a[i] * b[j])
        self.asm.emit_r::<MUL>(t0, ai, bj);
        // s[k] += t0
        self.asm.emit_r::<ADD>(sk, sk, t0);

        let sk1 = self.s(k + 1);

        // No carry possible when k == 0 (first partial product)
        if k == 0 {
            self.asm.emit_r::<ADD>(sk1, sk1, t1);
            return;
        }

        // Detect carry: t2 = (s[k] < t0)
        self.asm.emit_r::<SLTU>(t2, sk, t0);
        // t1 += carry
        self.asm.emit_r::<ADD>(t1, t1, t2);
        // s[k+1] += t1
        self.asm.emit_r::<ADD>(sk1, sk1, t1);

        // Ripple carry through higher limbs
        if k + 2 < OUTPUT_LIMBS {
            self.asm.emit_r::<SLTU>(t2, sk1, t1);
            for m in (k + 2)..OUTPUT_LIMBS {
                let sm = self.s(m);
                self.asm.emit_r::<ADD>(sm, sm, t2);
                if m + 1 < OUTPUT_LIMBS {
                    self.asm.emit_r::<SLTU>(t2, sm, t2);
                }
            }
        }
    }
}

/// Entry point for the inline sequence builder (called by tracer registry).
pub fn bigint_mul_sequence_builder(
    asm: InstrAssembler,
    operands: FormatInline,
) -> Vec<Instruction> {
    let builder = BigIntMulSequenceBuilder::new(asm, operands);
    builder.build()
}
