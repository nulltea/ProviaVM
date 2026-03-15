use super::{sdk::Limb, BIGINT256_MUL_FUNCT3, BIGINT256_MUL_FUNCT7, INLINE_OPCODE, INPUT_LIMBS, OUTPUT_LIMBS};
use tracer::emulator::cpu::Xlen;
use tracer::utils::inline_test_harness::{InlineMemoryLayout, InlineTestHarness};

pub type BigIntInput = ([Limb; INPUT_LIMBS], [Limb; INPUT_LIMBS]);
pub type BigIntOutput = [Limb; OUTPUT_LIMBS];

pub fn create_bigint_harness() -> InlineTestHarness {
    let layout = InlineMemoryLayout::two_inputs(32, 32, 64);
    #[cfg(feature = "rv64")]
    let xlen = Xlen::Bit64;
    #[cfg(not(feature = "rv64"))]
    let xlen = Xlen::Bit32;
    InlineTestHarness::new(layout, xlen)
}

pub fn instruction() -> tracer::instruction::inline::INLINE {
    InlineTestHarness::create_default_instruction(
        INLINE_OPCODE,
        BIGINT256_MUL_FUNCT3,
        BIGINT256_MUL_FUNCT7,
    )
}

pub mod bigint_verify {
    use super::*;

    pub fn assert_exec_trace_equiv(
        lhs: &[Limb; INPUT_LIMBS],
        rhs: &[Limb; INPUT_LIMBS],
        expected: &[Limb; OUTPUT_LIMBS],
    ) {
        let mut harness = create_bigint_harness();
        harness.setup_registers();

        #[cfg(feature = "rv64")]
        {
            harness.load_input64(lhs);
            harness.load_input2_64(rhs);
        }
        #[cfg(not(feature = "rv64"))]
        {
            harness.load_input32(lhs);
            harness.load_input2_32(rhs);
        }

        harness.execute_inline(instruction());

        #[cfg(feature = "rv64")]
        let result_vec = harness.read_output64(OUTPUT_LIMBS);
        #[cfg(not(feature = "rv64"))]
        let result_vec = harness.read_output32(OUTPUT_LIMBS);

        let mut result = [0 as Limb; OUTPUT_LIMBS];
        result.copy_from_slice(&result_vec);

        assert_eq!(&result, expected, "BigInt multiplication result mismatch");
    }
}
