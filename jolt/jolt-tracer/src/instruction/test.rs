use core::panic::AssertUnwindSafe;
use std::panic;

use crate::emulator::cpu::Cpu;
use crate::instruction::format::{InstructionFormat, InstructionRegisterState};
use crate::instruction::NormalizedInstruction;

#[cfg(test)]
use super::{div::DIV, divu::DIVU, mulh::MULH, mulhsu::MULHSU, rem::REM, remu::REMU, sll::SLL, slli::SLLI, sra::SRA, srai::SRAI, srl::SRL, srli::SRLI};

#[cfg(test)]
#[cfg(feature = "rv64")]
use super::{
    addiw::ADDIW, addw::ADDW, divuw::DIVUW, divw::DIVW, mulw::MULW, remuw::REMUW, remw::REMW,
    slliw::SLLIW, sllw::SLLW, sraiw::SRAIW, sraw::SRAW, srliw::SRLIW, srlw::SRLW, subw::SUBW,
};

use super::{RISCVInstruction, RISCVTrace};

use crate::emulator::terminal::DummyTerminal;

use crate::common::constants::RISCV_REGISTER_COUNT;

use rand::{rngs::StdRng, SeedableRng};

use super::{Cycle, RISCVCycle};

pub const TEST_MEMORY_CAPACITY: u64 = 1024 * 1024;

macro_rules! test_inline_sequences {
  ($( $instr:ty ),* $(,)?) => {
      $(
          paste::paste! {
              #[test]
              fn [<test_ $instr:lower _inline_sequence>]() {
                  inline_sequence_trace_test::<$instr>();
              }
          }
      )*
  };
}

test_inline_sequences!(
    DIV, DIVU, MULH, MULHSU, REM, REMU, SLL, SLLI, SRA, SRAI, SRL, SRLI,
);

#[cfg(feature = "rv64")]
test_inline_sequences!(
    ADDIW, ADDW, DIVUW, DIVW, MULW, REMUW, REMW, SLLIW, SLLW, SRAIW, SRAW, SRLIW, SRLW, SUBW,
);

fn test_rng() -> StdRng {
    let seed = [0u8; 32];
    StdRng::from_seed(seed)
}

pub fn inline_sequence_trace_test<I: RISCVInstruction + RISCVTrace + Copy>()
where
    Cycle: From<RISCVCycle<I>>,
{
    let mut rng = test_rng();
    let mut non_panic = 0;

    for _ in 0..1000 {
        let instruction = I::random(&mut rng);
        let instr: NormalizedInstruction = instruction.into();
        let register_state =
            <<I::Format as InstructionFormat>::RegisterState as InstructionRegisterState>::random(&mut rng);

        let mut original_cpu = Cpu::new(Box::new(DummyTerminal::default()));
        original_cpu.get_mut_mmu().init_memory(TEST_MEMORY_CAPACITY);

        let mut virtual_cpu = Cpu::new(Box::new(DummyTerminal::default()));
        virtual_cpu.get_mut_mmu().init_memory(TEST_MEMORY_CAPACITY);

        if instr.operands.rs1 != 0 {
            original_cpu.x[instr.operands.rs1 as usize] = register_state.rs1_value() as i64;
            virtual_cpu.x[instr.operands.rs1 as usize] = register_state.rs1_value() as i64;
        }
        if instr.operands.rs2 != 0 {
            original_cpu.x[instr.operands.rs2 as usize] = register_state.rs2_value() as i64;
            virtual_cpu.x[instr.operands.rs2 as usize] = register_state.rs2_value() as i64;
        }

        let mut ram_access = Default::default();

        let res = panic::catch_unwind(AssertUnwindSafe(|| {
            instruction.execute(&mut original_cpu, &mut ram_access);
        }));
        if res.is_err() {
            continue;
        }
        non_panic += 1;

        let mut trace_vec = Vec::new();
        instruction.trace(&mut virtual_cpu, Some(&mut trace_vec));

        assert_eq!(original_cpu.pc, virtual_cpu.pc, "PC register has different values after execution");

        for i in 0..RISCV_REGISTER_COUNT {
            assert_eq!(
                original_cpu.x[i as usize], virtual_cpu.x[i as usize],
                "Register {} has different values after execution. Original: {:?}, Virtual: {:?}",
                i, original_cpu.x[i as usize], virtual_cpu.x[i as usize]
            );
        }
    }
    if non_panic == 0 {
        panic!("All of instructions panic at the execute function");
    }
}
