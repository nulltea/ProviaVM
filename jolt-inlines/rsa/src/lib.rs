//! RSA inline implementations for Jolt VM.
//!
//! Provides a Montgomery multiplication inline for 2048-bit integers,
//! enabling efficient RSA signature verification in zkVM guests.

#![cfg_attr(not(feature = "host"), no_std)]

extern crate alloc;

pub mod mont_mul;
pub mod modpow;
pub mod verify;
pub mod witness;

pub use mont_mul::sdk::{mont_mul_2048, mont_square_2048, MontContext2048};
pub use modpow::{
    modpow_65537,
    modpow_65537_prepared,
    PreparedModulus2048,
    ValidatedPreparedModulus2048,
};
pub use witness::{
    Bytes2048,
    Rsa65537TrustedAdviceWitness2048,
    RsaReductionOp,
    RsaReductionStep2048,
    verify_rsa65537_trusted_advice_witness_pkcs1v15_sha256,
};
#[cfg(feature = "host")]
pub use witness::{
    build_rsa65537_trusted_advice_witness,
    trusted_advice_witness_seed_from_commitment,
    trusted_advice_witness_seed_from_commitment_bytes,
    validate_rsa65537_trusted_advice_witness,
};

/// Limb type: u64 on rv64, u32 on rv32.
#[cfg(feature = "rv64")]
pub type Limb = u64;
#[cfg(not(feature = "rv64"))]
pub type Limb = u32;

/// Number of limbs in a 2048-bit integer.
#[cfg(feature = "rv64")]
pub const LIMBS_2048: usize = 32;
#[cfg(not(feature = "rv64"))]
pub const LIMBS_2048: usize = 64;

/// Byte size of a single limb.
#[cfg(feature = "rv64")]
pub const LIMB_BYTES: usize = 8;
#[cfg(not(feature = "rv64"))]
pub const LIMB_BYTES: usize = 4;

// Inline opcode constants
pub const INLINE_OPCODE: u32 = 0x0B;

// rv64: single inline (fits u16)
#[cfg(feature = "rv64")]
pub const MONT_MUL_2048_FUNCT3: u32 = 0x00;
#[cfg(feature = "rv64")]
pub const MONT_MUL_2048_FUNCT7: u32 = 0x02;
#[cfg(feature = "rv64")]
pub const MONT_MUL_2048_NAME: &str = "MONT_MUL_2048";

#[cfg(feature = "rv64")]
pub const MONT_SQUARE_2048_FUNCT3: u32 = 0x01;
#[cfg(feature = "rv64")]
pub const MONT_SQUARE_2048_FUNCT7: u32 = 0x02;
#[cfg(feature = "rv64")]
pub const MONT_SQUARE_2048_NAME: &str = "MONT_SQUARE_2048";

// rv32: two-phase split (each half < 65535 virtual instructions)
#[cfg(not(feature = "rv64"))]
pub const MONT_MUL_2048_P1_FUNCT3: u32 = 0x00;
#[cfg(not(feature = "rv64"))]
pub const MONT_MUL_2048_P1_FUNCT7: u32 = 0x02;
#[cfg(not(feature = "rv64"))]
pub const MONT_MUL_2048_P1_NAME: &str = "MONT_MUL_2048_P1";
#[cfg(not(feature = "rv64"))]
pub const MONT_MUL_2048_P2_FUNCT3: u32 = 0x00;
#[cfg(not(feature = "rv64"))]
pub const MONT_MUL_2048_P2_FUNCT7: u32 = 0x03;
#[cfg(not(feature = "rv64"))]
pub const MONT_MUL_2048_P2_NAME: &str = "MONT_MUL_2048_P2";
#[cfg(not(feature = "rv64"))]
pub const MONT_SQUARE_2048_P1_FUNCT3: u32 = 0x01;
#[cfg(not(feature = "rv64"))]
pub const MONT_SQUARE_2048_P1_FUNCT7: u32 = 0x02;
#[cfg(not(feature = "rv64"))]
pub const MONT_SQUARE_2048_P1_NAME: &str = "MONT_SQUARE_2048_P1";
#[cfg(not(feature = "rv64"))]
pub const MONT_SQUARE_2048_P2_FUNCT3: u32 = 0x01;
#[cfg(not(feature = "rv64"))]
pub const MONT_SQUARE_2048_P2_FUNCT7: u32 = 0x03;
#[cfg(not(feature = "rv64"))]
pub const MONT_SQUARE_2048_P2_NAME: &str = "MONT_SQUARE_2048_P2";
/// Split point for the outer loop (each half < 65535 virtual instructions).
#[cfg(not(feature = "rv64"))]
pub const SPLIT_AT: usize = LIMBS_2048 / 2;

#[cfg(feature = "host")]
use tracer::register_inline;

#[cfg(all(feature = "host", feature = "rv64"))]
pub fn init_inlines() -> Result<(), String> {
    register_inline(
        INLINE_OPCODE,
        MONT_MUL_2048_FUNCT3,
        MONT_MUL_2048_FUNCT7,
        MONT_MUL_2048_NAME,
        std::boxed::Box::new(mont_mul::sequence_builder::mont_mul_2048_sequence_builder),
    )?;
    register_inline(
        INLINE_OPCODE,
        MONT_SQUARE_2048_FUNCT3,
        MONT_SQUARE_2048_FUNCT7,
        MONT_SQUARE_2048_NAME,
        std::boxed::Box::new(mont_mul::sequence_builder::mont_square_2048_sequence_builder),
    )?;
    Ok(())
}

#[cfg(all(feature = "host", not(feature = "rv64")))]
pub fn init_inlines() -> Result<(), String> {
    register_inline(
        INLINE_OPCODE,
        MONT_MUL_2048_P1_FUNCT3,
        MONT_MUL_2048_P1_FUNCT7,
        MONT_MUL_2048_P1_NAME,
        std::boxed::Box::new(mont_mul::sequence_builder::mont_mul_2048_p1_sequence_builder),
    )?;
    register_inline(
        INLINE_OPCODE,
        MONT_MUL_2048_P2_FUNCT3,
        MONT_MUL_2048_P2_FUNCT7,
        MONT_MUL_2048_P2_NAME,
        std::boxed::Box::new(mont_mul::sequence_builder::mont_mul_2048_p2_sequence_builder),
    )?;
    register_inline(
        INLINE_OPCODE,
        MONT_SQUARE_2048_P1_FUNCT3,
        MONT_SQUARE_2048_P1_FUNCT7,
        MONT_SQUARE_2048_P1_NAME,
        std::boxed::Box::new(mont_mul::sequence_builder::mont_square_2048_p1_sequence_builder),
    )?;
    register_inline(
        INLINE_OPCODE,
        MONT_SQUARE_2048_P2_FUNCT3,
        MONT_SQUARE_2048_P2_FUNCT7,
        MONT_SQUARE_2048_P2_NAME,
        std::boxed::Box::new(mont_mul::sequence_builder::mont_square_2048_p2_sequence_builder),
    )?;
    Ok(())
}

#[cfg(feature = "host")]
pub fn mont_mul_2048_trace_len() -> usize {
    use tracer::emulator::cpu::Xlen;
    use tracer::utils::inline_sequence_writer::SequenceInputs;

    let inputs = SequenceInputs::new(
        tracer::utils::inline_sequence_writer::DEFAULT_RAM_START_ADDRESS,
        false,
        #[cfg(feature = "rv64")]
        Xlen::Bit64,
        #[cfg(not(feature = "rv64"))]
        Xlen::Bit32,
        tracer::utils::inline_sequence_writer::DEFAULT_RS1,
        tracer::utils::inline_sequence_writer::DEFAULT_RS2,
        tracer::utils::inline_sequence_writer::DEFAULT_RS3,
    );
    #[cfg(feature = "rv64")]
    {
        mont_mul::sequence_builder::mont_mul_2048_sequence_builder((&inputs).into(), (&inputs).into()).len()
    }
    #[cfg(not(feature = "rv64"))]
    {
        mont_mul::sequence_builder::mont_mul_2048_p1_sequence_builder((&inputs).into(), (&inputs).into()).len()
            + mont_mul::sequence_builder::mont_mul_2048_p2_sequence_builder((&inputs).into(), (&inputs).into()).len()
    }
}

#[cfg(feature = "host")]
pub fn mont_square_2048_trace_len() -> usize {
    use tracer::emulator::cpu::Xlen;
    use tracer::utils::inline_sequence_writer::SequenceInputs;

    let inputs = SequenceInputs::new(
        tracer::utils::inline_sequence_writer::DEFAULT_RAM_START_ADDRESS,
        false,
        #[cfg(feature = "rv64")]
        Xlen::Bit64,
        #[cfg(not(feature = "rv64"))]
        Xlen::Bit32,
        tracer::utils::inline_sequence_writer::DEFAULT_RS1,
        tracer::utils::inline_sequence_writer::DEFAULT_RS2,
        tracer::utils::inline_sequence_writer::DEFAULT_RS3,
    );
    #[cfg(feature = "rv64")]
    {
        mont_mul::sequence_builder::mont_square_2048_sequence_builder((&inputs).into(), (&inputs).into()).len()
    }
    #[cfg(not(feature = "rv64"))]
    {
        mont_mul::sequence_builder::mont_square_2048_p1_sequence_builder((&inputs).into(), (&inputs).into()).len()
            + mont_mul::sequence_builder::mont_square_2048_p2_sequence_builder((&inputs).into(), (&inputs).into()).len()
    }
}

#[cfg(feature = "host")]
pub fn modpow_65537_trace_len() -> usize {
    mont_mul_2048_trace_len() + 16 * mont_square_2048_trace_len() + mont_mul_2048_trace_len() + mont_mul_2048_trace_len()
}

#[cfg(all(test, feature = "host"))]
mod trace_tests {
    use super::{modpow_65537_trace_len, mont_mul_2048_trace_len, mont_square_2048_trace_len};

    #[test]
    fn test_mont_mul_trace_regression() {
        #[cfg(feature = "rv64")]
        assert!(mont_mul_2048_trace_len() <= 23_569);

        #[cfg(not(feature = "rv64"))]
        assert!(mont_mul_2048_trace_len() <= 92_188);
    }

    #[test]
    fn test_modpow_trace_regression() {
        #[cfg(feature = "rv64")]
        assert!(modpow_65537_trace_len() <= 447_811);

        #[cfg(not(feature = "rv64"))]
        assert!(modpow_65537_trace_len() <= 1_751_572);
    }

    #[test]
    fn test_square_trace_not_worse_than_mul() {
        assert!(mont_square_2048_trace_len() <= mont_mul_2048_trace_len());
    }
}

#[cfg(all(feature = "host", not(target_arch = "wasm32")))]
#[ctor::ctor]
fn auto_register() {
    if let Err(e) = init_inlines() {
        tracing::error!("Failed to register MONT_MUL_2048 inlines: {e}");
    }
}
