pub const INLINE_OPCODE: u32 = 0x0B;

pub const BIGINT256_MUL_FUNCT3: u32 = 0x00;
pub const BIGINT256_MUL_FUNCT7: u32 = 0x04;
pub const BIGINT256_MUL_NAME: &str = "BIGINT256_MUL_INLINE";

/// Number of limbs per 256-bit operand.
#[cfg(feature = "rv64")]
pub const INPUT_LIMBS: usize = 4; // 256 / 64
#[cfg(not(feature = "rv64"))]
pub const INPUT_LIMBS: usize = 8; // 256 / 32

/// Number of limbs in the 512-bit result.
pub const OUTPUT_LIMBS: usize = 2 * INPUT_LIMBS;

/// Byte size of a single limb.
#[cfg(feature = "rv64")]
pub const LIMB_BYTES: usize = 8;
#[cfg(not(feature = "rv64"))]
pub const LIMB_BYTES: usize = 4;

pub mod sdk;
pub use sdk::*;

#[cfg(feature = "host")]
pub mod exec;
#[cfg(feature = "host")]
pub mod sequence_builder;

#[cfg(all(test, feature = "host"))]
pub mod test_utils;
#[cfg(all(test, feature = "host"))]
pub mod tests;
