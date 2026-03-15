//! RSA inline implementations for Jolt VM.
//!
//! Provides a Montgomery multiplication inline for 2048-bit integers,
//! enabling efficient RSA signature verification in zkVM guests.

#![cfg_attr(not(feature = "host"), no_std)]

extern crate alloc;

pub mod mont_mul;
pub mod modpow;
pub mod verify;

pub use mont_mul::sdk::{mont_mul_2048, MontContext2048};

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
pub const MONT_MUL_2048_FUNCT3: u32 = 0x01;
pub const MONT_MUL_2048_FUNCT7: u32 = 0x00;
pub const MONT_MUL_2048_NAME: &str = "MONT_MUL_2048_INLINE";

#[cfg(feature = "host")]
use tracer::register_inline;

#[cfg(feature = "host")]
pub fn init_inlines() -> Result<(), String> {
    register_inline(
        INLINE_OPCODE,
        MONT_MUL_2048_FUNCT3,
        MONT_MUL_2048_FUNCT7,
        MONT_MUL_2048_NAME,
        std::boxed::Box::new(mont_mul::sequence_builder::mont_mul_2048_sequence_builder),
    )?;
    Ok(())
}

#[cfg(all(feature = "host", not(target_arch = "wasm32")))]
#[ctor::ctor]
fn auto_register() {
    if let Err(e) = init_inlines() {
        tracing::error!("Failed to register MONT_MUL_2048 inlines: {e}");
    }
}
