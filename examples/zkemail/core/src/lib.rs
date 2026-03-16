#![no_std]
extern crate alloc;

use alloc::vec::Vec;
pub use jolt_inlines_rsa::{Bytes2048, Rsa65537Witness2048, RsaModStepWitness2048, RsaStepOp};
use serde::{Deserialize, Serialize};

/// Pre-parsed DKIM verification input.
/// The host extracts these from the raw email + DNS lookup.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DKIMInput {
    /// Canonicalized DKIM-signed header bytes (the data that was signed)
    pub signed_headers: Vec<u8>,
    /// RSA signature bytes (base64-decoded from b= tag)
    pub signature: Vec<u8>,
    /// RSA public key in PKCS#1 DER format, from DNS TXT record
    pub public_key_der: Vec<u8>,
    /// Sender domain as bytes (e.g., b"google.com")
    pub from_domain: Vec<u8>,
    /// Transcript-bound seed for RSA witness compression checks.
    pub rsa_challenge_seed: [u8; 32],
}

/// Output committed by the guest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKIMOutput {
    /// SHA-256 hash of from_domain
    pub from_domain_hash: [u8; 32],
    /// SHA-256 hash of the public key DER bytes
    pub public_key_hash: [u8; 32],
    /// Whether the DKIM signature verified
    pub verified: bool,
}
