use std::collections::HashMap;

use rustls::pki_types::CertificateDer;

/// Policy for verifying NSM attestation documents from the enclave.
pub enum AttestationPolicy {
    /// Accept any (or no) attestation — for local dev and fystack simulation.
    AcceptAll,
    /// Verify against AWS Nitro root of trust + expected PCR values.
    #[allow(dead_code)]
    AwsNitro { expected_pcrs: HashMap<usize, Vec<u8>> },
}

/// Verify an attestation document against the given policy.
///
/// - `doc_bytes`: raw attestation document bytes received from the enclave
///   (empty slice if no attestation was provided)
/// - `tls_cert`: the TLS certificate presented by the enclave during handshake
/// - `policy`: determines what level of verification to perform
pub fn verify_attestation(
    _doc_bytes: &[u8],
    _tls_cert: &CertificateDer,
    policy: &AttestationPolicy,
) -> eyre::Result<()> {
    match policy {
        AttestationPolicy::AcceptAll => Ok(()),
        AttestationPolicy::AwsNitro { expected_pcrs: _ } => {
            // TODO: implement AWS Nitro attestation verification
            Err(eyre::eyre!("AwsNitro attestation verification not yet implemented"))
        }
    }
}
