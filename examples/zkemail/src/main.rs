use std::net::SocketAddr;
use std::path::PathBuf;

use ::guest::{
    analyze_verify_dkim, build_delegate_verify_dkim, commit_trusted_advice_verify_dkim, compile_verify_dkim,
    memory_config_verify_dkim, preprocess_prover_verify_dkim, verify_dkim,
};
use ark_serialize::CanonicalSerialize;
use ark_bn254::Fr;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use cfdkim::{dns::from_tokio_resolver, public_key::retrieve_public_key};
use clap::Parser;
use eyre::Context;
use mailparse::MailHeaderMap;
use num_bigint::BigUint;
use serde::Deserialize;
use slog::{o, Discard, Logger};
use tracing::info;
use tracing_forest::ForestLayer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::Registry;
use tracing_subscriber::{EnvFilter, Layer};
use trust_dns_resolver::TokioAsyncResolver;
use zkemail_core::{DKIMInput, DKIMOutput, Rsa65537Witness2048, RsaModStepWitness2048, RsaStepOp};

use provia_jolt_sdk::*;
use jolt_inlines_rsa::{
    mont_mul_2048_trace_len,
    mont_square_2048_trace_len,
    modpow_65537_trace_len,
};
use jolt_inlines_rsa::verify::{limbs_to_bytes_be_2048, parse_pkcs1_modulus};
use jolt_inlines_sha2::Sha256;

type F = Fr;
type PCS = provia_jolt_sdk::PCS;

#[derive(Deserialize)]
struct DelegatorConfig {
    workers: Vec<String>,
}

#[derive(Parser)]
struct Args {
    /// Path to delegator config TOML.
    #[clap(long, default_value = ".artifacts/config_delegator.toml")]
    config_path: PathBuf,

    /// Path to the .eml file
    #[clap(long)]
    email_path: PathBuf,

    /// Expected sender domain (e.g., "google.com")
    #[clap(long)]
    from_domain: String,

    /// Print RSA kernel and full guest trace lengths, then exit.
    #[clap(long)]
    profile_rsa: bool,
}

fn init_tracing() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env_lossy()
        .add_directive("rustls=off".parse().unwrap())
        .add_directive("quinn=off".parse().unwrap())
        .add_directive("dory=off".parse().unwrap());

    let _ = tracing::subscriber::set_global_default(
        Registry::default().with(env_filter).with(ForestLayer::default().with_filter(LevelFilter::INFO)),
    );
}

/// Extract the value of a DKIM tag (e.g., "s", "d", "b", "h", "c", "a") from a DKIM-Signature header value.
fn get_dkim_tag(header_value: &str, tag: &str) -> Option<String> {
    let prefix = format!("{}=", tag);
    for part in header_value.split(';') {
        let trimmed = part.trim();
        if trimmed.starts_with(&prefix) {
            return Some(trimmed[prefix.len()..].trim().to_string());
        }
    }
    None
}

/// Perform relaxed header canonicalization per RFC 6376 Section 3.4.2:
/// - Convert header name to lowercase
/// - Unfold header continuation lines
/// - Reduce sequences of WSP to a single SP
/// - Strip trailing WSP before CRLF
fn canonicalize_header_relaxed(name: &str, value: &str) -> String {
    let lowered_name = name.to_lowercase();
    // Unfold: remove CRLF followed by WSP
    let unfolded = value.replace("\r\n", "").replace('\n', "");
    // Reduce runs of whitespace to a single space, trim leading/trailing
    let reduced: String = unfolded.split_whitespace().collect::<Vec<_>>().join(" ");
    format!("{}:{}", lowered_name, reduced)
}

/// Build the canonicalized header block that was signed by DKIM.
/// Returns the bytes that the RSA signature covers.
fn build_signed_headers(raw_email: &[u8], dkim_header_value: &str, signed_header_names: &str) -> eyre::Result<Vec<u8>> {
    let parsed = mailparse::parse_mail(raw_email)?;

    let header_names: Vec<&str> = signed_header_names.split(':').map(|s| s.trim()).collect();

    let mut lines = Vec::new();
    for name in &header_names {
        let name_lower = name.to_lowercase();
        if let Some(header) = parsed.headers.iter().find(|h| h.get_key().to_lowercase() == name_lower) {
            lines.push(canonicalize_header_relaxed(&header.get_key(), &header.get_value()));
        }
    }

    // Append the DKIM-Signature header itself with the b= value emptied
    let dkim_no_sig = remove_b_value(dkim_header_value);
    lines.push(canonicalize_header_relaxed("dkim-signature", &dkim_no_sig));

    // Join with CRLF; the final header does NOT get a trailing CRLF
    let result = lines.join("\r\n");
    Ok(result.into_bytes())
}

/// Remove the b= tag value from a DKIM-Signature header value,
/// leaving "b=" with an empty value.
fn remove_b_value(header_value: &str) -> String {
    let mut result = String::new();
    let mut in_b_tag = false;
    for part in header_value.split(';') {
        if !result.is_empty() {
            result.push(';');
        }
        let trimmed = part.trim();
        if trimmed.starts_with("b=") && !trimmed.starts_with("bh=") {
            // Keep "b=" but empty the value
            result.push_str(" b=");
            in_b_tag = true;
        } else {
            in_b_tag = false;
            result.push_str(part);
        }
    }
    let _ = in_b_tag;
    result
}

/// Prepare DKIM input by parsing the email, looking up DNS, and extracting
/// the canonicalized signed headers + RSA public key + signature.
fn left_pad_be_256(bytes: &[u8]) -> eyre::Result<[u8; 256]> {
    eyre::ensure!(bytes.len() <= 256, "integer exceeds 2048 bits");
    let mut out = [0u8; 256];
    let start = 256 - bytes.len();
    out[start..].copy_from_slice(bytes);
    Ok(out)
}

fn build_rsa_witness(public_key_der: &[u8], signature: &[u8]) -> eyre::Result<Rsa65537Witness2048> {
    eyre::ensure!(signature.len() == 256, "signature must be 256 bytes");

    let modulus = parse_pkcs1_modulus(public_key_der).ok_or_else(|| eyre::eyre!("invalid PKCS#1 DER public key"))?;
    let modulus_be = limbs_to_bytes_be_2048(&modulus);
    let modulus_bn = BigUint::from_bytes_be(&modulus_be);
    let signature_be: [u8; 256] = signature.try_into().context("signature length")?;
    let signature_bn = BigUint::from_bytes_be(&signature_be);

    let mut witness = Rsa65537Witness2048 {
        modulus_be: modulus_be.to_vec(),
        signature_be: signature_be.to_vec(),
        steps: vec![
            RsaModStepWitness2048 {
                op: RsaStepOp::Square,
                quotient_be: vec![0u8; 256],
                remainder_be: vec![0u8; 256],
            };
            17
        ],
    };

    let mut current = signature_bn.clone();
    for step_idx in 0..witness.steps.len() {
        let (lhs, rhs, op) = if step_idx < 16 {
            (&current, &current, RsaStepOp::Square)
        } else {
            (&current, &signature_bn, RsaStepOp::MulBase)
        };
        let product = lhs * rhs;
        let quotient = &product / &modulus_bn;
        let remainder = &product % &modulus_bn;
        witness.steps[step_idx] = RsaModStepWitness2048 {
            op,
            quotient_be: left_pad_be_256(&quotient.to_bytes_be())
                .expect("quotient fits in 2048 bits")
                .to_vec(),
            remainder_be: left_pad_be_256(&remainder.to_bytes_be())
                .expect("remainder fits in 2048 bits")
                .to_vec(),
        };
        current = remainder;
    }

    Ok(witness)
}

fn rsa_challenge_seed_from_commitment(commitment: &<PCS as CommitmentScheme>::Commitment) -> eyre::Result<[u8; 32]> {
    let mut commitment_bytes = Vec::new();
    commitment
        .serialize_compressed(&mut commitment_bytes)
        .context("serializing trusted advice commitment")?;
    let mut seed_input = b"zkemail-rsa-challenge-v1".to_vec();
    seed_input.extend_from_slice(&commitment_bytes);
    Ok(Sha256::digest(&seed_input))
}

fn validate_rsa_witness(input: &DKIMInput, witness: &Rsa65537Witness2048) -> eyre::Result<()> {
    let modulus = parse_pkcs1_modulus(&input.public_key_der).ok_or_else(|| eyre::eyre!("invalid PKCS#1 DER public key"))?;
    let modulus_be = limbs_to_bytes_be_2048(&modulus);
    eyre::ensure!(modulus_be.as_slice() == witness.modulus_be.as_slice(), "witness modulus mismatch");
    let signature_be: [u8; 256] = input.signature.as_slice().try_into().context("signature length")?;
    eyre::ensure!(signature_be.as_slice() == witness.signature_be.as_slice(), "witness signature mismatch");
    eyre::ensure!(witness.steps.len() == 17, "expected 17 RSA witness steps");

    let modulus_bn = BigUint::from_bytes_be(&witness.modulus_be);
    let signature_bn = BigUint::from_bytes_be(&witness.signature_be);
    let mut current = signature_bn.clone();
    for (step_idx, step) in witness.steps.iter().enumerate() {
        let expected_op = if step_idx < 16 { RsaStepOp::Square } else { RsaStepOp::MulBase };
        eyre::ensure!(step.op == expected_op, "unexpected RSA witness op at step {step_idx}");
        let rhs = if step_idx < 16 { &current } else { &signature_bn };
        let quotient = BigUint::from_bytes_be(&step.quotient_be);
        let remainder = BigUint::from_bytes_be(&step.remainder_be);
        eyre::ensure!(remainder < modulus_bn, "witness remainder out of range at step {step_idx}");
        eyre::ensure!(
            &current * rhs == &quotient * &modulus_bn + &remainder,
            "invalid modular witness relation at step {step_idx}",
        );
        current = remainder;
    }

    Ok(())
}

fn print_profile_summary(input: DKIMInput, witness: Rsa65537Witness2048) {
    let summary = analyze_verify_dkim(TrustedAdvice::from(witness), input);
    println!("arch: {}", if cfg!(feature = "rv64") { "rv64" } else { "rv32" });
    println!("mont_mul_2048 trace length: {}", mont_mul_2048_trace_len());
    println!("mont_square_2048 trace length: {}", mont_square_2048_trace_len());
    println!("modpow_65537 trace length: {}", modpow_65537_trace_len());
    println!("verify_dkim trace length: {}", summary.trace_len());
}

async fn prepare_dkim_input(email_path: &PathBuf, from_domain: &str) -> eyre::Result<(DKIMInput, Rsa65537Witness2048)> {
    let logger = Logger::root(Discard, o!());
    let raw_email = std::fs::read(email_path).context("reading email file")?;
    let parsed = mailparse::parse_mail(&raw_email).map_err(|e| eyre::eyre!("parse email: {}", e))?;

    // Find DKIM-Signature header for the target domain
    let dkim_headers = parsed.headers.get_all_headers("DKIM-Signature");
    if dkim_headers.is_empty() {
        return Err(eyre::eyre!("no DKIM-Signature headers found"));
    }

    let resolver = TokioAsyncResolver::tokio_from_system_conf().map_err(|e| eyre::eyre!("DNS resolver init: {}", e))?;
    let cfdkim_resolver = from_tokio_resolver(resolver);

    let mut found_header_value = None;
    let mut found_public_key_der = None;

    for header in &dkim_headers {
        let header_value = String::from_utf8_lossy(header.get_value_raw()).to_string();

        let d = match get_dkim_tag(&header_value, "d") {
            Some(d) => d,
            None => continue,
        };
        if d.to_lowercase() != from_domain.to_lowercase() {
            continue;
        }

        let algo = match get_dkim_tag(&header_value, "a") {
            Some(a) => a,
            None => continue,
        };
        if !algo.starts_with("rsa-") {
            continue;
        }

        let selector = match get_dkim_tag(&header_value, "s") {
            Some(s) => s,
            None => continue,
        };
        match retrieve_public_key(&logger, cfdkim_resolver.clone(), from_domain.to_string(), selector).await {
            Ok(pk) => {
                found_public_key_der = Some(pk.to_vec() as Vec<u8>);
                found_header_value = Some(header_value);
                break;
            }
            Err(e) => {
                info!(error = %e, "retrieve_public_key failed");
                continue;
            }
        }
    }

    let header_value = found_header_value.ok_or_else(|| eyre::eyre!("no matching DKIM header found"))?;
    let public_key_der = found_public_key_der.ok_or_else(|| eyre::eyre!("no public key retrieved"))?;

    // Extract signature bytes from b= tag
    let b_value = get_dkim_tag(&header_value, "b").ok_or_else(|| eyre::eyre!("missing b= tag"))?;
    let b_clean: String = b_value.chars().filter(|c| !c.is_whitespace()).collect();
    let signature = BASE64.decode(&b_clean).context("base64 decode DKIM signature")?;

    // Extract signed header names from h= tag
    let h_value = get_dkim_tag(&header_value, "h").ok_or_else(|| eyre::eyre!("missing h= tag"))?;

    // Build canonicalized signed headers
    let signed_headers = build_signed_headers(&raw_email, &header_value, &h_value)?;

    info!(
        domain = from_domain,
        signed_headers_len = signed_headers.len(),
        signature_len = signature.len(),
        public_key_len = public_key_der.len(),
        "prepared DKIM input"
    );

    let input = DKIMInput {
        signed_headers,
        signature,
        public_key_der,
        from_domain: from_domain.as_bytes().to_vec(),
        rsa_challenge_seed: [0u8; 32],
    };
    let witness = build_rsa_witness(&input.public_key_der, &input.signature)?;
    validate_rsa_witness(&input, &witness)?;

    Ok((
        input,
        witness,
    ))
}

fn main() -> eyre::Result<()> {
    init_tracing();

    let args = Args::parse();

    let target_dir = "/tmp/jolt-guest-targets";
    let mut preprocessing_program = compile_verify_dkim(target_dir);
    let prover_preprocessing = preprocess_prover_verify_dkim(&mut preprocessing_program);

    let rt = tokio::runtime::Runtime::new()?;
    let (mut dkim_input, rsa_witness) = rt.block_on(prepare_dkim_input(&args.email_path, &args.from_domain))?;
    let (trusted_commitment, _trusted_hint) =
        commit_trusted_advice_verify_dkim(TrustedAdvice::from(rsa_witness.clone()), &prover_preprocessing);
    let trusted_commitment = trusted_commitment.ok_or_else(|| eyre::eyre!("missing trusted advice commitment"))?;
    dkim_input.rsa_challenge_seed = rsa_challenge_seed_from_commitment(&trusted_commitment)?;

    if args.profile_rsa {
        print_profile_summary(dkim_input, rsa_witness);
        return Ok(());
    }

    let config: DelegatorConfig =
        toml::from_str(&std::fs::read_to_string(&args.config_path).context("reading config")?)
            .context("parsing config")?;

    // Parse worker addresses
    let addrs: Vec<SocketAddr> = config
        .workers
        .iter()
        .map(|s| s.trim().parse::<SocketAddr>())
        .collect::<Result<_, _>>()
        .context("parsing worker addresses")?;
    let worker_addrs: [SocketAddr; 3] =
        addrs.try_into().map_err(|v: Vec<_>| eyre::eyre!("expected 3 worker addresses, got {}", v.len()))?;

    // Compile guest program (before connecting so failures don't drop worker connections)
    let delegate = build_delegate_verify_dkim(compile_verify_dkim(target_dir));

    // Native execution
    let native_output: DKIMOutput = verify_dkim(TrustedAdvice::from(rsa_witness.clone()), dkim_input.clone());
    info!(?native_output, "native DKIM verification result");

    // Connect to workers
    info!(?worker_addrs, "connecting to workers");
    let mut client = Client::connect(worker_addrs)?;
    info!("connected to all 3 workers");

    // Delegate proof to workers
    info!("delegating proof...");
    let program_id = "zkemail-verify";
    let rsa_challenge_seed = dkim_input.rsa_challenge_seed;
    let (output, proof, program_io) =
        delegate(&mut client, TrustedAdvice::from(rsa_witness), dkim_input, program_id)?;
    info!(trace_length = proof.trace_length, "proof received");

    // Verify the proof
    let proof_commitment = proof
        .trusted_advice_commitment
        .as_ref()
        .ok_or_else(|| eyre::eyre!("proof missing trusted advice commitment"))?;
    let proof_seed = rsa_challenge_seed_from_commitment(proof_commitment)?;
    if proof_seed != rsa_challenge_seed {
        return Err(eyre::eyre!("RSA challenge seed mismatch for trusted advice commitment"));
    }

    let (bytecode, memory_init, program_size) = preprocessing_program.decode();
    let mut memory_config = memory_config_verify_dkim();
    memory_config.program_size = Some(program_size);
    let memory_layout = MemoryLayout::new(&memory_config);
    let verifier_preprocessing = JoltVerifierPreprocessing::from(&JoltRVArch::prover_preprocess(
        bytecode,
        memory_layout,
        memory_init,
        proof.trace_length,
    ));
    info!("verifying proof...");
    let is_valid = JoltRVArch::verify(&verifier_preprocessing, proof, program_io, None, None).is_ok();

    if !is_valid {
        return Err(eyre::eyre!("proof verification failed"));
    }
    if output != native_output {
        return Err(eyre::eyre!("output mismatch with native execution"));
    }

    info!(verified = output.verified, "proof verified successfully!");
    Ok(())
}
