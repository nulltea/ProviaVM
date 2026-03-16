mod fixture;
mod sod;

use std::net::SocketAddr;
use std::path::PathBuf;

use ::guest::{
    analyze_verify_passport, build_delegate_verify_passport, build_verifier_verify_passport,
    commit_trusted_advice_verify_passport, compile_verify_passport,
    memory_config_verify_passport, preprocess_prover_verify_passport, verify_passport,
};
use ark_bn254::Fr;
use clap::Parser;
use eyre::Context;
use provia_jolt_sdk::TrustedAdvice;
use jolt_inlines_rsa::verify::parse_pkcs1_modulus;
use jolt_inlines_rsa::{
    build_rsa65537_trusted_advice_witness, modpow_65537_trace_len, mont_mul_2048_trace_len,
    mont_square_2048_trace_len, trusted_advice_witness_seed_from_commitment,
    trusted_advice_witness_seed_from_commitment_bytes, validate_rsa65537_trusted_advice_witness,
    Bytes2048, Rsa65537TrustedAdviceWitness2048,
};
use serde::Deserialize;
use tracing::info;
use tracing_forest::ForestLayer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::Registry;
use tracing_subscriber::{EnvFilter, Layer};
use zkpassport_core::{PassportInput, PassportOutput};

use provia_jolt_sdk::*;

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

    /// Generate synthetic fixture instead of loading real files.
    #[clap(long)]
    generate: bool,

    /// Directory containing dg1.bin, sod.bin, ds_pubkey.der.
    #[clap(long, default_value = "fixtures")]
    fixtures_dir: PathBuf,

    /// Today's date as YYYYMMDD (e.g. 20260315).
    #[clap(long, default_value = "20260315")]
    today: u32,

    /// Only run native verification + trace analysis (no worker delegation).
    #[clap(long)]
    native_only: bool,
}

fn init_tracing() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env_lossy()
        .add_directive("rustls=off".parse().unwrap())
        .add_directive("quinn=off".parse().unwrap())
        .add_directive("dory=off".parse().unwrap());

    let _ = tracing::subscriber::set_global_default(
        Registry::default()
            .with(env_filter)
            .with(ForestLayer::default().with_filter(LevelFilter::INFO)),
    );
}

fn load_real_fixtures(dir: &PathBuf, today: u32) -> eyre::Result<PassportInput> {
    let dg1 = std::fs::read(dir.join("dg1.bin")).context("reading dg1.bin")?;
    let sod_bytes = std::fs::read(dir.join("sod.bin")).context("reading sod.bin")?;
    let ds_pubkey_der = std::fs::read(dir.join("ds_pubkey.der")).context("reading ds_pubkey.der")?;

    let parsed = sod::parse_sod(&sod_bytes).context("parsing SOD")?;

    Ok(PassportInput {
        dg1,
        encap_content: parsed.encap_content,
        signed_attrs_der: parsed.signed_attrs_der,
        signature: parsed.signature,
        ds_pubkey_der,
        rsa_challenge_seed: [0u8; 32],
        today_yyyymmdd: today,
    })
}

fn build_witness(
    pubkey_der: &[u8],
    signature: &[u8],
) -> eyre::Result<Rsa65537TrustedAdviceWitness2048> {
    eyre::ensure!(signature.len() == 256, "signature must be 256 bytes");
    let modulus =
        parse_pkcs1_modulus(pubkey_der).ok_or_else(|| eyre::eyre!("invalid PKCS#1 DER public key"))?;
    Ok(build_rsa65537_trusted_advice_witness(
        &modulus,
        &Bytes2048(signature.try_into().context("signature length")?),
    ))
}

fn validate_witness(
    input: &PassportInput,
    witness: &Rsa65537TrustedAdviceWitness2048,
) -> eyre::Result<()> {
    let modulus = parse_pkcs1_modulus(&input.ds_pubkey_der)
        .ok_or_else(|| eyre::eyre!("invalid PKCS#1 DER public key"))?;
    let signature = Bytes2048(input.signature.as_slice().try_into().context("signature length")?);
    eyre::ensure!(
        validate_rsa65537_trusted_advice_witness(&modulus, &signature, witness),
        "invalid RSA witness relation"
    );
    Ok(())
}

fn witness_seed_for_profile(
    witness: &Rsa65537TrustedAdviceWitness2048,
) -> eyre::Result<[u8; 32]> {
    let witness_bytes = provia_jolt_sdk::postcard::to_stdvec(&TrustedAdvice::from(*witness))
        .context("serializing trusted advice witness")?;
    Ok(trusted_advice_witness_seed_from_commitment_bytes(&witness_bytes))
}

fn main() -> eyre::Result<()> {
    init_tracing();

    let args = Args::parse();

    // Build PassportInput from either synthetic or real fixtures
    let mut input = if args.generate {
        info!("generating synthetic fixture");
        fixture::generate_fixture(b"000315", args.today)
    } else {
        info!(dir = ?args.fixtures_dir, "loading real fixtures");
        load_real_fixtures(&args.fixtures_dir, args.today)?
    };

    info!(
        dg1_len = input.dg1.len(),
        encap_len = input.encap_content.len(),
        signed_attrs_len = input.signed_attrs_der.len(),
        sig_len = input.signature.len(),
        pubkey_len = input.ds_pubkey_der.len(),
        "prepared PassportInput"
    );

    // Build RSA trusted-advice witness
    let witness = build_witness(&input.ds_pubkey_der, &input.signature)?;
    validate_witness(&input, &witness)?;
    info!("RSA trusted-advice witness built and validated");

    // Set challenge seed for profile/native mode
    input.rsa_challenge_seed = witness_seed_for_profile(&witness)?;

    // Native execution
    let native_output: PassportOutput =
        verify_passport(TrustedAdvice::from(witness), input.clone());
    info!(?native_output, "native verification result");

    // Trace analysis
    println!("arch: {}", if cfg!(feature = "rv64") { "rv64" } else { "rv32" });
    println!("mont_mul_2048 trace length: {}", mont_mul_2048_trace_len());
    println!("mont_square_2048 trace length: {}", mont_square_2048_trace_len());
    println!("modpow_65537 trace length: {}", modpow_65537_trace_len());
    let summary = analyze_verify_passport(TrustedAdvice::from(witness), input.clone());
    let raw_trace_len = summary.trace_len();
    let padded_trace_len = raw_trace_len.next_power_of_two();
    println!("verify_passport raw trace length: {}", raw_trace_len);
    println!("verify_passport padded trace length: {}", padded_trace_len);

    if args.native_only {
        info!("native-only mode, skipping proof delegation");
        return Ok(());
    }

    // Read delegator config
    let config: DelegatorConfig =
        toml::from_str(&std::fs::read_to_string(&args.config_path).context("reading config")?)
            .context("parsing config")?;

    let addrs: Vec<SocketAddr> = config
        .workers
        .iter()
        .map(|s| s.trim().parse::<SocketAddr>())
        .collect::<Result<_, _>>()
        .context("parsing worker addresses")?;
    let worker_addrs: [SocketAddr; 3] = addrs
        .try_into()
        .map_err(|v: Vec<_>| eyre::eyre!("expected 3 worker addresses, got {}", v.len()))?;

    // Compile guest program
    let target_dir = "/tmp/jolt-guest-targets";
    let mut preprocessing_program = compile_verify_passport(target_dir);
    let prover_preprocessing = preprocess_prover_verify_passport(&mut preprocessing_program);

    // Get seed from proof commitment
    let (trusted_commitment, _trusted_hint) =
        commit_trusted_advice_verify_passport(TrustedAdvice::from(witness), &prover_preprocessing);
    let trusted_commitment =
        trusted_commitment.ok_or_else(|| eyre::eyre!("missing trusted advice commitment"))?;
    input.rsa_challenge_seed =
        trusted_advice_witness_seed_from_commitment(&trusted_commitment)
            .context("serializing trusted advice commitment")?;

    let delegate = build_delegate_verify_passport(compile_verify_passport(target_dir));

    // Connect to workers
    info!(?worker_addrs, "connecting to workers");
    let mut client = Client::connect(worker_addrs)?;
    info!("connected to all 3 workers");

    // Delegate proof
    info!("delegating proof...");
    let program_id = "zkpassport-verify";
    let (output, proof, program_io) =
        delegate(&mut client, TrustedAdvice::from(witness), input, program_id)?;
    info!(trace_length = proof.trace_length, "proof received");

    // Verify the proof
    let (bytecode, memory_init, program_size) = preprocessing_program.decode();
    let mut memory_config = memory_config_verify_passport();
    memory_config.program_size = Some(program_size);
    let memory_layout = MemoryLayout::new(&memory_config);
    let prover_preprocessing: JoltProverPreprocessing<F, PCS> =
        JoltRVArch::prover_preprocess(bytecode, memory_layout, memory_init, proof.trace_length);
    let verifier =
        build_verifier_verify_passport(JoltVerifierPreprocessing::from(&prover_preprocessing));
    info!("verifying proof...");
    let is_valid = verifier(output.clone(), program_io.panic, proof);

    if !is_valid {
        return Err(eyre::eyre!("proof verification failed"));
    }
    if output != native_output {
        return Err(eyre::eyre!("output mismatch with native execution"));
    }

    info!(
        passive_auth = output.passive_auth_valid,
        over_18 = output.over_18,
        country = ?core::str::from_utf8(&output.issuing_country),
        "proof verified successfully!"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_native(input: &PassportInput) -> PassportOutput {
        let witness = build_witness(&input.ds_pubkey_der, &input.signature).unwrap();
        let mut input = input.clone();
        input.rsa_challenge_seed = witness_seed_for_profile(&witness).unwrap();
        verify_passport(TrustedAdvice::from(witness), input)
    }

    #[test]
    fn test_native_end_to_end_synthetic() {
        let input = fixture::generate_fixture(b"000315", 20260315);
        let output = run_native(&input);

        assert!(output.passive_auth_valid);
        assert!(output.over_18);
        assert_eq!(&output.issuing_country, b"UTO");
    }

    #[test]
    fn test_native_minor_rejected() {
        let input = fixture::generate_fixture(b"150101", 20260315);
        let output = run_native(&input);

        assert!(output.passive_auth_valid);
        assert!(!output.over_18);
    }

    #[test]
    fn test_native_exactly_18() {
        let input = fixture::generate_fixture(b"080315", 20260315);
        let output = run_native(&input);

        assert!(output.passive_auth_valid);
        assert!(output.over_18);
    }

    #[test]
    #[should_panic(expected = "DG1 hash not found")]
    fn test_tampered_dg1_rejected() {
        let mut input = fixture::generate_fixture(b"000315", 20260315);
        if let Some(b) = input.dg1.last_mut() {
            *b ^= 0xFF;
        }
        let _ = run_native(&input);
    }

    #[test]
    #[should_panic(expected = "SOD signature verification failed")]
    fn test_tampered_signature_rejected() {
        let mut input = fixture::generate_fixture(b"000315", 20260315);
        if let Some(b) = input.signature.last_mut() {
            *b ^= 0xFF;
        }
        let _ = run_native(&input);
    }

    #[test]
    #[ignore] // Run manually: cargo test save_test_fixture -- --ignored
    fn save_test_fixture() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha12Rng;

        let mut rng = ChaCha12Rng::seed_from_u64(42);
        let input = fixture::generate_fixture_with_rng(b"000315", 20260315, &mut rng);

        // Verify the fixture works
        let output = run_native(&input);
        assert!(output.passive_auth_valid);
        assert!(output.over_18);

        // Save to test-passport directory
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-passport");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("dg1.bin"), &input.dg1).unwrap();
        std::fs::write(dir.join("encap_content.bin"), &input.encap_content).unwrap();
        std::fs::write(dir.join("signed_attrs.bin"), &input.signed_attrs_der).unwrap();
        std::fs::write(dir.join("signature.bin"), &input.signature).unwrap();
        std::fs::write(dir.join("ds_pubkey.der"), &input.ds_pubkey_der).unwrap();

        // Also save the full PassportInput as postcard for easy loading
        let serialized = postcard::to_stdvec(&input).unwrap();
        std::fs::write(dir.join("passport_input.postcard"), &serialized).unwrap();

        eprintln!("Saved test fixture to {:?}", dir);
        eprintln!("  dg1.bin: {} bytes", input.dg1.len());
        eprintln!("  encap_content.bin: {} bytes", input.encap_content.len());
        eprintln!("  signed_attrs.bin: {} bytes", input.signed_attrs_der.len());
        eprintln!("  signature.bin: {} bytes", input.signature.len());
        eprintln!("  ds_pubkey.der: {} bytes", input.ds_pubkey_der.len());
        eprintln!("  passport_input.postcard: {} bytes", serialized.len());
    }
}
