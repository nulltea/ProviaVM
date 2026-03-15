mod fixture;
mod sod;

use std::net::SocketAddr;
use std::path::PathBuf;

use ::guest::{
    build_delegate_verify_passport, build_verifier_verify_passport, compile_verify_passport,
    memory_config_verify_passport, verify_passport,
};
use ark_bn254::Fr;
use clap::Parser;
use eyre::Context;
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

    /// Only run native verification (no worker delegation).
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
        today_yyyymmdd: today,
    })
}

fn main() -> eyre::Result<()> {
    init_tracing();

    let args = Args::parse();

    // Build PassportInput from either synthetic or real fixtures
    let input = if args.generate {
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

    // Native execution
    let native_output: PassportOutput = verify_passport(input.clone());
    info!(?native_output, "native verification result");

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
    let delegate = build_delegate_verify_passport(compile_verify_passport(target_dir));

    // Connect to workers
    info!(?worker_addrs, "connecting to workers");
    let mut client = Client::connect(worker_addrs)?;
    info!("connected to all 3 workers");

    // Delegate proof
    info!("delegating proof...");
    let program_id = "zkpassport-verify";
    let (output, proof, program_io) = delegate(&mut client, input, program_id)?;
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

    #[test]
    fn test_native_end_to_end_synthetic() {
        let input = fixture::generate_fixture(b"000315", 20260315);
        let output = verify_passport(input);

        assert!(output.passive_auth_valid);
        assert!(output.over_18);
        assert_eq!(&output.issuing_country, b"UTO");
    }

    #[test]
    fn test_native_minor_rejected() {
        // Born 2015-01-01 → age 11 on 2026-03-15
        let input = fixture::generate_fixture(b"150101", 20260315);
        let output = verify_passport(input);

        assert!(output.passive_auth_valid);
        assert!(!output.over_18);
    }

    #[test]
    fn test_native_exactly_18() {
        // Born 2008-03-15 → exactly 18 on 2026-03-15
        let input = fixture::generate_fixture(b"080315", 20260315);
        let output = verify_passport(input);

        assert!(output.passive_auth_valid);
        assert!(output.over_18);
    }

    #[test]
    #[should_panic(expected = "DG1 hash not found")]
    fn test_tampered_dg1_rejected() {
        let mut input = fixture::generate_fixture(b"000315", 20260315);
        // Tamper with DG1
        if let Some(b) = input.dg1.last_mut() {
            *b ^= 0xFF;
        }
        let _ = verify_passport(input);
    }

    #[test]
    #[should_panic(expected = "SOD signature verification failed")]
    fn test_tampered_signature_rejected() {
        let mut input = fixture::generate_fixture(b"000315", 20260315);
        // Tamper with signature
        if let Some(b) = input.signature.last_mut() {
            *b ^= 0xFF;
        }
        let _ = verify_passport(input);
    }
}
