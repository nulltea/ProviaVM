// Ensure inline #[ctor] registers sequence builders.
use jolt_inlines_sha2 as _;
use jolt_inlines_bigint as _;
use jolt_inlines_rsa as _;
use provia_jolt_sdk::TrustedAdvice;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use ark_bn254::Fr;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use sha2::Digest;

use provia_worker::host::program::generate_trace_shares;
use provia_worker::utils::test_utils::run_rep3_local_test_with_coordinator;
use provia_worker::utils::tracing::init_tracing;
use provia_worker::zkvm::state_manager::StateManagerWorker;
use provia_worker::zkvm::worker::Rep3JoltDagWorker;
use provia_worker::zkvm::instruction::Rep3Cycle;
use provia_worker::zkvm::{JoltArch, Rep3JoltWorker};
use provia_coordinator::zkvm::coordinator::Rep3JoltDag;
use provia_coordinator::zkvm::state_manager::StateManager;

use jolt_core::curve::Bn254Curve;
use jolt_core::field::JoltField;
use jolt_core::host::Program;
use jolt_core::poly::commitment::dory::{DoryCommitmentScheme, DoryGlobals};
use jolt_core::poly::commitment::commitment_scheme::CommitmentScheme;
use jolt_core::transcripts::Blake2bTranscript;
use jolt_core::zkvm::verifier::JoltDAG;
use jolt_core::zkvm::proof_serialization::JoltProof;
use jolt_core::zkvm::state_manager::StateManager as VanillaStateManager;
use jolt_core::zkvm::state_manager::{ProofData, ProofKeys};
use jolt_core::zkvm::witness::DTH_ROOT_OF_K;
use jolt_core::zkvm::{JoltProverPreprocessing, JoltRV64IMAC, JoltVerifierPreprocessing};
use tracer::JoltDevice;
use zkemail_core::{DKIMInput, Rsa65537Witness2048};
use jolt_inlines_rsa::{
    build_rsa65537_witness,
    challenge_seed_from_commitment_bytes,
    Bytes2048,
};

type F = Fr;
type PCS = DoryCommitmentScheme;
type FS = Blake2bTranscript;

struct DagFixture {
    proof: JoltProof<F, Bn254Curve, PCS, FS>,
    verifier_preprocessing: JoltVerifierPreprocessing<F, PCS>,
    io_device: tracer::JoltDevice,
    ram_k: usize,
}

fn dag_test_lock() -> MutexGuard<'static, ()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

fn use_sha2_fixture() -> bool {
    matches!(std::env::var("TEST_SHA2").ok().as_deref().or(std::env::var("SHA2_CHAIN").ok().as_deref()), Some("1"))
}

fn use_zkemail_fixture() -> bool {
    matches!(std::env::var("TEST_ZKEMAIL").ok().as_deref(), Some("1"))
}

fn build_program() -> Program {
    if use_zkemail_fixture() {
        configure_zkemail_program()
    } else if use_sha2_fixture() {
        let mut program = Program::new("sha2-chain-guest");
        program.set_stack_size(65536);
        program.set_memory_size(10240);
        program
    } else {
        let mut program = Program::new("fibonacci-guest");
        program.set_memory_size(10240);
        program
    }
}

/// Returns (public_inputs, untrusted_advice, trusted_advice).
fn build_inputs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    if use_zkemail_fixture() {
        let (input, prepared) = build_zkemail_fixture();
        (
            vec![],
            postcard::to_stdvec(&input).unwrap(),
            postcard::to_stdvec(&TrustedAdvice::from(prepared)).unwrap(),
        )
    } else if use_sha2_fixture() {
        let mut advice = postcard::to_stdvec(&[5u8; 32]).unwrap();
        advice.append(&mut postcard::to_stdvec(&1u32).unwrap());
        (vec![], advice, vec![])
    } else {
        (postcard::to_stdvec(&9u32).unwrap(), vec![], vec![])
    }
}

fn challenge_seed_from_witness(witness: &Rsa65537Witness2048) -> [u8; 32] {
    let witness_bytes = postcard::to_stdvec(witness).unwrap();
    challenge_seed_from_commitment_bytes(&witness_bytes)
}

/// Build a synthetic DKIMInput with a valid RSA-2048 PKCS#1v15-SHA256 signature.
fn build_zkemail_fixture() -> (DKIMInput, Rsa65537Witness2048) {
    use jolt_inlines_rsa::verify::{parse_pkcs1_modulus, verify_pkcs1v15_sha256_encoded};
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use sha2::Digest;

    let mut rng = ChaCha12Rng::seed_from_u64(42);
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = rsa::RsaPublicKey::from(&private_key);
    let signed_headers = b"from:test@example.com\r\nto:bob@example.com\r\n".to_vec();
    let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key);
    let signature_obj = signing_key.sign(&signed_headers);
    let signature = signature_obj.to_vec();
    let public_key_der = public_key.to_pkcs1_der().unwrap().to_vec();

    let mut input = DKIMInput {
        signed_headers,
        signature,
        public_key_der,
        from_domain: b"example.com".to_vec(),
        rsa_challenge_seed: [0u8; 32],
    };

    let modulus = parse_pkcs1_modulus(&input.public_key_der).unwrap();
    let signature = Bytes2048(input.signature.clone().try_into().unwrap());
    let header_hash: [u8; 32] = sha2::Sha256::digest(&input.signed_headers).into();
    let witness = build_rsa65537_witness(&modulus, &signature);
    let final_be = witness.steps[16].remainder.0;
    assert!(verify_pkcs1v15_sha256_encoded(&final_be, &header_hash));
    input.rsa_challenge_seed = challenge_seed_from_witness(&witness);

    (input, witness)
}

fn configure_zkemail_program() -> Program {
    let mut program = Program::new("zkemail-guest");
    program.set_func("verify_dkim");
    program.set_stack_size(131072);
    program.set_memory_size(1048576);
    program.set_max_input_size(65536);
    program.set_max_trusted_advice_size(16384);
    program
}

fn build_public_fixture(
    trace_file: &str,
) -> (
    [(Vec<Rep3Cycle>, provia_worker::host::memory::Rep3Memory, provia_worker::host::jolt_device::Rep3ProgramIOInput); 3],
    JoltProverPreprocessing<F, PCS>,
    JoltVerifierPreprocessing<F, PCS>,
    tracer::JoltDevice,
    usize,
    usize,
) {
    let mut program = build_program();
    let (inputs, untrusted_advice, trusted_advice) = build_inputs();

    let mut rng = ChaCha12Rng::seed_from_u64(0);
    let (bytecode, memory_init, io_device, shares) =
        generate_trace_shares(&mut program, &inputs, &untrusted_advice, &trusted_advice, &mut rng);

    // Shares are already padded to next power of 2 by generate_trace_shares.
    let padded_len = shares[0].0.len();
    tracing::info!("Padded trace len: {padded_len}");

    // 2) Preprocessing.
    let preprocessing: JoltProverPreprocessing<F, PCS> = <JoltArch as Rep3JoltWorker<F, PCS, FS>>::preprocess(
        bytecode.clone(),
        io_device.memory_layout.clone(),
        memory_init.clone(),
        padded_len,
    );
    let verifier_preprocessing = JoltVerifierPreprocessing::from(&preprocessing);

    // 3) Compute ram_K from shared trace (RAM addresses are public).
    let ram_K = provia_worker::utils::compute_ram_k(&shares[0].0, &preprocessing.shared);

    (shares, preprocessing, verifier_preprocessing, io_device, ram_K, padded_len)
}

fn build_dag_fixture(trace_file: &str) -> DagFixture {
    let _test_guard = dag_test_lock();
    let _tracing_guard = init_tracing(trace_file, std::path::Path::new("traces"));

    let (shares, preprocessing, verifier_preprocessing, mut io_device, ram_K, padded_len) =
        build_public_fixture(trace_file);

    // Truncate trailing zeros from outputs, matching what vanilla Jolt::prove does.
    // Both coordinator and verifier must see the same truncated outputs for Fiat-Shamir.
    io_device.outputs.truncate(io_device.outputs.iter().rposition(|&b| b != 0).map_or(0, |pos| pos + 1));

    // 4) Rep3 MPC proof.
    let preprocessing_arc = Arc::new(preprocessing);
    let verifier_preprocessing_arc = Arc::new(verifier_preprocessing);
    let io_device_arc = Arc::new(io_device);
    let shares_arc = Arc::new(shares);

    let preprocessing_arc_for_workers = Arc::clone(&preprocessing_arc);
    let verifier_preprocessing_arc_for_coord = Arc::clone(&verifier_preprocessing_arc);
    let io_device_arc_for_coord = Arc::clone(&io_device_arc);

    let (_worker_out, rep3_proof) = run_rep3_local_test_with_coordinator(
        1,
        {
            let shares_arc = Arc::clone(&shares_arc);
            let preprocessing_arc = Arc::clone(&preprocessing_arc_for_workers);
            move |party_idx| {
                let (trace, memory, advice_shares) = shares_arc[party_idx].clone();
                (trace, memory, Arc::clone(&preprocessing_arc), ram_K, advice_shares)
            }
        },
        {
            let verifier_preprocessing_arc = Arc::clone(&verifier_preprocessing_arc_for_coord);
            let prover_preprocessing_arc = Arc::clone(&preprocessing_arc);
            let io_device_arc = Arc::clone(&io_device_arc_for_coord);
            move || {
                (
                    Arc::clone(&verifier_preprocessing_arc),
                    Arc::clone(&prover_preprocessing_arc),
                    Arc::clone(&io_device_arc),
                    ram_K,
                )
            }
        },
        move |input, io_ctx| {
            let (trace, final_memory_state, preprocessing, ram_K, advice_shares) = input;
            let mut io_ctx = io_ctx;
            let party_id = io_ctx.party_id();

            // Preprocessing: create EdaBits pool for B2A conversions (2 rounds).
            let mut preproc = {
                use provia_worker::zkvm::preprocessing::compute_edabit_budget;
                use mpc_core::protocols::rep3_ring::edabits;
                let budget = compute_edabit_budget(trace.len());
                let pool_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(format!(".preprocessing/test/party_{}", io_ctx.party_idx()));
                #[cfg(not(feature = "ring-msm"))]
                let mut pool = edabits::preprocess_pool::<F, _>(
                    &pool_dir,
                    [budget.u8, budget.u16, budget.u32, budget.u64, budget.u128],
                    budget.dabits,
                    budget.rand_ohvs_u8_k4,
                    budget.ring_edabits_u64,
                    budget.ring_edabits_u128,
                    &mut io_ctx,
                )?;
                #[cfg(feature = "ring-msm")]
                let mut pool = edabits::preprocess_pool::<F, _>(
                    &pool_dir,
                    [budget.u8, budget.u16, budget.u32, budget.u64, budget.u128],
                    budget.dabits,
                    budget.rand_ohvs_u8_k4,
                    budget.ring_edabits_dory,
                    budget.ring_edabits_u64,
                    budget.ring_edabits_u128,
                    budget.ring_edabits_iring,
                    &mut io_ctx,
                )?;

                // Ring MSM preprocessing (wrap masks + daPoints — not in pool)
                #[cfg(feature = "ring-msm")]
                {
                    use mpc_core::protocols::rep3_ring::preprocessing::wrap_mask::generate_wrap_masks_lazy;
                    if budget.wrap_masks > 0 {
                        pool.set_wrap_masks(generate_wrap_masks_lazy(budget.wrap_masks, io_ctx.main())?);
                    }
                    if budget.wrap_masks_iring > 0 {
                        pool.set_wrap_masks_iring(generate_wrap_masks_lazy(budget.wrap_masks_iring, io_ctx.main())?);
                    }
                    let dory_num_columns = jolt_core::poly::commitment::dory::DoryGlobals::get_num_columns();
                    let (q0_xlen, q1_xlen, q0_64, q1_64) =
                        provia_worker::poly::commitment::dory::precompute_dapoint_q_columns(
                            &preprocessing.generators,
                            dory_num_columns,
                        );
                    if budget.dapoints > 0 {
                        let lazy_dp =
                            mpc_core::protocols::rep3_ring::preprocessing::dapoint::random_dapoints_from_columns(
                                &q0_xlen,
                                &q1_xlen,
                                budget.dapoints / 2,
                                dory_num_columns,
                                io_ctx.main(),
                            )?;
                        pool.set_dapoints(lazy_dp);
                    }
                    if budget.dapoints_iring > 0 {
                        let lazy_dp_iring =
                            mpc_core::protocols::rep3_ring::preprocessing::dapoint::random_dapoints_from_columns(
                                &q0_64,
                                &q1_64,
                                budget.dapoints_iring / 2,
                                dory_num_columns,
                                io_ctx.main(),
                            )?;
                        pool.set_dapoints_iring(lazy_dp_iring);
                    }
                    pool.save(&pool_dir).ok();
                }
                pool
            };

            let state =
                StateManagerWorker::new(&preprocessing, trace, advice_shares, final_memory_state, party_id, ram_K);
            Rep3JoltDagWorker::prove::<F, PCS, FS, _>(state, &mut io_ctx, &mut preproc)
        },
        move |input, net| {
            let (verifier_preprocessing, prover_preprocessing, program_io, ram_K) = input;
            // Match twist_sumcheck_switch_index computation in provia-worker zkvm/mod.rs.
            let num_chunks = rayon::current_num_threads().next_power_of_two().min(padded_len);
            let chunk_size = if num_chunks > 0 { padded_len / num_chunks } else { padded_len };
            let twist_sumcheck_switch_index = if chunk_size > 0 { chunk_size.trailing_zeros() as usize } else { 0 };
            let state: StateManager<'_, F, FS, PCS> =
                StateManager::new(&verifier_preprocessing, (*program_io).clone(), ram_K, twist_sumcheck_switch_index)
                    .with_pcs_setup(&prover_preprocessing.generators);
            Rep3JoltDag::prove(state, net)
        },
    );

    // 5) Verify the MPC-produced proof using the local jolt-core verifier.
    // Initialize DoryGlobals here (not before proof generation) so workers can
    // use advice-sized DoryGlobals during their commit without races.
    let _dory_guard = DoryGlobals::initialize(DTH_ROOT_OF_K, padded_len);
    let verifier_preprocessing = Arc::try_unwrap(verifier_preprocessing_arc).unwrap_or_else(|arc| (*arc).clone());
    let io_device = Arc::try_unwrap(io_device_arc).unwrap_or_else(|arc| (*arc).clone());

    DagFixture { proof: rep3_proof, verifier_preprocessing, io_device, ram_k: ram_K }
}

fn verify_dag_fixture(fixture: DagFixture) -> Result<(), Box<dyn std::error::Error>> {
    let DagFixture { proof, verifier_preprocessing, io_device, ram_k } = fixture;
    let twist_sumcheck_switch_index = proof.twist_sumcheck_switch_index;
    let verifier_program_io = JoltDevice {
        inputs: io_device.inputs.clone(),
        outputs: io_device.outputs.clone(),
        panic: io_device.panic,
        memory_layout: io_device.memory_layout.clone(),
        trusted_advice: vec![],
        untrusted_advice: vec![],
    };
    let verifier_sm = VanillaStateManager::from_proof(
        proof,
        Box::leak(Box::new(verifier_preprocessing)),
        verifier_program_io,
        ram_k,
        twist_sumcheck_switch_index,
    );
    JoltDAG::verify::<F, FS, PCS>(verifier_sm).map_err(Into::into)
}

#[test]
fn dag_correct() {
    let fixture = build_dag_fixture("dag_correct.json");
    verify_dag_fixture(fixture).expect("Vanilla verification of MPC proof failed");
}

#[cfg(feature = "zk")]
#[test]
fn dag_zk_tampered_y_com_fails() {
    let mut fixture = build_dag_fixture("dag_zk_tampered_y_com.json");
    assert!(fixture.proof.blindfold_proof.is_some(), "DAG ZK proof must include BlindFold");

    let reduced_opening_proof =
        fixture.proof.proofs.get_mut(&ProofKeys::ReducedOpeningProof).expect("reduced opening proof missing");
    let reduced_opening_proof = match reduced_opening_proof {
        ProofData::ReducedOpeningProof(proof) => proof,
        _ => panic!("unexpected proof type for reduced opening proof"),
    };
    if let Some(ref mut y_com) = reduced_opening_proof.joint_opening_proof.dory_proof_data.y_com {
        *y_com = *y_com + fixture.verifier_preprocessing.generators.g1_0;
    } else if let Some(ref mut e2) = reduced_opening_proof.joint_opening_proof.dory_proof_data.e2 {
        *e2 = *e2 + fixture.verifier_preprocessing.generators.g2_0;
    } else {
        panic!("ZK reduced opening proof missing committed evaluation fields");
    }

    let err = verify_dag_fixture(fixture).expect_err("tampered y_com must fail verification");
    let err_text = format!("{err:?}");
    assert!(
        err_text.contains("Stage 5") || err_text.contains("BlindFold"),
        "unexpected verification error after tampering y_com: {err_text}"
    );
}

#[cfg(feature = "zk")]
#[test]
fn dag_zk_tampered_stage5_hidden_claim_fails() {
    let mut fixture = build_dag_fixture("dag_zk_tampered_stage5_hidden_claim.json");
    assert!(fixture.proof.blindfold_proof.is_some(), "DAG ZK proof must include BlindFold");

    let reduced_opening_proof =
        fixture.proof.proofs.get_mut(&ProofKeys::ReducedOpeningProof).expect("reduced opening proof missing");
    let reduced_opening_proof = match reduced_opening_proof {
        ProofData::ReducedOpeningProof(proof) => proof,
        _ => panic!("unexpected proof type for reduced opening proof"),
    };
    let first_claim = reduced_opening_proof
        .sumcheck_claims
        .first_mut()
        .expect("reduced opening proof must contain at least one hidden claim");
    *first_claim += F::from_u64(1);

    let err = verify_dag_fixture(fixture).expect_err("tampered stage5 hidden claim must fail verification");
    let err_text = format!("{err:?}");
    assert!(
        err_text.contains("Stage 5") || err_text.contains("BlindFold"),
        "unexpected verification error after tampering stage5 hidden claim: {err_text}"
    );
}

#[test]
fn zkemail_trace_only() {
    let mut program = configure_zkemail_program();

    let (input, prepared) = build_zkemail_fixture();
    let inputs = postcard::to_stdvec(&input).unwrap();
    let trusted_advice = postcard::to_stdvec(&TrustedAdvice::from(prepared)).unwrap();
    eprintln!("Serialized input size: {} bytes", inputs.len());
    eprintln!("Serialized trusted advice size: {} bytes", trusted_advice.len());

    let (trace, _memory, io_device) = program.trace(&[], &inputs, &trusted_advice);
    eprintln!("Trace length: {}", trace.len());
    eprintln!("Panic: {}", io_device.panic);
    eprintln!("Outputs: {:?}", &io_device.outputs[..io_device.outputs.len().min(64)]);
    assert!(!io_device.panic, "zkemail guest panicked");
}

fn rep3_proof_twist_switch_index(padded_len: usize) -> usize {
    let num_chunks = rayon::current_num_threads().next_power_of_two().min(padded_len);
    let chunk_size = if num_chunks > 0 { padded_len / num_chunks } else { padded_len };
    if chunk_size > 0 {
        chunk_size.trailing_zeros() as usize
    } else {
        0
    }
}
