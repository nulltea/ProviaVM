use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;

use eyre::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use jolt_core::field::JoltField;
use jolt_core::poly::multilinear_polynomial::MultilinearPolynomial;
use mpc_core::protocols::rep3::network::{IoContextPool, Rep3MpcNet};
use mpc_net::config::{Address, NetworkConfig, NetworkParty};
use mpc_net::rep3::quic::Rep3QuicNetCoordinator;

// ── Test Network Helpers ────────────────────────────────────────────────────

/// Generate a self-signed certificate + private key for localhost.
fn generate_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("cert generation");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())).clone_key();
    (cert_der, key_der)
}

/// Build `NetworkConfig`s for 3 localhost parties using the given base port.
fn build_test_configs(base_port: u16) -> [NetworkConfig; 3] {
    let certs_keys: Vec<_> = (0..3).map(|_| generate_cert()).collect();

    let parties: Vec<NetworkParty> = (0..3)
        .map(|i| NetworkParty {
            id: i,
            worker: 0,
            dns_name: Address::new("localhost".into(), base_port + i as u16),
            cert: certs_keys[i].0.clone(),
            protocol: Default::default(),
        })
        .collect();

    std::array::from_fn(|i| NetworkConfig {
        parties: parties.clone(),
        coordinator: None,
        is_coordinator: false,
        my_id: i,
        worker: 0,
        bind_addr: SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), base_port + i as u16),
        key: certs_keys[i].1.clone_key(),
        timeout: Some(std::time::Duration::from_secs(30)),
        user_listen_addr: None,
    })
}

/// Spawn 3 MPC worker threads. Each worker receives its input via the closure
/// `make_input(party_index)`, runs `work_fn`, and returns the result.
///
/// Returns an array of 3 results.
pub fn run_rep3_test<I, O, W>(base_port: u16, num_io_forks: u32, make_input: impl Fn(usize) -> I, work_fn: W) -> [O; 3]
where
    I: Send + 'static,
    O: Send + 'static,
    W: Fn(I, IoContextPool<Rep3MpcNet>) -> eyre::Result<O> + Send + Sync + 'static,
{
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok(); // ignore if already installed

    let configs = build_test_configs(base_port);
    let work_fn = Arc::new(work_fn);

    let handles: Vec<_> = (0..3)
        .map(|i| {
            let config = configs[i].clone();
            let input = make_input(i);
            let work_fn = Arc::clone(&work_fn);
            thread::spawn(move || {
                // Each party gets its own rayon thread pool to avoid deadlocks.
                // In production each party is a separate process; in tests they
                // share a process and would contend on the global rayon pool.
                let pool = rayon::ThreadPoolBuilder::new()
                    .thread_name(move |idx| format!("party-{i}-rayon-{idx}"))
                    .build()
                    .unwrap();
                pool.install(|| {
                    let network =
                        Rep3MpcNet::new(config, 0).with_context(|| format!("party {i} network init")).unwrap();
                    let io_ctx = IoContextPool::init(network, num_io_forks)
                        .with_context(|| format!("party {i} io_ctx init"))
                        .unwrap();
                    work_fn(input, io_ctx).with_context(|| format!("party {i} work")).unwrap()
                })
            })
        })
        .collect();

    let results: Vec<O> = handles.into_iter().map(|h| h.join().expect("worker thread panicked")).collect();

    results.try_into().unwrap_or_else(|_| unreachable!())
}

// ── Test with Coordinator ───────────────────────────────────────────────────

/// Build `NetworkConfig`s for 3 worker parties + 1 coordinator on localhost.
/// Workers get ports `base_port..base_port+2`, coordinator gets `base_port+3`.
fn build_test_configs_with_coordinator(base_port: u16) -> ([NetworkConfig; 3], NetworkConfig) {
    let certs_keys: Vec<_> = (0..4).map(|_| generate_cert()).collect();

    // Worker parties (indices 0..3)
    let worker_parties: Vec<NetworkParty> = (0..3)
        .map(|i| NetworkParty {
            id: i,
            worker: 0,
            dns_name: Address::new("localhost".into(), base_port + i as u16),
            cert: certs_keys[i].0.clone(),
            protocol: Default::default(),
        })
        .collect();

    // Coordinator party
    let coordinator_party = NetworkParty {
        id: 0,
        worker: 0,
        dns_name: Address::new("localhost".into(), base_port + 3),
        cert: certs_keys[3].0.clone(),
        protocol: Default::default(),
    };

    let worker_configs: [NetworkConfig; 3] = std::array::from_fn(|i| NetworkConfig {
        parties: worker_parties.clone(),
        coordinator: Some(coordinator_party.clone()),
        is_coordinator: false,
        my_id: i,
        worker: 0,
        bind_addr: SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), base_port + i as u16),
        key: certs_keys[i].1.clone_key(),
        timeout: Some(std::time::Duration::from_secs(30)),
        user_listen_addr: None,
    });

    let coordinator_config = NetworkConfig {
        parties: worker_parties,
        coordinator: Some(coordinator_party),
        is_coordinator: true,
        my_id: 0,
        worker: 0,
        bind_addr: SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), base_port + 3),
        key: certs_keys[3].1.clone_key(),
        timeout: Some(std::time::Duration::from_secs(30)),
        user_listen_addr: None,
    };

    (worker_configs, coordinator_config)
}

/// Spawn 3 MPC worker threads + 1 coordinator thread.
///
/// Each worker receives its input via `make_worker_input(party_index)` and runs
/// `worker_fn` with an `IoContextPool` (passed by value for ownership transfer).
/// The coordinator receives its input via `make_coordinator_input()` and runs
/// `coordinator_fn` with a `Rep3QuicNetCoordinator`.
///
/// Returns `([worker_results; 3], coordinator_result)`.
pub fn run_rep3_test_with_coordinator<WI, WO, CI, CO, WF, CF>(
    base_port: u16,
    num_io_forks: u32,
    make_worker_input: impl Fn(usize) -> WI,
    make_coordinator_input: impl FnOnce() -> CI,
    worker_fn: WF,
    coordinator_fn: CF,
) -> ([WO; 3], CO)
where
    WI: Send + 'static,
    WO: Send + 'static,
    CI: Send + 'static,
    CO: Send + 'static,
    WF: Fn(WI, IoContextPool<Rep3MpcNet>) -> eyre::Result<WO> + Send + Sync + 'static,
    CF: FnOnce(CI, &mut Rep3QuicNetCoordinator) -> eyre::Result<CO> + Send + 'static,
{
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let (worker_configs, coordinator_config) = build_test_configs_with_coordinator(base_port);
    let worker_fn = Arc::new(worker_fn);

    // Spawn worker threads
    let worker_handles: Vec<_> = (0..3)
        .map(|i| {
            let config = worker_configs[i].clone();
            let input = make_worker_input(i);
            let worker_fn = Arc::clone(&worker_fn);
            thread::spawn(move || {
                let pool = rayon::ThreadPoolBuilder::new()
                    .thread_name(move |idx| format!("party-{i}-rayon-{idx}"))
                    .build()
                    .unwrap();
                pool.install(|| {
                    let network =
                        Rep3MpcNet::new(config, 0).with_context(|| format!("party {i} network init")).unwrap();
                    let io_ctx = IoContextPool::init(network, num_io_forks)
                        .with_context(|| format!("party {i} io_ctx init"))
                        .unwrap();
                    worker_fn(input, io_ctx).with_context(|| format!("party {i} work")).unwrap()
                })
            })
        })
        .collect();

    // Spawn coordinator thread
    let coordinator_input = make_coordinator_input();
    let coordinator_handle = thread::spawn(move || {
        let pool =
            rayon::ThreadPoolBuilder::new().thread_name(|idx| format!("coordinator-rayon-{idx}")).build().unwrap();
        pool.install(|| {
            let mut network =
                Rep3QuicNetCoordinator::new(coordinator_config, 0).context("coordinator network init").unwrap();
            coordinator_fn(coordinator_input, &mut network).context("coordinator work").unwrap()
        })
    });

    // Collect results
    let worker_results: Vec<WO> =
        worker_handles.into_iter().map(|h| h.join().expect("worker thread panicked")).collect();
    let coordinator_result = coordinator_handle.join().expect("coordinator thread panicked");

    let worker_array = worker_results.try_into().unwrap_or_else(|_| unreachable!());
    (worker_array, coordinator_result)
}

#[cfg(feature = "test-utils")]
pub use mpc_core::protocols::rep3::test_utils::run_rep3_local_test_with_coordinator;

// ── Shared DAG Test Infrastructure ──────────────────────────────────────────

use std::sync::{Mutex, MutexGuard, OnceLock};

use ark_bn254::Fr;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

use jolt_core::curve::Bn254Curve;
use jolt_core::host::Program;
use jolt_core::poly::commitment::dory::{DoryCommitmentScheme, DoryGlobals};
use jolt_core::transcripts::Blake2bTranscript;
use jolt_core::zkvm::proof_serialization::JoltProof;
use jolt_core::zkvm::state_manager::StateManager as VanillaStateManager;
use jolt_core::zkvm::verifier::JoltDAG;
use jolt_core::zkvm::witness::DTH_ROOT_OF_K;
use jolt_core::zkvm::{JoltProverPreprocessing, JoltVerifierPreprocessing};
use tracer::JoltDevice;

use crate::host::program::generate_trace_shares;
use crate::zkvm::instruction::Rep3Cycle;
use crate::zkvm::state_manager::StateManagerWorker;
use crate::zkvm::worker::Rep3JoltDagWorker;
use crate::zkvm::{JoltArch, Rep3JoltWorker};
use provia_coordinator::zkvm::coordinator::Rep3JoltDag;
use provia_coordinator::zkvm::state_manager::StateManager;

pub type TestF = Fr;
pub type TestPCS = DoryCommitmentScheme;
pub type TestFS = Blake2bTranscript;

pub struct TestFixture {
    pub proof: JoltProof<TestF, Bn254Curve, TestPCS, TestFS>,
    pub verifier_preprocessing: JoltVerifierPreprocessing<TestF, TestPCS>,
    pub io_device: JoltDevice,
    pub ram_k: usize,
}

/// Serializes the test so only one DAG proof runs at a time.
pub fn worker_test_lock() -> MutexGuard<'static, ()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

/// Trace a program, secret-share the trace, and build preprocessing.
pub fn build_test_fixture_from_parts(
    program: &mut Program,
    inputs: Vec<u8>,
    untrusted_advice: Vec<u8>,
    trusted_advice: Vec<u8>,
) -> (
    [(Vec<Rep3Cycle>, crate::host::memory::Rep3Memory, crate::host::jolt_device::Rep3ProgramIOInput); 3],
    JoltProverPreprocessing<TestF, TestPCS>,
    JoltVerifierPreprocessing<TestF, TestPCS>,
    JoltDevice,
    usize,
    usize,
) {
    let mut rng = ChaCha12Rng::seed_from_u64(0);
    let (bytecode, memory_init, io_device, raw_trace_len, shares) =
        generate_trace_shares(program, &inputs, &untrusted_advice, &trusted_advice, &mut rng);

    let padded_len = shares[0].0.len();
    tracing::info!("Padded trace len: {padded_len}");

    let preprocessing: JoltProverPreprocessing<TestF, TestPCS> =
        <JoltArch as Rep3JoltWorker<TestF, TestPCS, TestFS>>::preprocess(
            bytecode.clone(),
            io_device.memory_layout.clone(),
            memory_init.clone(),
            raw_trace_len,
        );
    let verifier_preprocessing = JoltVerifierPreprocessing::from(&preprocessing);

    let ram_k = crate::utils::compute_ram_k(&shares[0].0, &preprocessing.shared);

    (shares, preprocessing, verifier_preprocessing, io_device, ram_k, padded_len)
}

/// Run the full MPC DAG proof from pre-built shares.
pub fn prove_test_fixture(
    shares: [(Vec<Rep3Cycle>, crate::host::memory::Rep3Memory, crate::host::jolt_device::Rep3ProgramIOInput); 3],
    preprocessing: JoltProverPreprocessing<TestF, TestPCS>,
    verifier_preprocessing: JoltVerifierPreprocessing<TestF, TestPCS>,
    mut io_device: JoltDevice,
    ram_k: usize,
    padded_len: usize,
) -> TestFixture {
    io_device.outputs.truncate(io_device.outputs.iter().rposition(|&b| b != 0).map_or(0, |pos| pos + 1));

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
                (trace, memory, Arc::clone(&preprocessing_arc), ram_k, advice_shares)
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
                    ram_k,
                )
            }
        },
        move |input, io_ctx| {
            let (trace, final_memory_state, preprocessing, ram_k, advice_shares) = input;
            let mut io_ctx = io_ctx;
            let party_id = io_ctx.party_id();

            let mut preproc = {
                use crate::zkvm::preprocessing::compute_edabit_budget;
                use mpc_core::protocols::rep3_ring::edabits;
                let budget = compute_edabit_budget(trace.len());
                let pool_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(format!(".preprocessing/test/party_{}", io_ctx.party_idx()));
                #[cfg(not(feature = "ring-msm"))]
                let mut pool = edabits::preprocess_pool::<TestF, _>(
                    &pool_dir,
                    [budget.u8, budget.u16, budget.u32, budget.u64, budget.u128],
                    budget.dabits,
                    budget.rand_ohvs_u8_k4,
                    budget.ring_edabits_u64,
                    budget.ring_edabits_u128,
                    &mut io_ctx,
                )?;
                #[cfg(feature = "ring-msm")]
                let mut pool = edabits::preprocess_pool::<TestF, _>(
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

                #[cfg(feature = "ring-msm")]
                {
                    use mpc_core::protocols::rep3_ring::preprocessing::wrap_mask::generate_wrap_masks_lazy;
                    if budget.wrap_masks > 0 {
                        pool.set_wrap_masks(generate_wrap_masks_lazy(budget.wrap_masks, io_ctx.main())?);
                    }
                    if budget.wrap_masks_iring > 0 {
                        pool.set_wrap_masks_iring(generate_wrap_masks_lazy(budget.wrap_masks_iring, io_ctx.main())?);
                    }
                    let dory_num_columns = DoryGlobals::get_num_columns();
                    let (q0_xlen, q1_xlen, q0_64, q1_64) =
                        crate::poly::commitment::dory::precompute_dapoint_q_columns(
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
                StateManagerWorker::new(&preprocessing, trace, advice_shares, final_memory_state, party_id, ram_k);
            Rep3JoltDagWorker::prove::<TestF, TestPCS, TestFS, _>(state, &mut io_ctx, &mut preproc)
        },
        move |input, net| {
            let (verifier_preprocessing, prover_preprocessing, program_io, ram_k) = input;
            let twist_sumcheck_switch_index = rep3_proof_twist_switch_index(padded_len);
            let state: StateManager<'_, TestF, TestFS, TestPCS> =
                StateManager::new(&verifier_preprocessing, (*program_io).clone(), ram_k, twist_sumcheck_switch_index)
                    .with_pcs_setup(&prover_preprocessing.generators);
            Rep3JoltDag::prove(state, net)
        },
    );

    let _dory_guard = DoryGlobals::initialize(DTH_ROOT_OF_K, padded_len);
    let verifier_preprocessing = Arc::try_unwrap(verifier_preprocessing_arc).unwrap_or_else(|arc| (*arc).clone());
    let io_device = Arc::try_unwrap(io_device_arc).unwrap_or_else(|arc| (*arc).clone());

    TestFixture { proof: rep3_proof, verifier_preprocessing, io_device, ram_k }
}

/// Verify a `TestFixture` using the local jolt-core verifier.
pub fn verify_test_fixture(fixture: TestFixture) -> Result<(), Box<dyn std::error::Error>> {
    let TestFixture { proof, verifier_preprocessing, io_device, ram_k } = fixture;
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
    JoltDAG::verify::<TestF, TestFS, TestPCS>(verifier_sm).map_err(Into::into)
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

// ── Polynomial Comparison ───────────────────────────────────────────────────

/// Compare two multilinear polynomials coefficient-by-coefficient.
/// Panics with a detailed mismatch report if they differ.
pub fn check_poly<F: JoltField>(poly: &MultilinearPolynomial<F>, check: &MultilinearPolynomial<F>, label: &str) {
    assert_eq!(poly.len(), check.len(), "len mismatch {label}");
    let len = poly.len();
    let mut mismatches = Vec::new();
    for i in 0..len {
        let a = poly.get_coeff(i);
        let b = check.get_coeff(i);
        if a != b {
            mismatches.push((i, a, b));
        }
    }
    if !mismatches.is_empty() {
        panic!("{label}: {} mismatches (first at pos {}, len {len})", mismatches.len(), mismatches[0].0,);
    }
}
