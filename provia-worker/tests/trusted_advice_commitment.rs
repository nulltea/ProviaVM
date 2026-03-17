use ark_bn254::Fr;
use jolt_core::common::constants::RAM_WORD_SIZE;
use jolt_core::common::jolt_device::{JoltDevice, MemoryConfig, MemoryLayout};
use jolt_core::poly::commitment::commitment_scheme::CommitmentScheme;
use jolt_core::poly::commitment::dory::{DoryContext, DoryGlobals};
use jolt_core::poly::multilinear_polynomial::MultilinearPolynomial;
use jolt_core::transcripts::Blake2bTranscript;
use jolt_core::utils::math::Math;
use mpc_core::protocols::rep3::combine_field_elements;
use mpc_core::protocols::rep3::Rep3PrimeFieldShare;
use mpc_core::protocols::rep3::test_utils::run_rep3_local_test_with_coordinator;
use mpc_core::protocols::rep3_ring::casts::r2f_b2a_many;
use mpc_core::protocols::rep3_ring::edabits;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use provia_coordinator::poly::commitment::Rep3CommitmentScheme as CoordinatorRep3CommitmentScheme;
use provia_worker::host::jolt_device::Rep3ProgramIOInput;
use provia_worker::poly::commitment::dory::{test_support::init_dory_globals, DoryCommitmentScheme};
use provia_worker::poly::commitment::Rep3CommitmentScheme as WorkerRep3CommitmentScheme;
use provia_worker::poly::Rep3MultilinearPolynomial;
use provia_worker::utils::test_utils::worker_test_lock;

#[test]
fn trusted_advice_commitment_matches_public_commit() {
    let _guard = worker_test_lock();

    let trusted_advice = (0u8..=255).cycle().take(777).collect::<Vec<_>>();
    let memory_layout = MemoryLayout::new(&MemoryConfig {
        max_input_size: 0,
        max_output_size: 0,
        max_untrusted_advice_size: 0,
        max_trusted_advice_size: 16_384,
        stack_size: 0,
        memory_size: 0,
        program_size: Some(0),
    });
    let max_size = memory_layout.max_trusted_advice_size as usize / RAM_WORD_SIZE as usize;

    init_dory_globals(1, max_size);
    DoryGlobals::initialize_context(1, max_size, DoryContext::TrustedAdvice, None);
    DoryGlobals::set_context(DoryContext::TrustedAdvice);

    let setup = <DoryCommitmentScheme as CommitmentScheme>::setup_prover(max_size.log_2());
    let mut public_coeffs = vec![0u64; max_size];
    for (i, chunk) in trusted_advice.chunks(RAM_WORD_SIZE as usize).enumerate() {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        public_coeffs[i + 1] = u64::from_le_bytes(word);
    }
    let expected_coeffs: Vec<Fr> = public_coeffs.iter().copied().map(Fr::from).collect();
    let public_poly = MultilinearPolynomial::<Fr>::from(public_coeffs);
    let (public_commitment, _) = <DoryCommitmentScheme as CommitmentScheme>::commit(&public_poly, &setup);
    DoryGlobals::set_context(DoryContext::Main);

    let mut rng = ChaCha12Rng::seed_from_u64(0);
    let shares: [Rep3ProgramIOInput; 3] = Rep3ProgramIOInput::generate_secret_shares(
        JoltDevice {
            inputs: vec![],
            outputs: vec![],
            panic: false,
            trusted_advice,
            untrusted_advice: vec![],
            memory_layout,
        },
        &mut rng,
    )
    .try_into()
    .unwrap();

    let (results, _) = run_rep3_local_test_with_coordinator(
        0,
        |party_idx| shares[party_idx].clone(),
        || (),
        move |share, mut io_ctx| {
            DoryGlobals::initialize_context(1, max_size, DoryContext::TrustedAdvice, None);
            DoryGlobals::set_context(DoryContext::TrustedAdvice);

            let words = Rep3ProgramIOInput::pack_advice_words(&share.trusted_advice);
            let field_words = r2f_b2a_many(&words, io_ctx.main())?;
            let mut coeffs = vec![Rep3PrimeFieldShare::zero_share(); max_size];
            for (i, coeff) in field_words.into_iter().enumerate() {
                coeffs[i + 1] = coeff;
            }

            let poly = Rep3MultilinearPolynomial::from_shared_coeffs(coeffs.clone());
            let mut preproc = edabits::preprocess_pool::<Fr, _>(
                &std::env::temp_dir().join(format!("provia-worker-advice-test-{}", io_ctx.party_idx())),
                [0, 0, 0, 0, 0],
                0,
                0,
                0,
                0,
                &mut io_ctx,
            )?;
            let result = <DoryCommitmentScheme as WorkerRep3CommitmentScheme<Fr, Blake2bTranscript>>::commit_rep3(
                &poly,
                &setup,
                false,
                &mut io_ctx,
                &mut preproc,
            )?;
            DoryGlobals::set_context(DoryContext::Main);
            Ok((result.0, coeffs))
        },
        |(), _| Ok(()),
    );

    let combined =
        <DoryCommitmentScheme as CoordinatorRep3CommitmentScheme<Fr, Blake2bTranscript>>::combine_commitment_shares(
            &[&results[0].0, &results[1].0, &results[2].0],
        );
    let combined_coeffs = combine_field_elements(
        &results[0].1,
        &results[1].1,
        &results[2].1,
    );

    assert_eq!(combined_coeffs, expected_coeffs);
    assert_eq!(combined, public_commitment);
}
