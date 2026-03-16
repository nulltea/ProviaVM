use provia_worker::utils::test_utils::{
    build_test_fixture_from_parts, prove_test_fixture, verify_test_fixture, worker_test_lock,
    TestF, TestFixture,
};

use jolt_core::field::JoltField;
use jolt_core::host::Program;
use jolt_core::zkvm::state_manager::{ProofData, ProofKeys};

type F = TestF;

fn prove_fibonacci_fixture() -> TestFixture {
    let mut program = Program::new("fibonacci-guest");
    program.set_memory_size(10240);
    let inputs = postcard::to_stdvec(&9u32).unwrap();

    let (shares, preprocessing, verifier_preprocessing, io_device, ram_k, padded_len) =
        build_test_fixture_from_parts(&mut program, inputs, vec![], vec![]);

    prove_test_fixture(shares, preprocessing, verifier_preprocessing, io_device, ram_k, padded_len)
}

#[test]
fn prove_correct() {
    let _test_guard = worker_test_lock();
    let fixture = prove_fibonacci_fixture();
    verify_test_fixture(fixture).expect("Vanilla verification of MPC proof failed");
}

#[cfg(feature = "zk")]
#[test]
fn zk_tampered_y_com_fails() {
    let _test_guard = worker_test_lock();
    let mut fixture = prove_fibonacci_fixture();
    assert!(fixture.proof.blindfold_proof.is_some(), "ZK proof must include BlindFold");

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

    let err = verify_test_fixture(fixture).expect_err("tampered y_com must fail verification");
    let err_text = format!("{err:?}");
    assert!(
        err_text.contains("Stage 5") || err_text.contains("BlindFold"),
        "unexpected verification error after tampering y_com: {err_text}"
    );
}

#[cfg(feature = "zk")]
#[test]
fn zk_tampered_stage5_hidden_claim_fails() {
    let _test_guard = worker_test_lock();
    let mut fixture = prove_fibonacci_fixture();
    assert!(fixture.proof.blindfold_proof.is_some(), "ZK proof must include BlindFold");

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

    let err = verify_test_fixture(fixture).expect_err("tampered stage5 hidden claim must fail verification");
    let err_text = format!("{err:?}");
    assert!(
        err_text.contains("Stage 5") || err_text.contains("BlindFold"),
        "unexpected verification error after tampering stage5 hidden claim: {err_text}"
    );
}
