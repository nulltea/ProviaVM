// Ensure inline #[ctor] registers sequence builders.
use jolt_inlines_sha2 as _;

use jolt_core::host::Program;
use provia_worker::utils::test_utils::{
    build_test_fixture_from_parts, prove_test_fixture, verify_test_fixture, worker_test_lock,
    TestFixture,
};

fn configure_program() -> Program {
    let mut program = Program::new("sha2-chain-guest");
    program.set_stack_size(65536);
    program.set_memory_size(10240);
    program
}

fn prove_sha2_chain_fixture() -> TestFixture {
    let mut program = configure_program();
    let mut advice = postcard::to_stdvec(&[5u8; 32]).unwrap();
    advice.append(&mut postcard::to_stdvec(&1u32).unwrap());

    let (shares, preprocessing, verifier_preprocessing, io_device, ram_k, padded_len) =
        build_test_fixture_from_parts(&mut program, vec![], advice, vec![]);

    prove_test_fixture(shares, preprocessing, verifier_preprocessing, io_device, ram_k, padded_len)
}

#[test]
fn trace_only() {
    let _test_guard = worker_test_lock();
    let mut program = configure_program();

    let mut advice = postcard::to_stdvec(&[5u8; 32]).unwrap();
    advice.append(&mut postcard::to_stdvec(&1u32).unwrap());

    let (trace, _memory, io_device) = program.trace(&[], &advice, &[]);
    eprintln!("Trace length: {}", trace.len());
    eprintln!("Panic: {}", io_device.panic);
    assert!(!io_device.panic, "sha2-chain guest panicked");
}

#[test]
fn prove_correct() {
    let _test_guard = worker_test_lock();
    let fixture = prove_sha2_chain_fixture();
    verify_test_fixture(fixture).expect("Vanilla verification of sha2-chain MPC proof failed");
}
