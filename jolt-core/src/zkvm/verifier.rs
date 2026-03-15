use std::collections::HashMap;
use std::marker::PhantomData;

use strum::IntoEnumIterator;

use crate::curve::{Bn254Curve, JoltCurve};
use crate::field::JoltField;
use crate::poly::commitment::commitment_scheme::{CommitmentScheme, ZkEvalCommitment};
use crate::poly::eq_poly::EqPolynomial;
#[cfg(feature = "zk")]
use crate::poly::opening_proof::OpeningId;
use crate::poly::opening_proof::{OpeningPoint, SumcheckId};
use crate::subprotocols::sumcheck::{BatchedSumcheck, SumcheckInstance, SumcheckInstanceProof};
use crate::transcripts::Transcript;
use crate::utils::math::Math;
use crate::zkvm::r1cs::inputs::{ALL_R1CS_INPUTS, COMMITTED_R1CS_INPUTS};
use crate::zkvm::r1cs::key::UniformSpartanKey;
use crate::zkvm::state_manager::{ProofData, ProofKeys, StateManager};
use crate::zkvm::witness::{compute_d_parameter, AllCommittedPolynomials, CommittedPolynomial, VirtualPolynomial};
use anyhow::Context;

#[cfg(feature = "zk")]
use crate::subprotocols::blindfold::{
    pedersen_generator_count_for_r1cs, BakedPublicInputs, BlindFoldVerifier, BlindFoldVerifierInput,
    InputClaimConstraint, OutputClaimConstraint, StageConfig, ValueSource, VerifierR1CSBuilder,
};

use crate::common::constants::XLEN;

// ---------------------------------------------------------------------------
// SpartanDag
// ---------------------------------------------------------------------------

pub struct SpartanDag<F: JoltField> {
    padded_trace_length: usize,
    _marker: PhantomData<F>,
}

#[cfg(feature = "zk")]
pub struct Stage1BlindfoldData<F: JoltField> {
    pub tau: Vec<F::Challenge>,
    pub challenges: Vec<F::Challenge>,
    pub output_claim_ids: Vec<OpeningId>,
}

#[cfg(feature = "zk")]
type Stage1VerifyResult<F> = Stage1BlindfoldData<F>;
#[cfg(not(feature = "zk"))]
type Stage1VerifyResult<F> = ();

impl<F: JoltField> SpartanDag<F> {
    pub fn new<ProofTranscript: Transcript>(padded_trace_length: usize) -> Self {
        Self { padded_trace_length, _marker: PhantomData }
    }

    pub fn stage1_verify<C: JoltCurve, ProofTranscript: Transcript, PCS: CommitmentScheme<Field = F>>(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Result<Stage1VerifyResult<F>, anyhow::Error> {
        let key = UniformSpartanKey::<F>::new(self.padded_trace_length);
        let num_rounds_x = key.num_rows_bits();

        let tau: Vec<F::Challenge> = sm.transcript.borrow_mut().challenge_vector_optimized::<F>(num_rounds_x);

        // Get stage1 proof
        let proofs = sm.proofs.borrow();
        let proof_data = proofs.get(&ProofKeys::Stage1Sumcheck).expect("Stage 1 sumcheck proof not found");
        let proof = match proof_data {
            ProofData::SumcheckProof(p) => p,
            _ => return Err(anyhow::anyhow!("Invalid proof type for stage 1")),
        };
        let is_zk = proof.is_zk();

        // Verify the outer sumcheck
        let (final_eval, r) = proof.verify(
            F::zero(), // initial claim is 0
            num_rounds_x,
            3, // degree 3: Az(x)*Bz(x)*Cz(x) with eq folded in
            &mut *sm.transcript.borrow_mut(),
        )?;
        let stage1_challenges = r.clone();

        // Reverse r (outer sumcheck binds from top)
        let outer_sumcheck_r: Vec<F::Challenge> = r.into_iter().rev().collect();

        // Compute eq(tau, r)
        let eq_eval = EqPolynomial::<F>::mle(&tau, &outer_sumcheck_r);

        // Get Az/Bz/Cz claims from accumulator
        let accumulator = sm.get_verifier_accumulator();
        let acc = accumulator.borrow();
        let claim_az = acc.get_virtual_polynomial_opening(VirtualPolynomial::SpartanAz, SumcheckId::SpartanOuter).1;
        let claim_bz = acc.get_virtual_polynomial_opening(VirtualPolynomial::SpartanBz, SumcheckId::SpartanOuter).1;
        let claim_cz = acc.get_virtual_polynomial_opening(VirtualPolynomial::SpartanCz, SumcheckId::SpartanOuter).1;
        drop(acc);

        // Verify: final_eval == eq(tau, r) * (Az * Bz - Cz)
        let expected = eq_eval * (claim_az * claim_bz - claim_cz);
        if !is_zk && final_eval != expected {
            return Err(anyhow::anyhow!("Spartan outer sumcheck final eval mismatch"));
        }

        if is_zk {
            if let crate::subprotocols::sumcheck::SumcheckInstanceProof::Zk(zk_proof) = proof {
                let mut transcript = sm.transcript.borrow_mut();
                transcript.append_message(b"output_claims_coms");
                zk_proof
                    .output_claims_commitments
                    .iter()
                    .for_each(|commitment| transcript.append_serializable(commitment));
            }
        } else {
            sm.transcript.borrow_mut().append_scalars(&[claim_az, claim_bz, claim_cz]);
        }

        // Store virtual openings with opening points
        let opening_point = OpeningPoint::new(outer_sumcheck_r.clone());
        {
            let mut acc = accumulator.borrow_mut();
            if is_zk {
                acc.set_zk_mode(true);
            }
            let transcript = &mut *sm.transcript.borrow_mut();

            acc.append_virtual(
                transcript,
                VirtualPolynomial::SpartanAz,
                SumcheckId::SpartanOuter,
                opening_point.clone(),
            );
            acc.append_virtual(
                transcript,
                VirtualPolynomial::SpartanBz,
                SumcheckId::SpartanOuter,
                opening_point.clone(),
            );
            acc.append_virtual(transcript, VirtualPolynomial::SpartanCz, SumcheckId::SpartanOuter, opening_point);
            if is_zk {
                acc.set_zk_mode(false);
            }
        }

        // Compute r_cycle and append committed/virtual openings
        let num_steps_bits = key.num_steps.log_2();
        let (r_cycle, _) = outer_sumcheck_r.split_at(num_steps_bits);

        // Append committed openings (PCS)
        let committed_polys: Vec<CommittedPolynomial> =
            COMMITTED_R1CS_INPUTS.iter().map(|input| CommittedPolynomial::try_from(input).ok().unwrap()).collect();
        {
            let mut acc = accumulator.borrow_mut();
            if is_zk {
                acc.set_zk_mode(true);
            }
            acc.append_dense(
                &mut *sm.transcript.borrow_mut(),
                committed_polys,
                SumcheckId::SpartanOuter,
                r_cycle.to_vec(),
            );
            if is_zk {
                acc.set_zk_mode(false);
            }
        }

        // Append virtual openings for remaining R1CS inputs
        for input in ALL_R1CS_INPUTS.iter() {
            if COMMITTED_R1CS_INPUTS.contains(input) {
                continue;
            }
            let poly = VirtualPolynomial::try_from(input).ok().unwrap();
            let mut acc = accumulator.borrow_mut();
            if is_zk {
                acc.set_zk_mode(true);
            }
            acc.append_virtual(
                &mut *sm.transcript.borrow_mut(),
                poly,
                SumcheckId::SpartanOuter,
                OpeningPoint::new(r_cycle.to_vec()),
            );
            if is_zk {
                acc.set_zk_mode(false);
            }
        }

        #[cfg(feature = "zk")]
        let output_claim_ids = if is_zk {
            let mut acc = accumulator.borrow_mut();
            let _ = acc.take_pending_claims();
            acc.take_pending_claim_ids()
        } else {
            Vec::new()
        };

        drop(proofs);
        #[cfg(feature = "zk")]
        return Ok(Stage1BlindfoldData { tau, challenges: stage1_challenges, output_claim_ids });
        #[cfg(not(feature = "zk"))]
        Ok(())
    }

    pub fn stage2_verifier_instances<C: JoltCurve, ProofTranscript: Transcript, PCS: CommitmentScheme<Field = F>>(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Vec<Box<dyn SumcheckInstance<F, ProofTranscript>>> {
        use crate::zkvm::spartan::inner::InnerSumcheck;
        let inner = InnerSumcheck::new_verifier::<C, ProofTranscript, PCS>(sm);
        vec![Box::new(inner)]
    }

    pub fn stage3_verifier_instances<C: JoltCurve, ProofTranscript: Transcript, PCS: CommitmentScheme<Field = F>>(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Vec<Box<dyn SumcheckInstance<F, ProofTranscript>>> {
        use crate::zkvm::spartan::pc::PCSumcheck;
        use crate::zkvm::spartan::product::ProductVirtualizationSumcheck;

        let accumulator = sm.get_verifier_accumulator();
        let acc = accumulator.borrow();

        let gamma_pc: F = sm.transcript.borrow_mut().challenge_scalar();
        let (r_cycle_point, next_pc_eval) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::NextPC, SumcheckId::SpartanOuter);
        let (_, next_unexpanded_pc_eval) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::NextUnexpandedPC, SumcheckId::SpartanOuter);
        let (_, next_is_noop_eval) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::NextIsNoop, SumcheckId::SpartanOuter);
        drop(acc);

        let input_claim_pc = next_unexpanded_pc_eval + gamma_pc * next_pc_eval + gamma_pc.square() * next_is_noop_eval;
        let spartan_pc = PCSumcheck::<F>::new_verifier_from_openings(input_claim_pc, gamma_pc, r_cycle_point.r.len());
        let spartan_product = ProductVirtualizationSumcheck::<F>::new_verifier::<C, ProofTranscript, PCS>(sm);

        vec![Box::new(spartan_pc), Box::new(spartan_product)]
    }
}

// ---------------------------------------------------------------------------
// RegistersDag
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct RegistersDag;

impl RegistersDag {
    pub fn stage2_verifier_instances<
        F: JoltField,
        C: JoltCurve,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F>,
    >(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Vec<Box<dyn SumcheckInstance<F, ProofTranscript>>> {
        use crate::zkvm::registers::read_write_checking::RegistersReadWriteChecking;
        let rwc = RegistersReadWriteChecking::new_verifier::<C, ProofTranscript, PCS>(sm);
        vec![Box::new(rwc)]
    }

    pub fn stage3_verifier_instances<
        F: JoltField,
        C: JoltCurve,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F>,
    >(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Vec<Box<dyn SumcheckInstance<F, ProofTranscript>>> {
        use crate::zkvm::registers::val_evaluation::ValEvaluationSumcheck;
        let val_eval = ValEvaluationSumcheck::new_verifier::<C, ProofTranscript, PCS>(sm);
        vec![Box::new(val_eval)]
    }
}

// ---------------------------------------------------------------------------
// RamDag
// ---------------------------------------------------------------------------

pub struct RamDag {
    initial_ram_state: Vec<u64>,
}

impl RamDag {
    pub fn new_verifier<F: JoltField, C: JoltCurve, ProofTranscript: Transcript, PCS: CommitmentScheme<Field = F>>(
        sm: &StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Self {
        let initial_ram_state =
            crate::zkvm::ram::build_initial_memory_state(&sm.preprocessing.shared.ram, &sm.program_io, sm.ram_K);
        Self { initial_ram_state }
    }

    pub fn stage2_verifier_instances<
        F: JoltField,
        C: JoltCurve,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F>,
    >(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Vec<Box<dyn SumcheckInstance<F, ProofTranscript>>> {
        use crate::zkvm::ram::output_check::OutputSumcheck;
        use crate::zkvm::ram::raf_evaluation::RafEvaluationSumcheck;
        use crate::zkvm::ram::read_write_checking::RamReadWriteChecking;

        let K = sm.ram_K;
        let accumulator = sm.get_verifier_accumulator();
        let raf_claim = accumulator
            .borrow()
            .get_virtual_polynomial_opening(VirtualPolynomial::RamAddress, SumcheckId::SpartanOuter)
            .1;
        let _start_address = sm.preprocessing.shared.ram.min_bytecode_address;
        let ra_claim = accumulator
            .borrow()
            .get_virtual_polynomial_opening(VirtualPolynomial::RamRa, SumcheckId::RamRafEvaluation)
            .1;
        let raf = RafEvaluationSumcheck::new_verifier_from_parts(
            raf_claim,
            K.log_2(),
            sm.program_io.memory_layout.trusted_advice_start,
            ra_claim,
        );
        let rwc = RamReadWriteChecking::new_verifier::<C, ProofTranscript, PCS>(sm);
        let output = OutputSumcheck::new_verifier::<C, ProofTranscript, PCS>(sm);

        vec![Box::new(raf), Box::new(rwc), Box::new(output)]
    }

    pub fn stage3_verifier_instances<
        F: JoltField,
        C: JoltCurve,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F>,
    >(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Vec<Box<dyn SumcheckInstance<F, ProofTranscript>>> {
        use crate::zkvm::ram::hamming_booleanity::HammingBooleanitySumcheck;
        use crate::zkvm::ram::output_check::ValFinalSumcheck;
        use crate::zkvm::ram::val_evaluation::ValEvaluationSumcheck;

        let val_eval = ValEvaluationSumcheck::new_verifier::<C, ProofTranscript, PCS>(&self.initial_ram_state, sm);
        let val_final = ValFinalSumcheck::new_verifier::<C, ProofTranscript, PCS>(&self.initial_ram_state, sm);
        let log_T = sm.trace_length.log_2();
        let hamming_bool = HammingBooleanitySumcheck::<F>::new_verifier_from_parts(log_T);

        vec![Box::new(val_eval), Box::new(val_final), Box::new(hamming_bool)]
    }

    pub fn stage4_verifier_instances<
        F: JoltField,
        C: JoltCurve,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F>,
    >(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Vec<Box<dyn SumcheckInstance<F, ProofTranscript>>> {
        use crate::zkvm::ram::booleanity::BooleanitySumcheck;
        use crate::zkvm::ram::hamming_weight::HammingWeightSumcheck;
        use crate::zkvm::ram::ra_virtual::RaSumcheck;
        use crate::zkvm::witness::{compute_d_parameter, DTH_ROOT_OF_K};

        let ram_K = sm.ram_K;
        let d = compute_d_parameter(ram_K);
        let log_K = ram_K.log_2();
        let T = sm.trace_length;

        // HammingWeight
        let hamming_gamma: F = sm.transcript.borrow_mut().challenge_scalar();
        let mut hamming_gamma_powers = vec![F::one(); d];
        for i in 1..d {
            hamming_gamma_powers[i] = hamming_gamma_powers[i - 1] * hamming_gamma;
        }
        let accumulator = sm.get_verifier_accumulator();
        let (_, hamming_booleanity_claim) = accumulator
            .borrow()
            .get_virtual_polynomial_opening(VirtualPolynomial::RamHammingWeight, SumcheckId::RamHammingBooleanity);
        let hamming_input_claim = hamming_booleanity_claim * hamming_gamma_powers.iter().sum::<F>();
        let hamming_weight = HammingWeightSumcheck::new_verifier_from_parts(hamming_gamma_powers, hamming_input_claim);

        // Booleanity
        let bool_r_cycle: Vec<F::Challenge> = sm.transcript.borrow_mut().challenge_vector_optimized::<F>(T.log_2());
        let bool_r_address: Vec<F::Challenge> =
            sm.transcript.borrow_mut().challenge_vector_optimized::<F>(DTH_ROOT_OF_K.log_2());
        let bool_gamma: F = sm.transcript.borrow_mut().challenge_scalar();
        let mut bool_gamma_powers = vec![F::one(); d];
        for i in 1..d {
            bool_gamma_powers[i] = bool_gamma_powers[i - 1] * bool_gamma;
        }
        let booleanity =
            BooleanitySumcheck::new_verifier_from_parts(d, T, bool_r_cycle, bool_r_address, bool_gamma_powers);

        // RaSumcheck
        let acc = accumulator.borrow();
        let (r_val, ra_claim_val) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::RamRa, SumcheckId::RamValFinalEvaluation);
        let (r_address_val, r_cycle_val) = r_val.split_at_r(log_K);
        let (r_rw, ra_claim_rw) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::RamRa, SumcheckId::RamReadWriteChecking);
        let (_, r_cycle_rw) = r_rw.split_at_r(log_K);
        let (r_raf, ra_claim_raf) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::RamRa, SumcheckId::RamRafEvaluation);
        let (_, r_cycle_raf) = r_raf.split_at_r(log_K);
        drop(acc);

        let r_address = if r_address_val.len() % DTH_ROOT_OF_K.log_2() == 0 {
            r_address_val.to_vec()
        } else {
            let pad = DTH_ROOT_OF_K.log_2() - (r_address_val.len() % DTH_ROOT_OF_K.log_2());
            [&vec![F::Challenge::from(0_u128); pad], r_address_val].concat()
        };
        let r_address_chunks: Vec<Vec<F::Challenge>> =
            r_address.chunks(DTH_ROOT_OF_K.log_2()).map(|c| c.to_vec()).collect();

        let ra_gamma: F = sm.transcript.borrow_mut().challenge_scalar();
        let ra_gamma_arr = [F::one(), ra_gamma, ra_gamma.square()];
        let combined_ra_claim =
            ra_gamma_arr[0] * ra_claim_val + ra_gamma_arr[1] * ra_claim_rw + ra_gamma_arr[2] * ra_claim_raf;

        let ra_virtual = RaSumcheck::new_verifier_from_parts(
            ra_gamma_arr,
            combined_ra_claim,
            d,
            T,
            [r_cycle_val.to_vec(), r_cycle_rw.to_vec(), r_cycle_raf.to_vec()],
            r_address_chunks,
        );

        vec![Box::new(hamming_weight), Box::new(booleanity), Box::new(ra_virtual)]
    }
}

// ---------------------------------------------------------------------------
// LookupsDag
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct LookupsDag;

impl LookupsDag {
    pub fn stage2_verifier_instances<
        F: JoltField,
        C: JoltCurve,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F>,
    >(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Vec<Box<dyn SumcheckInstance<F, ProofTranscript>>> {
        use crate::zkvm::instruction_lookups::booleanity::BooleanitySumcheck;
        use crate::zkvm::instruction_lookups::{D, LOG_K_CHUNK};

        let accumulator = sm.get_verifier_accumulator();
        let log_T = accumulator
            .borrow()
            .get_virtual_polynomial_opening(VirtualPolynomial::LookupOutput, SumcheckId::SpartanOuter)
            .0
            .r
            .len();

        // Draw gamma and r_address from transcript (matches coordinator)
        let gamma: F = sm.transcript.borrow_mut().challenge_scalar();
        let mut gamma_powers = [F::one(); D];
        for i in 1..D {
            gamma_powers[i] = gamma_powers[i - 1] * gamma;
        }
        let r_address: Vec<F::Challenge> = sm.transcript.borrow_mut().challenge_vector_optimized::<F>(LOG_K_CHUNK);

        let booleanity = BooleanitySumcheck::new_verifier_from_parts(gamma_powers, r_address, log_T);

        vec![Box::new(booleanity)]
    }

    pub fn stage3_verifier_instances<
        F: JoltField,
        C: JoltCurve,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F>,
    >(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Vec<Box<dyn SumcheckInstance<F, ProofTranscript>>> {
        use crate::zkvm::instruction_lookups::hamming_weight::HammingWeightSumcheck;
        use crate::zkvm::instruction_lookups::read_raf_checking::ReadRafSumcheck;
        use crate::zkvm::instruction_lookups::D;

        let accumulator = sm.get_verifier_accumulator();
        let acc = accumulator.borrow();

        let (_, rv_claim) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::LookupOutput, SumcheckId::SpartanOuter);
        let (_, left_operand_claim) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::LeftLookupOperand, SumcheckId::SpartanOuter);
        let (_, right_operand_claim) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::RightLookupOperand, SumcheckId::SpartanOuter);
        let log_T =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::LookupOutput, SumcheckId::SpartanOuter).0.r.len();
        drop(acc);

        let read_raf = ReadRafSumcheck::new_verifier(
            &mut *sm.transcript.borrow_mut(),
            rv_claim,
            left_operand_claim,
            right_operand_claim,
            log_T,
        );

        // HammingWeight: draw gamma from transcript
        let gamma: F = sm.transcript.borrow_mut().challenge_scalar();
        let mut gamma_powers = [F::one(); D];
        for i in 1..D {
            gamma_powers[i] = gamma_powers[i - 1] * gamma;
        }
        let hamming_weight = HammingWeightSumcheck::new_verifier_from_parts(gamma_powers);

        vec![Box::new(read_raf), Box::new(hamming_weight)]
    }

    pub fn stage4_verifier_instances<
        F: JoltField,
        C: JoltCurve,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F>,
    >(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Vec<Box<dyn SumcheckInstance<F, ProofTranscript>>> {
        use crate::zkvm::instruction_lookups::ra_virtual::InstructionRaSumcheck;
        use crate::zkvm::instruction_lookups::{D, LOG_K_CHUNK};

        let accumulator = sm.get_verifier_accumulator();
        let acc = accumulator.borrow();

        let (ra_point, ra_claim) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::InstructionRa, SumcheckId::InstructionReadRaf);
        let (r_address, r_cycle) = ra_point.r.split_at(D * LOG_K_CHUNK);
        let r_address_chunks: Vec<Vec<F::Challenge>> = r_address.chunks(LOG_K_CHUNK).map(|c| c.to_vec()).collect();
        drop(acc);

        let ra = InstructionRaSumcheck::new(ra_claim, r_cycle.to_vec(), r_address_chunks);
        vec![Box::new(ra)]
    }
}

// ---------------------------------------------------------------------------
// BytecodeDag
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct BytecodeDag;

impl BytecodeDag {
    pub fn stage4_verifier_instances<
        F: JoltField,
        C: JoltCurve,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F>,
    >(
        &mut self,
        sm: &mut StateManager<'_, F, C, ProofTranscript, PCS>,
    ) -> Vec<Box<dyn SumcheckInstance<F, ProofTranscript>>> {
        use crate::zkvm::bytecode::booleanity::BooleanitySumcheck as BytecodeBooleanity;
        use crate::zkvm::bytecode::hamming_weight::HammingWeightSumcheck as BytecodeHammingWeight;
        use crate::zkvm::bytecode::read_raf_checking::ReadRafSumcheck as BytecodeReadRaf;
        use crate::zkvm::instruction::CircuitFlags;
        use crate::zkvm::lookup_table::LookupTables;
        use strum::EnumCount;

        let K = sm.preprocessing.shared.bytecode.code_size;
        let log_K = K.log_2();
        let d = sm.preprocessing.shared.bytecode.d;
        let log_K_chunk = log_K.div_ceil(d);
        let log_T = sm.trace_length.log_2();

        let accumulator = sm.get_verifier_accumulator();

        // ReadRaf: draw gamma from transcript
        let read_raf_gamma: F = sm.transcript.borrow_mut().challenge_scalar();
        let read_raf_gamma_sqr = read_raf_gamma.square();
        let read_raf_gamma_cub = read_raf_gamma_sqr * read_raf_gamma;
        let read_raf_gamma_four = read_raf_gamma_sqr.square();

        // Stage1 gamma_powers + rv_claim
        let gamma_powers_1 = crate::zkvm::bytecode::read_raf_checking::get_gamma_powers::<F>(
            &mut *sm.transcript.borrow_mut(),
            3 + crate::zkvm::instruction::NUM_CIRCUIT_FLAGS,
        );
        let acc = accumulator.borrow();
        let (_, unexpanded_pc_claim_1) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::UnexpandedPC, SumcheckId::SpartanOuter);
        let (_, imm_claim_1) = acc.get_virtual_polynomial_opening(VirtualPolynomial::Imm, SumcheckId::SpartanOuter);
        let (_, rd_claim_1) = acc.get_virtual_polynomial_opening(VirtualPolynomial::Rd, SumcheckId::SpartanOuter);
        let mut rv_claim_1 = gamma_powers_1[0] * unexpanded_pc_claim_1
            + gamma_powers_1[1] * imm_claim_1
            + gamma_powers_1[2] * rd_claim_1;
        for (i, flag) in CircuitFlags::iter().enumerate() {
            let (_, flag_claim) =
                acc.get_virtual_polynomial_opening(VirtualPolynomial::OpFlags(flag), SumcheckId::SpartanOuter);
            rv_claim_1 += gamma_powers_1[3 + i] * flag_claim;
        }
        drop(acc);

        // Stage2 gamma_powers
        let gamma_powers_2 =
            crate::zkvm::bytecode::read_raf_checking::get_gamma_powers::<F>(&mut *sm.transcript.borrow_mut(), 3);
        let acc = accumulator.borrow();
        let (_, rdwa_claim_2) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::RdWa, SumcheckId::RegistersReadWriteChecking);
        let (_, rs1ra_claim_2) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::Rs1Ra, SumcheckId::RegistersReadWriteChecking);
        let (_, rs2ra_claim_2) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::Rs2Ra, SumcheckId::RegistersReadWriteChecking);
        let rv_claim_2 =
            gamma_powers_2[0] * rdwa_claim_2 + gamma_powers_2[1] * rs1ra_claim_2 + gamma_powers_2[2] * rs2ra_claim_2;

        // Stage3 gamma_powers
        drop(acc);
        let gamma_powers_3 = crate::zkvm::bytecode::read_raf_checking::get_gamma_powers::<F>(
            &mut *sm.transcript.borrow_mut(),
            4 + LookupTables::<XLEN>::COUNT,
        );
        let acc = accumulator.borrow();
        let (_, rd_wa_claim_3) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::RdWa, SumcheckId::RegistersValEvaluation);
        let (_, unexpanded_pc_claim_3) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::UnexpandedPC, SumcheckId::SpartanShift);
        let (_, is_noop_claim_3) = acc
            .get_virtual_polynomial_opening(VirtualPolynomial::OpFlags(CircuitFlags::IsNoop), SumcheckId::SpartanShift);
        let (_, raf_flag_claim_3) =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::InstructionRafFlag, SumcheckId::InstructionReadRaf);
        let mut rv_claim_3 = gamma_powers_3[0] * rd_wa_claim_3
            + gamma_powers_3[1] * unexpanded_pc_claim_3
            + gamma_powers_3[2] * is_noop_claim_3
            + gamma_powers_3[3] * raf_flag_claim_3;
        for i in 0..LookupTables::<XLEN>::COUNT {
            let (_, lt_claim) = acc
                .get_virtual_polynomial_opening(VirtualPolynomial::LookupTableFlag(i), SumcheckId::InstructionReadRaf);
            rv_claim_3 += gamma_powers_3[4 + i] * lt_claim;
        }

        let (_, raf_claim) = acc.get_virtual_polynomial_opening(VirtualPolynomial::PC, SumcheckId::SpartanOuter);
        let (_, raf_shift_claim) = acc.get_virtual_polynomial_opening(VirtualPolynomial::PC, SumcheckId::SpartanShift);
        drop(acc);

        let rv_claim = rv_claim_1
            + read_raf_gamma * rv_claim_2
            + read_raf_gamma_sqr * rv_claim_3
            + read_raf_gamma_cub * raf_claim
            + read_raf_gamma_four * raf_shift_claim;

        // Compute val polynomials from bytecode preprocessing
        let bytecode = &sm.preprocessing.shared.bytecode.bytecode;
        let val_1 = BytecodeReadRaf::<F>::compute_val_1_from_bytecode(bytecode, &gamma_powers_1);

        // Val2 needs eq_r_register
        let acc = accumulator.borrow();
        let r_register_2 =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::RdWa, SumcheckId::RegistersReadWriteChecking).0.r;
        drop(acc);
        let eq_r_register_2 =
            EqPolynomial::<F>::evals(&r_register_2[..(crate::common::constants::REGISTER_COUNT as usize).log_2()]);
        let val_2 = BytecodeReadRaf::<F>::compute_val_2_from_bytecode(bytecode, &gamma_powers_2, &eq_r_register_2);

        // Val3 needs eq_r_register from val evaluation
        let acc = accumulator.borrow();
        let r_register_3 =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::RdWa, SumcheckId::RegistersValEvaluation).0.r;
        drop(acc);
        let eq_r_register_3 =
            EqPolynomial::<F>::evals(&r_register_3[..(crate::common::constants::REGISTER_COUNT as usize).log_2()]);
        let val_3 = BytecodeReadRaf::<F>::compute_val_3_from_bytecode(bytecode, &gamma_powers_3, &eq_r_register_3);

        // r_cycles from accumulator
        let acc = accumulator.borrow();
        let _r_cycle_1 = acc.get_virtual_polynomial_opening(VirtualPolynomial::Imm, SumcheckId::SpartanOuter).0.r;
        let r_2 =
            acc.get_virtual_polynomial_opening(VirtualPolynomial::Rs1Ra, SumcheckId::RegistersReadWriteChecking).0;
        let (_, _r_cycle_2) = r_2.split_at_r((crate::common::constants::REGISTER_COUNT as usize).log_2());
        let r_3 = acc.get_virtual_polynomial_opening(VirtualPolynomial::RdWa, SumcheckId::RegistersValEvaluation).0;
        let (_, _r_cycle_3) = r_3.split_at_r((crate::common::constants::REGISTER_COUNT as usize).log_2());
        drop(acc);

        let val_polys = [val_1, val_2, val_3];
        let read_raf = BytecodeReadRaf::new_verifier_from_parts(
            read_raf_gamma,
            rv_claim,
            log_K,
            log_T,
            d,
            [gamma_powers_1.clone(), gamma_powers_2.clone(), gamma_powers_3.clone()],
            val_polys,
        );

        // Booleanity
        let bool_gamma: F = sm.transcript.borrow_mut().challenge_scalar();
        let mut bool_gamma_powers = vec![F::one(); d];
        for i in 1..d {
            bool_gamma_powers[i] = bool_gamma_powers[i - 1] * bool_gamma;
        }
        let bool_r_address: Vec<F::Challenge> = sm.transcript.borrow_mut().challenge_vector_optimized::<F>(log_K_chunk);
        let booleanity =
            BytecodeBooleanity::new_verifier_from_parts(bool_gamma_powers, bool_r_address, log_T, log_K_chunk);

        // HammingWeight
        let hw_gamma: F = sm.transcript.borrow_mut().challenge_scalar();
        let mut hw_gamma_powers = vec![F::one(); d];
        for i in 1..d {
            hw_gamma_powers[i] = hw_gamma_powers[i - 1] * hw_gamma;
        }
        let hamming_weight = BytecodeHammingWeight::new_verifier_from_parts(hw_gamma_powers, log_K_chunk);

        vec![Box::new(read_raf), Box::new(booleanity), Box::new(hamming_weight)]
    }
}

// ---------------------------------------------------------------------------
// JoltDAG
// ---------------------------------------------------------------------------

pub enum JoltDAG {}

#[cfg(feature = "zk")]
struct StageBlindfoldVerifyData<F: JoltField> {
    batching_coefficients: Vec<F>,
    challenges: Vec<F::Challenge>,
    output_claim_ids: Vec<OpeningId>,
}

impl JoltDAG {
    #[tracing::instrument(skip_all, level = "trace", name = "JoltDAG::verify")]
    pub fn verify<
        'a,
        F: JoltField,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F> + ZkEvalCommitment<Bn254Curve>,
    >(
        mut state_manager: StateManager<'a, F, Bn254Curve, ProofTranscript, PCS>,
    ) -> Result<(), anyhow::Error> {
        state_manager.fiat_shamir_preamble();

        let ram_K = state_manager.ram_K;
        let bytecode_d = state_manager.get_verifier_data().0.shared.bytecode.d;
        let _guard = AllCommittedPolynomials::initialize(compute_d_parameter(ram_K), bytecode_d);

        // Append commitments to transcript
        let commitments = state_manager.get_commitments();
        let transcript = state_manager.get_transcript();
        for commitment in commitments.borrow().iter() {
            transcript.borrow_mut().append_serializable(commitment);
        }

        // Append untrusted advice commitment to transcript
        if let Some(ref untrusted_advice_commitment) = state_manager.untrusted_advice_commitment {
            transcript.borrow_mut().append_serializable(untrusted_advice_commitment);
        }
        // Append trusted advice commitment to transcript
        if let Some(ref trusted_advice_commitment) = state_manager.trusted_advice_commitment {
            transcript.borrow_mut().append_serializable(trusted_advice_commitment);
        }

        // Stage 1:
        let trace_length = state_manager.get_verifier_data().2;
        let padded_trace_length = trace_length.next_power_of_two();
        let mut spartan_dag = SpartanDag::<F>::new::<ProofTranscript>(padded_trace_length);
        let mut lookups_dag = LookupsDag::default();
        let mut registers_dag = RegistersDag::default();
        let mut ram_dag = RamDag::new_verifier(&state_manager);
        let mut bytecode_dag = BytecodeDag::default();
        #[cfg(feature = "zk")]
        let stage1_blindfold = spartan_dag.stage1_verify(&mut state_manager).context("Stage 1")?;
        #[cfg(not(feature = "zk"))]
        spartan_dag.stage1_verify(&mut state_manager).context("Stage 1")?;

        // Stage 2:
        let stage2_instances: Vec<_> = std::iter::empty()
            .chain(spartan_dag.stage2_verifier_instances(&mut state_manager))
            .chain(registers_dag.stage2_verifier_instances(&mut state_manager))
            .chain(ram_dag.stage2_verifier_instances(&mut state_manager))
            .chain(lookups_dag.stage2_verifier_instances(&mut state_manager))
            .collect();
        let stage2_instances_ref: Vec<&dyn SumcheckInstance<F, ProofTranscript>> =
            stage2_instances.iter().map(|instance| &**instance as &dyn SumcheckInstance<F, ProofTranscript>).collect();

        let proofs = state_manager.proofs.borrow();
        let stage2_proof_data = proofs.get(&ProofKeys::Stage2Sumcheck).expect("Stage 2 sumcheck proof not found");
        let stage2_proof = match stage2_proof_data {
            ProofData::SumcheckProof(proof) => proof,
            _ => panic!("Invalid proof type for stage 2"),
        };

        let transcript = state_manager.get_transcript();
        let opening_accumulator = state_manager.get_verifier_accumulator();
        let (stage2_batching_coeffs, r_stage2, stage2_output_claim_ids) = BatchedSumcheck::verify(
            stage2_proof,
            stage2_instances_ref,
            Some(opening_accumulator.clone()),
            &mut *transcript.borrow_mut(),
        )
        .context("Stage 2")?;

        drop(proofs);

        // Stage 3:
        let stage3_instances: Vec<_> = std::iter::empty()
            .chain(spartan_dag.stage3_verifier_instances(&mut state_manager))
            .chain(registers_dag.stage3_verifier_instances(&mut state_manager))
            .chain(lookups_dag.stage3_verifier_instances(&mut state_manager))
            .chain(ram_dag.stage3_verifier_instances(&mut state_manager))
            .collect();
        let stage3_instances_ref: Vec<&dyn SumcheckInstance<F, ProofTranscript>> =
            stage3_instances.iter().map(|instance| &**instance as &dyn SumcheckInstance<F, ProofTranscript>).collect();

        let proofs = state_manager.proofs.borrow();
        let stage3_proof_data = proofs.get(&ProofKeys::Stage3Sumcheck).expect("Stage 3 sumcheck proof not found");
        let stage3_proof = match stage3_proof_data {
            ProofData::SumcheckProof(proof) => proof,
            _ => panic!("Invalid proof type for stage 3"),
        };

        let (stage3_batching_coeffs, r_stage3, stage3_output_claim_ids) = BatchedSumcheck::verify(
            stage3_proof,
            stage3_instances_ref,
            Some(opening_accumulator.clone()),
            &mut *transcript.borrow_mut(),
        )
        .context("Stage 3")?;

        drop(proofs);

        // Stage 4:
        let stage4_instances: Vec<_> = std::iter::empty()
            .chain(ram_dag.stage4_verifier_instances(&mut state_manager))
            .chain(bytecode_dag.stage4_verifier_instances(&mut state_manager))
            .chain(lookups_dag.stage4_verifier_instances(&mut state_manager))
            .collect();
        let stage4_instances_ref: Vec<&dyn SumcheckInstance<F, ProofTranscript>> =
            stage4_instances.iter().map(|instance| &**instance as &dyn SumcheckInstance<F, ProofTranscript>).collect();

        let proofs = state_manager.proofs.borrow();
        let stage4_proof_data = proofs.get(&ProofKeys::Stage4Sumcheck).expect("Stage 4 sumcheck proof not found");
        let stage4_proof = match stage4_proof_data {
            ProofData::SumcheckProof(proof) => proof,
            _ => panic!("Invalid proof type for stage 4"),
        };

        let (stage4_batching_coeffs, r_stage4, stage4_output_claim_ids) = BatchedSumcheck::verify(
            stage4_proof,
            stage4_instances_ref,
            Some(opening_accumulator.clone()),
            &mut *transcript.borrow_mut(),
        )
        .context("Stage 4")?;

        // Verify trusted_advice opening proofs
        if state_manager.trusted_advice_commitment.is_some() {
            Self::verify_trusted_advice_proofs(
                &state_manager,
                &state_manager.preprocessing.generators,
                &mut *transcript.borrow_mut(),
            )
            .context("Stage 5")?;
        }

        // Verify untrusted_advice opening proofs
        if state_manager.untrusted_advice_commitment.is_some() {
            Self::verify_untrusted_advice_proofs(
                &state_manager,
                &state_manager.preprocessing.generators,
                &mut *transcript.borrow_mut(),
            )
            .context("Stage 5")?;
        }

        {
            // Batch-prove all openings
            let batched_opening_proof =
                proofs.get(&ProofKeys::ReducedOpeningProof).expect("Reduced opening proof not found");
            let batched_opening_proof = match batched_opening_proof {
                ProofData::ReducedOpeningProof(proof) => proof,
                _ => panic!("Invalid proof type for stage 4"),
            };
            let stage5_eval_commitment = PCS::eval_commitment(&batched_opening_proof.joint_opening_proof)
                .ok_or_else(|| anyhow::anyhow!("missing eval commitment"))?;

            let mut commitments_map = HashMap::new();
            for polynomial in AllCommittedPolynomials::iter() {
                commitments_map.insert(*polynomial, commitments.borrow()[polynomial.to_index()].clone());
            }
            let accumulator = state_manager.get_verifier_accumulator();
            accumulator
                .borrow_mut()
                .reduce_and_verify(
                    &state_manager.preprocessing.generators,
                    &mut commitments_map,
                    batched_opening_proof,
                    &mut *transcript.borrow_mut(),
                )
                .context("Stage 5")?;
            drop(proofs);

            #[cfg(feature = "zk")]
            if state_manager.blindfold_proof.is_some() {
                Self::verify_blindfold::<F, ProofTranscript, PCS>(
                    &mut state_manager,
                    stage1_blindfold,
                    &stage2_instances,
                    StageBlindfoldVerifyData {
                        batching_coefficients: stage2_batching_coeffs,
                        challenges: r_stage2,
                        output_claim_ids: stage2_output_claim_ids,
                    },
                    &stage3_instances,
                    StageBlindfoldVerifyData {
                        batching_coefficients: stage3_batching_coeffs,
                        challenges: r_stage3,
                        output_claim_ids: stage3_output_claim_ids,
                    },
                    &stage4_instances,
                    StageBlindfoldVerifyData {
                        batching_coefficients: stage4_batching_coeffs,
                        challenges: r_stage4,
                        output_claim_ids: stage4_output_claim_ids,
                    },
                    stage5_eval_commitment,
                )
                .context("BlindFold")?;
            }
        }

        Ok(())
    }

    #[cfg(feature = "zk")]
    #[allow(clippy::too_many_arguments)]
    fn verify_blindfold<
        'a,
        F: JoltField,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F> + ZkEvalCommitment<Bn254Curve>,
    >(
        state_manager: &mut StateManager<'a, F, Bn254Curve, ProofTranscript, PCS>,
        stage1_data: Stage1BlindfoldData<F>,
        stage2_instances: &[Box<dyn SumcheckInstance<F, ProofTranscript>>],
        stage2_data: StageBlindfoldVerifyData<F>,
        stage3_instances: &[Box<dyn SumcheckInstance<F, ProofTranscript>>],
        stage3_data: StageBlindfoldVerifyData<F>,
        stage4_instances: &[Box<dyn SumcheckInstance<F, ProofTranscript>>],
        stage4_data: StageBlindfoldVerifyData<F>,
        stage5_eval_commitment: <Bn254Curve as JoltCurve>::G1,
    ) -> Result<(), anyhow::Error> {
        let opening_data = state_manager
            .get_verifier_accumulator()
            .borrow_mut()
            .take_blindfold_opening_data()
            .ok_or_else(|| anyhow::anyhow!("missing BlindFold opening reduction data"))?;

        let stage2_input_constraint = InputClaimConstraint::batch_required(
            &stage2_instances.iter().map(|instance| instance.input_claim_constraint()).collect::<Vec<_>>(),
            stage2_data.batching_coefficients.len(),
        );
        let stage3_input_constraint = InputClaimConstraint::batch_required(
            &stage3_instances.iter().map(|instance| instance.input_claim_constraint()).collect::<Vec<_>>(),
            stage3_data.batching_coefficients.len(),
        );
        let stage4_input_constraint = InputClaimConstraint::batch_required(
            &stage4_instances.iter().map(|instance| instance.input_claim_constraint()).collect::<Vec<_>>(),
            stage4_data.batching_coefficients.len(),
        );
        let stage2_output_constraint = OutputClaimConstraint::batch(
            &stage2_instances.iter().map(|instance| instance.output_claim_constraint()).collect::<Vec<_>>(),
        );
        let stage3_output_constraint = OutputClaimConstraint::batch(
            &stage3_instances.iter().map(|instance| instance.output_claim_constraint()).collect::<Vec<_>>(),
        );
        let stage4_output_constraint = OutputClaimConstraint::batch(
            &stage4_instances.iter().map(|instance| instance.output_claim_constraint()).collect::<Vec<_>>(),
        );

        let stage2_input_challenges = Self::batched_input_challenge_values(
            stage2_instances,
            &stage2_data,
            state_manager.get_verifier_accumulator(),
        );
        let stage3_input_challenges = Self::batched_input_challenge_values(
            stage3_instances,
            &stage3_data,
            state_manager.get_verifier_accumulator(),
        );
        let stage4_input_challenges = Self::batched_input_challenge_values(
            stage4_instances,
            &stage4_data,
            state_manager.get_verifier_accumulator(),
        );
        let stage2_output_challenges = Self::batched_output_challenge_values(stage2_instances, &stage2_data);
        let stage3_output_challenges = Self::batched_output_challenge_values(stage3_instances, &stage3_data);
        let stage4_output_challenges = Self::batched_output_challenge_values(stage4_instances, &stage4_data);

        let proofs = state_manager.proofs.borrow();
        let stage1_proof = Self::sumcheck_proof(&proofs, ProofKeys::Stage1Sumcheck)?;
        let stage2_proof = Self::sumcheck_proof(&proofs, ProofKeys::Stage2Sumcheck)?;
        let stage3_proof = Self::sumcheck_proof(&proofs, ProofKeys::Stage3Sumcheck)?;
        let stage4_proof = Self::sumcheck_proof(&proofs, ProofKeys::Stage4Sumcheck)?;

        let stage1_eq_eval = crate::poly::eq_poly::EqPolynomial::<F>::mle(
            &stage1_data.tau,
            &stage1_data.challenges.iter().rev().copied().collect::<Vec<_>>(),
        );

        let stage_proofs = [stage1_proof, stage2_proof, stage3_proof, stage4_proof];
        let blindfold_hyrax_c = stage_proofs
            .iter()
            .map(|proof| match proof {
                SumcheckInstanceProof::Zk(zk_proof) => {
                    zk_proof.poly_degrees.iter().map(|degree| degree + 1).max().unwrap_or(1)
                }
                SumcheckInstanceProof::Clear(_) => 1,
            })
            .max()
            .unwrap_or(1)
            .next_power_of_two();
        let _stage_batching_coeffs = [
            vec![F::one()],
            stage2_data.batching_coefficients.clone(),
            stage3_data.batching_coefficients.clone(),
            stage4_data.batching_coefficients.clone(),
        ];
        let stage_input_constraints = [
            InputClaimConstraint::default(),
            stage2_input_constraint,
            stage3_input_constraint,
            stage4_input_constraint,
        ];
        let stage_input_challenges =
            [vec![], stage2_input_challenges, stage3_input_challenges, stage4_input_challenges];
        let stage_output_constraints = [
            Some(Self::stage1_output_constraint()),
            stage2_output_constraint,
            stage3_output_constraint,
            stage4_output_constraint,
        ];
        let stage_output_challenges = [
            Some(vec![F::one(), stage1_eq_eval]),
            stage2_output_challenges,
            stage3_output_challenges,
            stage4_output_challenges,
        ];
        let stage_sumcheck_challenges = [
            stage1_data.challenges.clone(),
            stage2_data.challenges.clone(),
            stage3_data.challenges.clone(),
            stage4_data.challenges.clone(),
        ];
        let oc_blocks = vec![
            stage1_data.output_claim_ids,
            stage2_data.output_claim_ids,
            stage3_data.output_claim_ids,
            stage4_data.output_claim_ids,
        ];
        let initial_claims = vec![
            F::zero(),
            Self::batched_initial_claim(stage2_instances, &stage2_data.batching_coefficients),
            Self::batched_initial_claim(stage3_instances, &stage3_data.batching_coefficients),
            Self::batched_initial_claim(stage4_instances, &stage4_data.batching_coefficients),
        ];

        let mut stage_configs = Vec::new();
        let mut baked_challenges = Vec::new();
        let mut baked_input_challenges = Vec::new();
        let mut baked_output_challenges = Vec::new();
        let mut round_commitments = Vec::new();
        let mut output_claims_row_commitments = Vec::new();

        for stage_idx in 0..4 {
            let zk_proof = match stage_proofs[stage_idx] {
                SumcheckInstanceProof::Zk(zk_proof) => zk_proof,
                SumcheckInstanceProof::Clear(_) => {
                    return Err(anyhow::anyhow!("BlindFold requires ZK DAG sumcheck proofs"));
                }
            };
            let oc_block_rows = oc_blocks[stage_idx].len().div_ceil(blindfold_hyrax_c);
            anyhow::ensure!(
                zk_proof.output_claims_commitments.len() == oc_block_rows,
                "BlindFold stage {} OC rows mismatch: proof has {}, verifier reconstructed {} rows from {} claims",
                stage_idx + 1,
                zk_proof.output_claims_commitments.len(),
                oc_block_rows,
                oc_blocks[stage_idx].len(),
            );

            round_commitments.extend_from_slice(&zk_proof.round_commitments);
            output_claims_row_commitments.extend_from_slice(&zk_proof.output_claims_commitments);
            baked_input_challenges.extend_from_slice(&stage_input_challenges[stage_idx]);
            if let Some(values) = &stage_output_challenges[stage_idx] {
                baked_output_challenges.extend_from_slice(values);
            }

            for (round_idx, poly_degree) in zk_proof.poly_degrees.iter().copied().enumerate() {
                let mut config = if round_idx == 0 {
                    StageConfig::new_chain(1, poly_degree)
                } else {
                    StageConfig::new(1, poly_degree)
                };
                if round_idx == 0 && !stage_input_constraints[stage_idx].terms.is_empty() {
                    config = config.with_input_constraint(stage_input_constraints[stage_idx].clone());
                }
                if round_idx + 1 == zk_proof.poly_degrees.len() {
                    if let Some(constraint) = &stage_output_constraints[stage_idx] {
                        config = config.with_constraint(constraint.clone());
                    }
                }
                stage_configs.push(config);
                baked_challenges.push(stage_sumcheck_challenges[stage_idx][round_idx].into());
            }
        }

        let extra_constraint = OutputClaimConstraint::linear(
            opening_data
                .opening_ids
                .iter()
                .enumerate()
                .map(|(idx, opening_id)| (ValueSource::challenge(idx), ValueSource::opening(*opening_id)))
                .collect(),
        );
        let baked = BakedPublicInputs {
            challenges: baked_challenges,
            initial_claims,
            batching_coefficients: Vec::new(),
            output_constraint_challenges: baked_output_challenges,
            input_constraint_challenges: baked_input_challenges,
            extra_constraint_challenges: opening_data.constraint_coeffs.clone(),
        };
        let _oc_block_lens: Vec<usize> = oc_blocks.iter().map(|b| b.len()).collect();
        let r1cs =
            VerifierR1CSBuilder::<F>::new_with_extra(&stage_configs, &[extra_constraint], &baked, oc_blocks).build();
        drop(proofs);

        let verifier_input = BlindFoldVerifierInput {
            round_commitments,
            output_claims_row_commitments,
            eval_commitments: vec![stage5_eval_commitment],
        };
        let blindfold_proof =
            state_manager.blindfold_proof.as_ref().ok_or_else(|| anyhow::anyhow!("missing blindfold proof"))?;
        let (expected_e_rows, _) = r1cs.hyrax.e_grid(r1cs.num_constraints);
        anyhow::ensure!(
            verifier_input.round_commitments.len() == r1cs.hyrax.total_rounds,
            "BlindFold verifier round commitments mismatch: got {}, expected {}",
            verifier_input.round_commitments.len(),
            r1cs.hyrax.total_rounds,
        );
        anyhow::ensure!(
            verifier_input.output_claims_row_commitments.len() == r1cs.hyrax.output_claims_rows,
            "BlindFold verifier OC row commitments mismatch: got {}, expected {}",
            verifier_input.output_claims_row_commitments.len(),
            r1cs.hyrax.output_claims_rows,
        );
        anyhow::ensure!(
            blindfold_proof.noncoeff_row_commitments.len() == r1cs.hyrax.regular_noncoeff_rows(),
            "BlindFold proof noncoeff rows mismatch: got {}, expected {}",
            blindfold_proof.noncoeff_row_commitments.len(),
            r1cs.hyrax.regular_noncoeff_rows(),
        );
        anyhow::ensure!(
            blindfold_proof.random_instance.output_claims_row_commitments.len() == r1cs.hyrax.output_claims_rows,
            "BlindFold random instance OC rows mismatch: got {}, expected {}",
            blindfold_proof.random_instance.output_claims_row_commitments.len(),
            r1cs.hyrax.output_claims_rows,
        );
        anyhow::ensure!(
            blindfold_proof.random_instance.noncoeff_row_commitments.len() == r1cs.hyrax.regular_noncoeff_rows(),
            "BlindFold random instance noncoeff rows mismatch: got {}, expected {}",
            blindfold_proof.random_instance.noncoeff_row_commitments.len(),
            r1cs.hyrax.regular_noncoeff_rows(),
        );
        anyhow::ensure!(
            blindfold_proof.random_instance.e_row_commitments.len() == expected_e_rows,
            "BlindFold random instance E rows mismatch: got {}, expected {}",
            blindfold_proof.random_instance.e_row_commitments.len(),
            expected_e_rows,
        );
        let pedersen_generators =
            state_manager.preprocessing.pedersen_generators(pedersen_generator_count_for_r1cs(&r1cs));
        let eval_commitment_gens = PCS::eval_commitment_gens_verifier(&state_manager.preprocessing.generators);
        let verifier = BlindFoldVerifier::<_, _>::new(&pedersen_generators, &r1cs, eval_commitment_gens);
        let mut blindfold_transcript = ProofTranscript::new(b"BlindFold");
        verifier
            .verify(blindfold_proof, &verifier_input, &mut blindfold_transcript)
            .map_err(|err| anyhow::anyhow!("BlindFold verification failed: {err:?}"))
    }

    #[cfg(feature = "zk")]
    fn sumcheck_proof<'a, F, C, PCS, ProofTranscript>(
        proofs: &'a crate::zkvm::state_manager::Proofs<F, C, PCS, ProofTranscript>,
        key: ProofKeys,
    ) -> Result<&'a SumcheckInstanceProof<F, C, ProofTranscript>, anyhow::Error>
    where
        F: JoltField,
        C: JoltCurve,
        PCS: CommitmentScheme<Field = F>,
        ProofTranscript: Transcript,
    {
        match proofs.get(&key).ok_or_else(|| anyhow::anyhow!("missing sumcheck proof for {key:?}"))? {
            ProofData::SumcheckProof(proof) => Ok(proof),
            _ => Err(anyhow::anyhow!("invalid proof type for {key:?}")),
        }
    }

    #[cfg(feature = "zk")]
    fn batched_input_challenge_values<F, ProofTranscript>(
        instances: &[Box<dyn SumcheckInstance<F, ProofTranscript>>],
        stage_data: &StageBlindfoldVerifyData<F>,
        opening_accumulator: std::rc::Rc<std::cell::RefCell<crate::poly::opening_proof::VerifierOpeningAccumulator<F>>>,
    ) -> Vec<F>
    where
        F: JoltField,
        ProofTranscript: Transcript,
    {
        let max_num_rounds = instances.iter().map(|instance| instance.num_rounds()).max().unwrap();
        let mut values: Vec<F> = stage_data
            .batching_coefficients
            .iter()
            .zip(instances.iter())
            .map(|(alpha, instance)| alpha.mul_pow_2(max_num_rounds - instance.num_rounds()))
            .collect();
        for instance in instances {
            values.extend(instance.input_constraint_challenge_values(Some(opening_accumulator.clone())));
        }
        values
    }

    #[cfg(feature = "zk")]
    fn batched_output_challenge_values<F, ProofTranscript>(
        instances: &[Box<dyn SumcheckInstance<F, ProofTranscript>>],
        stage_data: &StageBlindfoldVerifyData<F>,
    ) -> Option<Vec<F>>
    where
        F: JoltField,
        ProofTranscript: Transcript,
    {
        let constraints: Vec<_> = instances.iter().map(|instance| instance.output_claim_constraint()).collect();
        OutputClaimConstraint::batch(&constraints)?;

        let max_num_rounds = instances.iter().map(|instance| instance.num_rounds()).max().unwrap();
        let mut values = stage_data.batching_coefficients.clone();
        for instance in instances {
            let offset = max_num_rounds - instance.num_rounds();
            values
                .extend(instance.output_constraint_challenge_values(
                    &stage_data.challenges[offset..offset + instance.num_rounds()],
                ));
        }
        Some(values)
    }

    #[cfg(feature = "zk")]
    fn batched_initial_claim<F, ProofTranscript>(
        instances: &[Box<dyn SumcheckInstance<F, ProofTranscript>>],
        batching_coefficients: &[F],
    ) -> F
    where
        F: JoltField,
        ProofTranscript: Transcript,
    {
        let max_num_rounds = instances.iter().map(|instance| instance.num_rounds()).max().unwrap_or(0);
        instances
            .iter()
            .zip(batching_coefficients.iter())
            .map(|(instance, coeff)| instance.input_claim().mul_pow_2(max_num_rounds - instance.num_rounds()) * coeff)
            .sum()
    }

    #[cfg(feature = "zk")]
    fn stage1_output_constraint() -> OutputClaimConstraint {
        OutputClaimConstraint::batch(&[Some(OutputClaimConstraint::sum_of_products(vec![
            crate::subprotocols::blindfold::ProductTerm::scaled(
                ValueSource::challenge(0),
                vec![
                    ValueSource::opening(OpeningId::Virtual(
                        crate::zkvm::witness::VirtualPolynomial::SpartanAz,
                        crate::poly::opening_proof::SumcheckId::SpartanOuter,
                    )),
                    ValueSource::opening(OpeningId::Virtual(
                        crate::zkvm::witness::VirtualPolynomial::SpartanBz,
                        crate::poly::opening_proof::SumcheckId::SpartanOuter,
                    )),
                ],
            ),
            crate::subprotocols::blindfold::ProductTerm::scaled(
                ValueSource::challenge(0),
                vec![
                    ValueSource::constant(-1),
                    ValueSource::opening(OpeningId::Virtual(
                        crate::zkvm::witness::VirtualPolynomial::SpartanCz,
                        crate::poly::opening_proof::SumcheckId::SpartanOuter,
                    )),
                ],
            ),
        ]))])
        .expect("single stage1 constraint should batch")
    }

    fn verify_trusted_advice_proofs<
        F: JoltField,
        C: JoltCurve,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F>,
    >(
        state_manager: &StateManager<'_, F, C, ProofTranscript, PCS>,
        verifier_setup: &PCS::VerifierSetup,
        transcript: &mut ProofTranscript,
    ) -> Result<(), anyhow::Error> {
        let trusted_advice_commitment = state_manager.trusted_advice_commitment.as_ref().unwrap();
        let accumulator = state_manager.get_verifier_accumulator();

        let (point, eval) = accumulator.borrow().get_trusted_advice_opening().unwrap();
        let proof = match state_manager.proofs.borrow().get(&ProofKeys::TrustedAdviceProof) {
            Some(ProofData::OpeningProof(proof)) => proof.clone(),
            _ => return Err(anyhow::anyhow!("Trusted advice proof not found")),
        };

        PCS::verify(&proof, verifier_setup, transcript, &point.r, &eval, trusted_advice_commitment)
            .map_err(|e| anyhow::anyhow!("Trusted advice opening proof verification failed: {e:?}"))?;

        Ok(())
    }

    fn verify_untrusted_advice_proofs<
        F: JoltField,
        C: JoltCurve,
        ProofTranscript: Transcript,
        PCS: CommitmentScheme<Field = F>,
    >(
        state_manager: &StateManager<'_, F, C, ProofTranscript, PCS>,
        verifier_setup: &PCS::VerifierSetup,
        transcript: &mut ProofTranscript,
    ) -> Result<(), anyhow::Error> {
        use crate::poly::opening_proof::{OpeningPoint, SumcheckId, BIG_ENDIAN};
        use crate::utils::math::Math;
        use crate::zkvm::witness::VirtualPolynomial;

        let untrusted_advice_commitment = state_manager.untrusted_advice_commitment.as_ref().unwrap();
        let accumulator = state_manager.get_verifier_accumulator();

        // Reconstruct the advice opening point from the RamVal sumcheck point.
        // The serialized proof only stores the claim (scalar), not the opening
        // point, so the verifier must recompute it.
        let ws = crate::common::constants::RAM_WORD_SIZE as usize;
        let max_size = state_manager.program_io.memory_layout.max_untrusted_advice_size as usize / ws;
        let log_advice_size = max_size.next_power_of_two().log_2();
        let total_memory_vars = state_manager.ram_K.log_2();
        let (r_val_point, _) = accumulator
            .borrow()
            .get_virtual_polynomial_opening(VirtualPolynomial::RamVal, SumcheckId::RamReadWriteChecking);
        let r_address = &r_val_point.r[..total_memory_vars];
        let high_bits = total_memory_vars - log_advice_size;
        let advice_opening_point = OpeningPoint::<BIG_ENDIAN, F>::new(r_address[high_bits..].to_vec());

        // Directly populate the opening point in the accumulator without touching
        // the Fiat-Shamir transcript.  The prover (coordinator) inserts into
        // `openings` directly and never calls `append_untrusted_advice`, so the
        // verifier must match.
        {
            use crate::poly::opening_proof::OpeningId;
            let mut acc = accumulator.borrow_mut();
            if let Some((point, _)) = acc.openings.get_mut(&OpeningId::UntrustedAdvice) {
                *point = advice_opening_point;
            } else {
                acc.openings.insert(OpeningId::UntrustedAdvice, (advice_opening_point, F::zero()));
            }
        }

        let (point, eval) = accumulator.borrow().get_untrusted_advice_opening().unwrap();
        let proof = match state_manager.proofs.borrow().get(&ProofKeys::UntrustedAdviceProof) {
            Some(ProofData::OpeningProof(proof)) => proof.clone(),
            _ => return Err(anyhow::anyhow!("Untrusted advice proof not found")),
        };

        PCS::verify(&proof, verifier_setup, transcript, &point.r, &eval, untrusted_advice_commitment)
            .map_err(|e| anyhow::anyhow!("Untrusted advice opening proof verification failed: {e:?}"))?;

        Ok(())
    }
}
