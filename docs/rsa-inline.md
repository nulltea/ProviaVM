# RSA Inline and zkemail Design

## Overview

The repository now has two RSA-2048 verification paths:

- The original Montgomery-inline path in `jolt-inlines/rsa`, built around `modpow_65537`.
- The zkemail fast path, built around a **trusted-advice witness** that avoids replaying modular multiplication in the guest trace.

The Montgomery path remains the generic fallback library implementation. zkemail uses the trusted-advice witness path because it is materially smaller in trace size.

## Naive Montgomery Path

### What it does

The original path verifies RSA-2048 signatures by computing:

- one Montgomery multiply to enter Montgomery form,
- sixteen squarings for the `65537` addition chain,
- one multiply by the original signature,
- one Montgomery multiply to leave Montgomery form.

That is `19` Montgomery operations per verification.

### Guest hot path

The core primitive is the Montgomery inline in `jolt-inlines/rsa`:

- rv32 uses `64` `u32` limbs and splits the inline into two phases.
- rv64 uses `32` `u64` limbs and fits the multiply in a single inline.

Current micro-kernel trace sizes:

| Metric | rv32 | rv64 |
|---|---:|---:|
| `mont_mul_2048` | `92,188` | `23,569` |
| `mont_square_2048` | `92,188` | `23,569` |
| `modpow_65537` | `1,751,572` | `447,811` |

### Why zkemail moved away from it

Even with the inline, the Montgomery path still dominates the guest trace because the verifier is effectively replaying bigint arithmetic inside the VM. It is still useful as:

- the generic RSA fallback path,
- a correctness reference,
- a baseline for measuring any future RSA inline work.

It is no longer the zkemail hot path.

## Trusted-Advice Witness Path

### High-level flow

zkemail now verifies RSA using a trusted-advice witness in `jolt-inlines/rsa::witness`:

1. The host parses the DKIM email and PKCS#1 RSA public key.
2. The host builds a `Witness2048`.
3. The host commits that trusted advice in the proving flow.
4. The host derives the public `rsa_challenge_seed` from the trusted-advice commitment.
5. The guest:
   - parses the modulus from DER,
   - binds modulus and signature against the witness,
   - checks sampled remainder residues,
   - checks weighted residue consistency across the `65537` chain,
   - checks the final PKCS#1 v1.5 SHA-256 encoded message.

### Witness contents

`Witness2048` contains:

- `modulus: Bytes2048`
- `signature: Bytes2048`
- `steps: [Step2048; 17]`

Each `Step2048` contains:

- `op: StepOp`
- `quotient_residues: [u32; 4]`
- `remainder_residues: [u32; 4]`
- `remainder_limbs: Limbs2048`

The `17` steps are:

- `16` squaring reductions,
- `1` final multiply-by-base reduction.

### Why this is smaller

The guest no longer computes or replays full Montgomery multiplication. Instead it:

- carries cached residues for the quotient and remainder,
- recomputes only sampled remainder residue checks from bytes,
- folds step errors with seeded weights,
- performs one exact PKCS#1 decode check at the end.

This makes the trace mostly about byte scanning and residue arithmetic, not bigint multiplication.

## Trust Model

### Soundness

This path is **commitment-bound** and **probabilistic**.

- The trusted-advice witness is committed before proving.
- The public `rsa_challenge_seed` is derived from that trusted-advice commitment.
- The guest uses that seed to choose sampled remainder checks and seeded row weights.

The guest is **not** replaying the bigint arithmetic exactly. Soundness comes from:

- exact modulus/signature binding,
- exact `remainder < modulus`,
- exact PKCS#1 output check,
- seeded probabilistic consistency checks over the reduction chain.

### Privacy

This design focuses on binding, not privacy.

- The witness is carried via trusted advice.
- There is no blindfold/private witness layer in this path today.
- If witness privacy becomes important, it would require a follow-up design, not a parameter tweak.

### Profile-only seed path

The example `--profile-rsa` path does **not** commit trusted advice. It derives the seed from serialized trusted-advice bytes only so the local profiler can trace the same guest logic without running the full proving setup.

That shortcut is:

- acceptable for local profiling,
- not proof-bound,
- not the model used by the actual prove/verify flow.

## Final Result

Current measured results after cleanup:

| Metric | rv32 | rv64 |
|---|---:|---:|
| worker `zkemail_trace_only` | `473,706` | `430,302` |
| example `verify_dkim` | `544,013` | `509,707` |

rv64 is only a modest improvement now because zkemail no longer spends most of its time inside Montgomery arithmetic. The remaining hot path is mostly:

- byte-to-residue scanning,
- sampled residue recomputation,
- seeded weighted folding,
- PKCS#1 decoding.

Those operations benefit less from wider guest limbs than the old Montgomery kernel did.

## What Is Still Worth Exploring

### Worth exploring

1. rv64-specific witness verifier fast path

- Compute residues from `u64` chunks or native rv64 limb loads instead of always scanning `4`-byte chunks.
- This is the most plausible next micro-optimization because the trusted-advice witness verifier is now the hot path.

2. Witness layout optimization

- Replace byte-oriented remainder storage/scanning with a limb-oriented representation if it reduces guest trace without making host preparation too expensive.
- The main target is remainder handling, not quotient handling; quotient bytes are already avoided.

3. Deeper proof-system work

- Move more of the weighted residue/opening logic out of guest code and into committed-opening verification if a stronger or smaller protocol is needed.
- That would be a proof-system change, not a local zkemail refactor.

### Not worth prioritizing for zkemail now

- `mont_square_2048`
- further Montgomery inline shrinking

Those optimizations only matter for the legacy Montgomery fallback path. They are no longer the right next move for zkemail itself.
