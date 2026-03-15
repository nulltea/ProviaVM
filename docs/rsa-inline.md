# RSA Inline Instructions

## Overview

RSA-2048 signature verification in the zkVM guest uses Montgomery multiplication as the core primitive. A single `modpow_65537` requires 19 Montgomery multiplications (1 to enter Montgomery form, 16 squarings, 1 final multiply, 1 to exit). Each Montgomery multiplication is implemented as an inline instruction that expands into virtual RISC-V instructions at trace time.

## Montgomery Multiplication (SOS Method)

Computes `z = x * y * R^{-1} mod m` where `R = 2^(LIMB_BITS * LIMBS_2048)`.

Uses 8 virtual registers and a memory-resident accumulator (`zz[0..2n]`). The outer loop iterates `n` times (n = LIMBS_2048), each iteration performing two inner `add_mul_vvw` passes of `n` multiply-accumulates.

### Instruction Counts

| Architecture | Limbs (n) | Virtual instructions per inline | Fits u16 (65535)? |
|---|---|---|---|
| rv32 | 64 | ~91,716 | No |
| rv64 | 32 | ~23,000 | Yes |

## Route A: rv32 Two-Phase Split

Since rv32 exceeds the u16 `inline_sequence_remaining` limit, the outer loop is split at `SPLIT_AT = n/2 = 32`:

- **Phase 1** (`MONT_MUL_2048_P1`, funct7=0x02): init + outer loop iterations `[0..32)`. Stores carry to `CARRY_OFFSET` in memory.
- **Phase 2** (`MONT_MUL_2048_P2`, funct7=0x03): loads carry from `CARRY_OFFSET`, outer loop iterations `[32..64)` + final reduction.

Each phase emits ~45K virtual instructions, fitting within u16.

Guest code issues two inline instructions sequentially:
```
mont_mul_2048_p1_inline(x, y, ctx);
mont_mul_2048_p2_inline(x, y, ctx);
```

## Route B: rv64 Single Inline

rv64 uses 32 u64 limbs, producing ~23K virtual instructions that fit in a single inline:

- **Single phase** (`MONT_MUL_2048`, funct7=0x02): init + full outer loop + final reduction.

Guest code issues one inline instruction:
```
mont_mul_2048_inline(x, y, ctx);
```

## Memory Layout

`MontContext2048` (`repr(C)`):

| Offset | Size | Field |
|---|---|---|
| 0 | n * LB | `z` — output / zz_lo workspace |
| n * LB | n * LB | `modulus` — m |
| 2n * LB | LB | `n0inv` — k = -m^{-1} mod 2^LIMB_BITS |
| 2n * LB + LB | n * LB | `_scratch[0..n]` — zz_hi workspace |
| 3n * LB + LB | LB | `_scratch[n]` — carry (rv32 inter-phase transfer) |

Where LB = `LIMB_BYTES` (4 on rv32, 8 on rv64), n = `LIMBS_2048` (64 on rv32, 32 on rv64).

## Feature Gating

All route selection is compile-time via `#[cfg(feature = "rv64")]`:
- `lib.rs`: opcode constants and `init_inlines()` registration
- `sdk.rs`: guest inline calls and host dispatch
- `sequence_builder.rs`: entry points

## Future: Route C (Advice + Polynomial Fingerprint)

An O(n) verification approach using advice values and polynomial fingerprinting, similar to upstream Jolt's secp256k1 inline. The host would compute the Montgomery multiplication result and quotient, inject them as advice, and the guest would verify via a polynomial identity check at a random evaluation point.

**Status**: Not implemented. Currently unsound in ProviaVM's architecture because the client generates the trace (and thus controls the advice values) while also knowing the evaluation points (deterministic PRNG with hardcoded seed). A malicious client could craft adversarial advice that satisfies the polynomial check without performing correct computation.

**When viable**: Route C becomes sound when trace generation happens inside MPC, where no single party has full knowledge of both the advice values and the evaluation point. This requires implementing MPC-based tracing in ProviaVM, which shifts trust away from the client.
