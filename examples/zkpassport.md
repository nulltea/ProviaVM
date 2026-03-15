# zkPassport — Minimal e-Passport Verification in zkVM

## Goal

Prove in Jolt zkVM:

1. **Passive authentication**: DG1 hash matches SOD, SOD signature verifies under DS public key
2. **Selective disclosure**: age ≥ 18

**Public output** (committed by proof):
- `passive_auth_valid: bool`
- `over_18: bool`
- `issuing_country: [u8; 3]`

**Private input** (witness, not revealed):
- raw DG1, SOD fields, DS public key, DOB

---

## Scope (MVP)

| In scope | Out of scope |
|----------|-------------|
| DG1 only | DG2 / biometrics |
| SOD passive auth | Active auth / chip auth |
| SHA-256 | SHA-1 / SHA-384 / SHA-512 |
| RSA PKCS#1 v1.5 | ECDSA / RSA-PSS / Brainpool |
| TD3 MRZ format | TD1 / TD2 |
| Pinned DS public key | DS → CSCA cert chain in guest |
| age ≥ 18 predicate | Arbitrary predicates |
| Synthetic + real fixture support | NFC / BAC / PACE |

---

## Architecture

Follows the `zkemail` example pattern: host pre-parses complex structures,
guest verifies the cryptographic chain.

```
zkpassport/
  Cargo.toml              # host crate
  core/
    Cargo.toml             # shared types (no_std)
    src/lib.rs             # PassportInput, PassportOutput, MRZ parsing, age predicate
  guest/
    Cargo.toml             # guest crate (no_std, riscv32)
    src/lib.rs             # #[jolt::provable] verify_passport
  src/
    main.rs                # host: load fixtures or generate, native + delegated proof
    fixture.rs             # synthetic fixture generation
    sod.rs                 # CMS/SOD parsing for real fixture files
  fixtures/
    dg1.bin                # raw EF.DG1 (provided externally)
    sod.bin                # raw EF.SOD (provided externally)
    ds_pubkey.der          # DS RSA public key (provided externally)
```

---

## Types

```rust
// core/src/lib.rs

/// Host pre-parses SOD/CMS, extracts these fields for the guest.
pub struct PassportInput {
    pub dg1: Vec<u8>,              // raw EF.DG1 bytes (TLV-wrapped MRZ)
    pub encap_content: Vec<u8>,    // LDS Security Object (CMS encapContentInfo value)
    pub signed_attrs_der: Vec<u8>, // CMS signedAttrs, DER SET OF
    pub signature: Vec<u8>,        // CMS signature (RSA PKCS#1 v1.5)
    pub ds_pubkey_der: Vec<u8>,    // DS public key, PKCS#1 DER
    pub today_yyyymmdd: u32,       // e.g. 20260315
}

pub struct PassportOutput {
    pub passive_auth_valid: bool,
    pub over_18: bool,
    pub issuing_country: [u8; 3],
}
```

---

## Guest Verification Pipeline

```rust
fn verify_passport(input: PassportInput) -> PassportOutput
```

1. `dg1_hash = SHA-256(input.dg1)`
2. Assert `encap_content` contains `dg1_hash` (byte-containment check)
3. `content_digest = SHA-256(input.encap_content)`
4. Assert `signed_attrs_der` contains `content_digest` (byte-containment check)
5. `attrs_hash = SHA-256(input.signed_attrs_der)`
6. RSA PKCS#1v15 verify: `ds_pubkey` verifies `signature` over `attrs_hash`
7. Unwrap DG1 TLV → 88-byte TD3 MRZ
8. Extract DOB (line 2, bytes 13..19) and issuing country (line 1, bytes 2..5)
9. Compute `over_18` using century expansion (YY > 50 → 19YY, else 20YY)

If any step fails, the guest panics (proof is invalid).

### Byte-containment check

`contains_subsequence(haystack, needle)` — linear scan for 32-byte SHA-256 hash
in small DER structures (< 1KB). False positive probability: 2^{-256}.

**MVP simplification**: proper ASN.1 field extraction would eliminate any theoretical
adversarial embedding; deferred to future work.

---

## Host Modes

**Synthetic fixture** (`--generate`):
- Generates RSA 2048 key pair, fake TD3 MRZ, DG1 TLV, LDS Security Object, CMS signedAttrs
- Real RSA signature over real SHA-256 hash chain
- Self-consistent end-to-end

**Real fixtures** (`--fixtures-dir ./fixtures`):
- Loads `dg1.bin`, `sod.bin`, `ds_pubkey.der`
- Parses SOD via `cms` crate (CMS SignedData → signedAttrs, encapContent, signature)
- Constructs `PassportInput`

Then: native execution → optional worker delegation → proof verification.

---

## Dependencies

**Guest** (no_std): `sha2`, `rsa`, `serde` — same as zkemail.
**Host** (std): above + `cms`, `der`, `rand`, `clap`, `eyre`, `tracing`, provia-jolt-sdk.

No new guest dependencies beyond what zkemail already uses.

---

## Testing

15 tests implemented:

**Core unit tests** (9):
- MRZ parsing (TD3 format, issuing country, DOB extraction)
- Age predicate (over 18, exactly 18, one day before, 1900s birth, minor)
- DG1 TLV unwrapping
- Byte-containment helper
- ASCII digit parsing

**Host integration tests** (6):
- Fixture round-trip (RSA signature verifies, hash chain consistent)
- Native end-to-end: adult (age 26), minor (age 11), exactly 18
- Tampered DG1 rejected (panics)
- Tampered signature rejected (panics)

```bash
RUSTFLAGS="-A warnings" cargo test -p zkpassport-core   # 9 tests
RUSTFLAGS="-A warnings" cargo test -p zkpassport        # 6 tests
```

---

## Simplifications vs Full Passive Auth

| Aspect | Full e-passport | This MVP |
|--------|-----------------|----------|
| DS → CSCA cert chain | Verified in guest | Skipped — DS pubkey is trusted input |
| Hash table binding | ASN.1 field extraction | Byte-containment check |
| messageDigest binding | ASN.1 field extraction | Byte-containment check |
| Algorithms | SHA-1/256/384/512, RSA/ECDSA/RSA-PSS | SHA-256 + RSA PKCS#1v15 only |
| Certificate validation | Expiry, extensions, key usage | None |
| PKI / revocation | CSCA master list, CRL, OCSP | Pinned single key |
| DG1 format | Full ASN.1 LDS | Fixed TLV unwrap for TD3 |

**What IS real**: RSA signature verification, SHA-256 hashing, hash chain from
DG1 → LDS SO → signedAttrs → signature, MRZ parsing, age predicate.
The crypto verification path is genuine, not mocked.

---

## Future Work

1. **DS → CSCA cert chain verification** in guest (add DS TBS cert + CSCA pubkey to input)
2. **Proper ASN.1 field extraction** in guest (replace byte-containment with TLV walking)
3. **ECDSA P-256** support (many newer passports use ECDSA)
4. **SHA-384/SHA-512** for passports that use them
5. **Nullifier** for sybil resistance: `H(doc_number || salt)`
6. **Real SOD parsing** improvements for diverse passport formats
7. **zkVM proving integration test** following `dag_correct.rs` pattern
