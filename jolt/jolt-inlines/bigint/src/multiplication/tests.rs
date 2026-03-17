#![cfg(all(test, feature = "host"))]

use super::{sdk::Limb, INPUT_LIMBS, OUTPUT_LIMBS};

mod bigint256_multiplication {
    use super::TestVectors;
    use crate::test_utils::bigint_verify;

    #[test]
    fn test_bigint256_mul_default() {
        let (lhs, rhs, expected) = TestVectors::get_default_test();
        bigint_verify::assert_exec_trace_equiv(&lhs, &rhs, &expected);
    }

    #[test]
    fn test_bigint256_mul_random() {
        for _ in 0..100 {
            let (lhs, rhs, expected) = TestVectors::generate_random_test();
            bigint_verify::assert_exec_trace_equiv(&lhs, &rhs, &expected);
        }
    }

    #[test]
    fn test_bigint256_mul_edge_cases() {
        let edge_cases = TestVectors::get_edge_cases();
        for (i, (lhs, rhs, expected, description)) in edge_cases.iter().enumerate() {
            println!("Edge case #{}: {}", i + 1, description);
            bigint_verify::assert_exec_trace_equiv(lhs, rhs, expected);
        }
    }
}

pub struct TestVectors;

impl TestVectors {
    pub fn get_default_test() -> ([Limb; INPUT_LIMBS], [Limb; INPUT_LIMBS], [Limb; OUTPUT_LIMBS]) {
        // 256-bit values, represented as native limbs
        let lhs_bytes: [u8; 32] = [
            0x9c, 0x0b, 0x1a, 0x2f, 0x3e, 0x5d, 0x6c, 0x8b,
            0x0a, 0x1f, 0x2e, 0x4d, 0x7c, 0x9b, 0xa8, 0xf3,
            0x22, 0x33, 0x44, 0x55, 0x76, 0x87, 0x09, 0x1a,
            0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c,
        ];
        let rhs_bytes: [u8; 32] = [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
            0x94, 0x83, 0x72, 0x61, 0x50, 0x4f, 0x3e, 0x2d,
            0x1c, 0x0b, 0xfa, 0xe9, 0xd8, 0xc7, 0xb6, 0xa5,
        ];

        let lhs = limbs_from_le_bytes(&lhs_bytes);
        let rhs = limbs_from_le_bytes(&rhs_bytes);
        let expected = reference_multiply(lhs, rhs);
        (lhs, rhs, expected)
    }

    pub fn generate_random_test() -> ([Limb; INPUT_LIMBS], [Limb; INPUT_LIMBS], [Limb; OUTPUT_LIMBS]) {
        use rand::{thread_rng, Rng};
        let mut rng = thread_rng();
        let lhs: [Limb; INPUT_LIMBS] = core::array::from_fn(|_| rng.gen());
        let rhs: [Limb; INPUT_LIMBS] = core::array::from_fn(|_| rng.gen());
        let expected = reference_multiply(lhs, rhs);
        (lhs, rhs, expected)
    }

    #[allow(clippy::type_complexity)]
    pub fn get_edge_cases() -> Vec<([Limb; INPUT_LIMBS], [Limb; INPUT_LIMBS], [Limb; OUTPUT_LIMBS], &'static str)> {
        let mut cases = Vec::new();
        let zero = [0 as Limb; INPUT_LIMBS];
        let mut one = [0 as Limb; INPUT_LIMBS];
        one[0] = 1;
        let max = [Limb::MAX; INPUT_LIMBS];
        let mut two = [0 as Limb; INPUT_LIMBS];
        two[0] = 2;

        let add = |c: &mut Vec<_>, a, b, desc| {
            c.push((a, b, reference_multiply(a, b), desc));
        };

        add(&mut cases, zero, zero, "0 * 0");
        add(&mut cases, zero, one, "0 * 1");
        add(&mut cases, one, zero, "1 * 0");
        add(&mut cases, one, one, "1 * 1");
        add(&mut cases, max, zero, "MAX * 0");
        add(&mut cases, zero, max, "0 * MAX");
        add(&mut cases, max, one, "MAX * 1");
        add(&mut cases, one, max, "1 * MAX");
        add(&mut cases, max, max, "MAX * MAX");
        add(&mut cases, max, two, "(2^256 - 1) * 2");

        // Single limb max
        let mut single_max = [0 as Limb; INPUT_LIMBS];
        single_max[0] = Limb::MAX;
        add(&mut cases, single_max, single_max, "Single limb MAX * Single limb MAX");

        // High limb only
        let mut high_only = [0 as Limb; INPUT_LIMBS];
        high_only[INPUT_LIMBS - 1] = Limb::MAX;
        add(&mut cases, high_only, high_only, "High limb only * High limb only");

        cases
    }
}

/// Reference multiply using u128 arithmetic for correctness checking.
fn reference_multiply(a: [Limb; INPUT_LIMBS], b: [Limb; INPUT_LIMBS]) -> [Limb; OUTPUT_LIMBS] {
    // Convert to u32 limbs for uniform handling
    let a_bytes = limbs_to_le_bytes(&a);
    let b_bytes = limbs_to_le_bytes(&b);

    // Work in u32 limbs (8 per 256-bit value) for simple reference impl
    let a32: [u32; 8] = u32_limbs_from_le_bytes(&a_bytes);
    let b32: [u32; 8] = u32_limbs_from_le_bytes(&b_bytes);
    let mut r32 = [0u32; 16];

    for i in 0..8 {
        let mut carry: u64 = 0;
        for j in 0..8 {
            let product = (a32[i] as u64) * (b32[j] as u64) + (r32[i + j] as u64) + carry;
            r32[i + j] = product as u32;
            carry = product >> 32;
        }
        r32[i + 8] = r32[i + 8].wrapping_add(carry as u32);
    }

    let result_bytes = u32_limbs_to_le_bytes(&r32);
    output_limbs_from_le_bytes(&result_bytes)
}

fn limbs_from_le_bytes(bytes: &[u8; 32]) -> [Limb; INPUT_LIMBS] {
    let mut limbs = [0 as Limb; INPUT_LIMBS];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = i * core::mem::size_of::<Limb>();
        let chunk = &bytes[start..start + core::mem::size_of::<Limb>()];
        #[cfg(feature = "rv64")]
        { *limb = u64::from_le_bytes(chunk.try_into().unwrap()); }
        #[cfg(not(feature = "rv64"))]
        { *limb = u32::from_le_bytes(chunk.try_into().unwrap()); }
    }
    limbs
}

fn limbs_to_le_bytes(limbs: &[Limb; INPUT_LIMBS]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, &limb) in limbs.iter().enumerate() {
        let start = i * core::mem::size_of::<Limb>();
        let le = limb.to_le_bytes();
        bytes[start..start + le.len()].copy_from_slice(&le);
    }
    bytes
}

fn u32_limbs_from_le_bytes(bytes: &[u8; 32]) -> [u32; 8] {
    let mut limbs = [0u32; 8];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = u32::from_le_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    limbs
}

fn u32_limbs_to_le_bytes(limbs: &[u32; 16]) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    for (i, &limb) in limbs.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

fn output_limbs_from_le_bytes(bytes: &[u8; 64]) -> [Limb; OUTPUT_LIMBS] {
    let mut limbs = [0 as Limb; OUTPUT_LIMBS];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = i * core::mem::size_of::<Limb>();
        let chunk = &bytes[start..start + core::mem::size_of::<Limb>()];
        #[cfg(feature = "rv64")]
        { *limb = u64::from_le_bytes(chunk.try_into().unwrap()); }
        #[cfg(not(feature = "rv64"))]
        { *limb = u32::from_le_bytes(chunk.try_into().unwrap()); }
    }
    limbs
}
