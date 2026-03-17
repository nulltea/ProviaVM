use super::{INPUT_LIMBS, OUTPUT_LIMBS};

#[cfg(feature = "rv64")]
type Limb = u64;
#[cfg(feature = "rv64")]
type DoubleLimb = u128;

#[cfg(not(feature = "rv64"))]
type Limb = u32;
#[cfg(not(feature = "rv64"))]
type DoubleLimb = u64;

const LIMB_BITS: u32 = (core::mem::size_of::<Limb>() * 8) as u32;

/// Execute 256-bit × 256-bit = 512-bit multiplication (schoolbook).
/// Input/output: limbs in little-endian order.
pub fn bigint_mul(lhs: [Limb; INPUT_LIMBS], rhs: [Limb; INPUT_LIMBS]) -> [Limb; OUTPUT_LIMBS] {
    let mut result = [0 as Limb; OUTPUT_LIMBS];

    for (i, &lhs_limb) in lhs.iter().enumerate() {
        for (j, &rhs_limb) in rhs.iter().enumerate() {
            let product = (lhs_limb as DoubleLimb) * (rhs_limb as DoubleLimb);
            let low = product as Limb;
            let high = (product >> LIMB_BITS) as Limb;

            let k = i + j;

            let (sum, carry1) = result[k].overflowing_add(low);
            result[k] = sum;

            let mut carry = carry1 as Limb;
            if high != 0 || carry != 0 {
                let (sum_hi, c_hi) = result[k + 1].overflowing_add(high);
                let (sum_c, c_c) = sum_hi.overflowing_add(carry);
                result[k + 1] = sum_c;
                carry = (c_hi as Limb) + (c_c as Limb);

                let mut pos = k + 2;
                while carry != 0 && pos < OUTPUT_LIMBS {
                    let (s, c) = result[pos].overflowing_add(carry);
                    result[pos] = s;
                    carry = c as Limb;
                    pos += 1;
                }
            }
        }
    }
    result
}
