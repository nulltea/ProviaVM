#![no_std]
extern crate alloc;

use alloc::vec::Vec;
pub use jolt_inlines_rsa::{Bytes2048, Step2048, StepOp, Witness2048};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core I/O types
// ---------------------------------------------------------------------------

/// Host pre-parses SOD/CMS and extracts these fields for the guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PassportInput {
    /// Raw EF.DG1 bytes (TLV-wrapped MRZ). Guest hashes this.
    pub dg1: Vec<u8>,
    /// CMS encapContentInfo value — the LDS Security Object (DER).
    /// Contains the DG hash table. Guest hashes this to check messageDigest binding.
    pub encap_content: Vec<u8>,
    /// CMS signedAttrs, DER-encoded (re-tagged as SET OF per CMS spec).
    /// Guest hashes this for signature verification.
    pub signed_attrs_der: Vec<u8>,
    /// CMS signature bytes (RSA PKCS#1 v1.5).
    pub signature: Vec<u8>,
    /// Document Signer RSA public key, PKCS#1 DER.
    pub ds_pubkey_der: Vec<u8>,
    /// Transcript-bound seed for RSA witness compression checks.
    pub rsa_challenge_seed: [u8; 32],
    /// Today's date as YYYYMMDD integer (e.g. 20260315).
    pub today_yyyymmdd: u32,
}

/// Public output committed by the guest proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassportOutput {
    /// All passive auth checks passed.
    pub passive_auth_valid: bool,
    /// Holder is 18 or older.
    pub over_18: bool,
    /// 3-letter issuing state code from MRZ.
    pub issuing_country: [u8; 3],
}

// ---------------------------------------------------------------------------
// MRZ parsing (TD3 format, 2 lines × 44 chars = 88 bytes)
// ---------------------------------------------------------------------------

/// Parsed fields from a TD3 Machine Readable Zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMrz {
    /// 3-letter issuing state code (e.g. b"UTO").
    pub issuing_country: [u8; 3],
    /// Date of birth as 6 ASCII digits YYMMDD.
    pub dob_yymmdd: [u8; 6],
}

/// Strip the DG1 TLV wrapper and return the raw 88-byte TD3 MRZ.
///
/// EF.DG1 structure: tag 0x61, length, then tag 0x5F1F, length, then MRZ bytes.
pub fn unwrap_dg1_to_mrz(dg1: &[u8]) -> Option<&[u8]> {
    let (_, inner) = read_tlv(dg1)?;
    if inner.first() != Some(&0x5F) || inner.get(1) != Some(&0x1F) {
        return None;
    }
    // Tag 0x5F1F is a two-byte tag
    let (_, mrz) = read_tlv_two_byte_tag(&inner[2..])?;
    if mrz.len() == 88 {
        Some(mrz)
    } else {
        None
    }
}

/// Parse a TD3 MRZ (88 bytes) into structured fields.
///
/// Layout:
///   Line 1 (bytes 0..44):  [0] type, [1] subtype, [2..5] issuing country, [5..44] name
///   Line 2 (bytes 44..88): [0..9] doc number, [9] check, [10..13] nationality,
///                           [13..19] DOB YYMMDD, [19] check, [20] sex,
///                           [21..27] expiry YYMMDD, ...
pub fn parse_td3_mrz(mrz: &[u8]) -> Option<ParsedMrz> {
    if mrz.len() != 88 {
        return None;
    }
    let issuing_country: [u8; 3] = [mrz[2], mrz[3], mrz[4]];
    let line2 = &mrz[44..];
    let dob_yymmdd: [u8; 6] = [
        line2[13], line2[14], line2[15], line2[16], line2[17], line2[18],
    ];
    Some(ParsedMrz {
        issuing_country,
        dob_yymmdd,
    })
}

// ---------------------------------------------------------------------------
// Age predicate
// ---------------------------------------------------------------------------

/// Expand a 2-digit MRZ year to a 4-digit year.
/// ICAO rule for DOB: YY > 50 → 19YY, else 20YY.
fn expand_mrz_year(yy: u8) -> u32 {
    if yy > 50 { 1900 + yy as u32 } else { 2000 + yy as u32 }
}

/// Parse 2 ASCII digit chars into a u8 (e.g. b"74" → 74).
fn ascii2_to_u8(hi: u8, lo: u8) -> Option<u8> {
    let h = hi.checked_sub(b'0')?;
    let l = lo.checked_sub(b'0')?;
    if h > 9 || l > 9 {
        return None;
    }
    Some(h * 10 + l)
}

/// Check whether a person with the given DOB (YYMMDD ASCII digits) is at least 18
/// on the given date (YYYYMMDD integer, e.g. 20260315).
pub fn is_over_18(dob_yymmdd: [u8; 6], today_yyyymmdd: u32) -> bool {
    let yy = match ascii2_to_u8(dob_yymmdd[0], dob_yymmdd[1]) {
        Some(v) => v,
        None => return false,
    };
    let mm = match ascii2_to_u8(dob_yymmdd[2], dob_yymmdd[3]) {
        Some(v) => v,
        None => return false,
    };
    let dd = match ascii2_to_u8(dob_yymmdd[4], dob_yymmdd[5]) {
        Some(v) => v,
        None => return false,
    };

    let birth_year = expand_mrz_year(yy);
    let birth_mmdd = (mm as u32) * 100 + dd as u32;

    let today_year = today_yyyymmdd / 10000;
    let today_mmdd = today_yyyymmdd % 10000;

    let mut age = today_year.wrapping_sub(birth_year);
    if today_mmdd < birth_mmdd {
        age = age.wrapping_sub(1);
    }
    age >= 18
}

// ---------------------------------------------------------------------------
// Byte-containment helper
// ---------------------------------------------------------------------------

/// Check whether `haystack` contains `needle` as a contiguous subsequence.
pub fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Minimal TLV helpers (not a general ASN.1 parser)
// ---------------------------------------------------------------------------

/// Read a single-byte-tag TLV. Returns (tag, value_slice).
fn read_tlv(data: &[u8]) -> Option<(u8, &[u8])> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    let (len, offset) = read_der_length(&data[1..])?;
    let value = data.get(1 + offset..1 + offset + len)?;
    Some((tag, value))
}

/// Read value after a two-byte tag has already been consumed.
/// `data` starts right after the two-byte tag.
fn read_tlv_two_byte_tag(data: &[u8]) -> Option<((), &[u8])> {
    let (len, offset) = read_der_length(data)?;
    let value = data.get(offset..offset + len)?;
    Some(((), value))
}

/// Decode a DER length field. Returns (length_value, bytes_consumed).
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x81 {
        let len = *data.get(1)? as usize;
        Some((len, 2))
    } else if first == 0x82 {
        let hi = *data.get(1)? as usize;
        let lo = *data.get(2)? as usize;
        Some((hi << 8 | lo, 3))
    } else {
        // Lengths > 65535 not expected for passport data
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_parse_td3_mrz() {
        // ICAO example: P<UTOERIKSSON<<ANNA<MARIA...
        let line1 = b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
        let line2 = b"L898902C36UTO7408122F1204159ZE184226B<<<<<<0";
        assert_eq!(line1.len(), 44);
        assert_eq!(line2.len(), 44);

        let mut mrz = [0u8; 88];
        mrz[..44].copy_from_slice(line1);
        mrz[44..].copy_from_slice(line2);

        let parsed = parse_td3_mrz(&mrz).unwrap();
        assert_eq!(&parsed.issuing_country, b"UTO");
        assert_eq!(&parsed.dob_yymmdd, b"740812");
    }

    #[test]
    fn test_is_over_18_yes() {
        // Born 2000-03-15, today 2026-03-15 → age 26
        assert!(is_over_18(*b"000315", 20260315));
    }

    #[test]
    fn test_is_over_18_exactly_18() {
        // Born 2008-03-15, today 2026-03-15 → exactly 18
        assert!(is_over_18(*b"080315", 20260315));
    }

    #[test]
    fn test_is_over_18_one_day_before() {
        // Born 2008-03-16, today 2026-03-15 → still 17
        assert!(!is_over_18(*b"080316", 20260315));
    }

    #[test]
    fn test_is_over_18_1900s() {
        // Born 1974-08-12 (YY=74 > 50 → 1974), today 2026-03-15 → age 51
        assert!(is_over_18(*b"740812", 20260315));
    }

    #[test]
    fn test_is_over_18_minor() {
        // Born 2015-01-01, today 2026-03-15 → age 11
        assert!(!is_over_18(*b"150101", 20260315));
    }

    #[test]
    fn test_unwrap_dg1_to_mrz() {
        // Build a minimal DG1: 0x61 || len || 0x5F1F || len || 88 MRZ bytes
        let mrz = [b'X'; 88];
        let mut dg1 = Vec::new();
        dg1.push(0x61);
        // inner length = 2 (tag 5F1F) + 1 (length byte) + 88 = 91
        dg1.push(91);
        dg1.push(0x5F);
        dg1.push(0x1F);
        dg1.push(88);
        dg1.extend_from_slice(&mrz);

        let result = unwrap_dg1_to_mrz(&dg1).unwrap();
        assert_eq!(result.len(), 88);
        assert_eq!(result, &mrz[..]);
    }

    #[test]
    fn test_contains_subsequence() {
        let haystack = b"hello world";
        assert!(contains_subsequence(haystack, b"world"));
        assert!(contains_subsequence(haystack, b"hello"));
        assert!(contains_subsequence(haystack, b"lo wo"));
        assert!(!contains_subsequence(haystack, b"worlds"));
        assert!(contains_subsequence(haystack, b""));
        assert!(!contains_subsequence(b"", b"a"));
    }

    #[test]
    fn test_ascii2_to_u8() {
        assert_eq!(ascii2_to_u8(b'0', b'0'), Some(0));
        assert_eq!(ascii2_to_u8(b'7', b'4'), Some(74));
        assert_eq!(ascii2_to_u8(b'9', b'9'), Some(99));
        assert_eq!(ascii2_to_u8(b'a', b'0'), None);
    }
}
